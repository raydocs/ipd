package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"ipd/internal/app"
	"ipd/internal/config"
	"ipd/internal/leak"
)

func TestDNSSessionSensitivePathHistory(t *testing.T) {
	for _, pattern := range []string{
		"/v1//dnsleak/%s/../../sources",
		"/v1/./dnsleak/%s/../../sources",
		"/v1//dnsleak/%s/%%2e%%2e/%%2e%%2e/sources",
		"/v1%%2f%%2fdnsleak%%2f%s%%2f..%%2f..%%2fsources",
		"/v1//dns%%6ceak/%s/../../sources",
		"/v1/other/..//dnsleak/%s/../../sources",
		"/v1//dnsleak/%s/%%2E%%2E//%%2e%%2e/sources",
		"/v1/%%2e/dnsleak/%s/../../sources",
	} {
		t.Run(pattern, func(t *testing.T) {
			svc, h := contractHandler(t, true)
			svc.DNSSessions = leak.NewDNSServer("example.test", leak.SessionOptions{Enabled: true})
			session, err := svc.DNSSessions.Issue()
			if err != nil {
				t.Fatal(err)
			}
			path := fmt.Sprintf(pattern, session.Token)
			req := httptest.NewRequest("GET", path, nil)
			req.RemoteAddr = "192.0.2.55:12345"
			h.ServeHTTP(httptest.NewRecorder(), req)
			if count, err := svc.DB.CountLogs(); err != nil || count != 0 {
				t.Errorf("sensitive pre-clean path and caller persisted: count=%d err=%v", count, err)
			}
		})
	}
}

func TestDNSSessionDefaultTextWire(t *testing.T) {
	// A long valid zone also exercises renderer truncation of arrays/observations.
	domain := strings.Repeat("a", 50) + "." + strings.Repeat("b", 50) + ".example.test"
	svc := app.New(&config.Config{Domain: domain, DNSSessionsEnabled: true, Offline: true, AnonymousRPM: 1000, DataDir: t.TempDir()}, nil)
	ts := httptest.NewServer(New(svc).Handler())
	defer ts.Close()
	call := func(method, path string) string {
		t.Helper()
		req, err := http.NewRequest(method, ts.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		body, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != 200 || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/plain") || res.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("text wire status/headers: %d %v", res.StatusCode, res.Header)
		}
		return string(body)
	}
	issued := call("POST", "/v1/dnsleak")
	tokenPattern := regexp.MustCompile(`(?:"token"|token):\s*"([0-9a-f]{32})"`)
	match := tokenPattern.FindStringSubmatch(issued)
	token := ""
	if len(match) != 2 {
		t.Errorf("default POST omitted usable token/query names: %s", issued)
		// Independently exercise GET even when the old POST text is unusable.
		st, err := svc.DNSSessions.Issue()
		if err != nil {
			t.Fatal(err)
		}
		token = st.Token
	} else {
		token = match[1]
	}
	for i := 0; i < 3; i++ {
		if name := fmt.Sprintf("q%d.%s.dns.%s.", i, token, domain); !strings.Contains(issued, name) {
			t.Errorf("default POST omitted full query name %d", i)
		}
	}
	if !strings.Contains(issued, "expires_at") {
		t.Error("missing expiry")
	}
	empty := call("GET", "/v1/dnsleak/"+token)
	if !strings.Contains(empty, "observations") || !strings.Contains(empty, "[]") {
		t.Errorf("empty GET omitted observations: %s", empty)
	}
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp", tcp.Addr().String())
	if err != nil {
		tcp.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- svc.DNSSessions.ServeListeners(ctx, udp, tcp) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("listener cleanup timeout")
		}
	}()
	for i := 0; i < 3; i++ {
		m := new(dns.Msg)
		m.SetQuestion(fmt.Sprintf("q%d.%s.dns.%s.", i, token, domain), dns.TypeA)
		m.SetEdns0(1232, false)
		m.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 2, SourceNetmask: 128, Address: net.ParseIP(fmt.Sprintf("2001:db8:%x::123", i+1))}}
		if _, _, err := (&dns.Client{Net: "udp", Timeout: time.Second}).Exchange(m, tcp.Addr().String()); err != nil {
			t.Fatal(err)
		}
	}
	observed := call("GET", "/v1/dnsleak/"+token)
	for i := 1; i <= 3; i++ {
		if !strings.Contains(observed, fmt.Sprintf("2001:db8:%x::/56", i)) {
			t.Errorf("GET omitted observation %d: %s", i, observed)
		}
	}
	var payload leak.SessionResult
	for _, line := range strings.Split(observed, "\n") {
		if strings.HasPrefix(line, "data: ") {
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &payload); err != nil {
				t.Fatal("truncated text data", err)
			}
		}
	}
	if len(payload.Observations) != 3 {
		t.Fatalf("text omitted observations: %s", observed)
	}
	for _, obs := range payload.Observations {
		if obs.Resolver != "127.0.0.1" || obs.At.IsZero() {
			t.Error("text omitted resolver/time", obs)
		}
	}
}

func TestDNSSessionSSECache(t *testing.T) {
	svc := app.New(&config.Config{Domain: "example.test", DNSSessionsEnabled: true, Offline: true, AnonymousRPM: 1000, DataDir: t.TempDir()}, nil)
	h := New(svc).Handler()
	for _, method := range []string{"POST", "GET"} {
		t.Run(method, func(t *testing.T) {
			path, template := "/v1/dnsleak?stream=1", "/v1/dnsleak"
			if method == "GET" {
				session, err := svc.DNSSessions.Issue()
				if err != nil {
					t.Fatal(err)
				}
				path = "/v1/dnsleak/" + session.Token + "?stream=1"
				template = "/v1/dnsleak/{token}"
			}
			w := contractRequest(h, method, path, "", "application/json")
			if w.Code != 200 || w.Header().Get("Content-Type") != "text/event-stream" {
				t.Fatalf("SSE status/headers: %d %v", w.Code, w.Header())
			}
			if got := w.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("session SSE cache = %q, want no-store", got)
			}
			blocks := strings.Split(w.Body.String(), "\n\n")
			if len(blocks) < 2 || !strings.HasPrefix(blocks[0], "event: local\ndata: ") || blocks[1] != "event: done\ndata: {}" {
				t.Fatal("invalid SSE framing", w.Body.String())
			}
			var report any
			if err := json.Unmarshal([]byte(strings.TrimPrefix(blocks[0], "event: local\ndata: ")), &report); err != nil {
				t.Fatal(err)
			}
			schema := object(t, object(t, object(t, operation(t, contractDoc(t), template, strings.ToLower(method))["responses"])["200"])["content"])
			ref := object(t, object(t, schema["application/json"])["schema"])
			if err := contractSchema(t, contractDoc(t), ref).Validate(report); err != nil {
				t.Fatal(err)
			}
		})
	}
	w := contractRequest(h, "GET", "/v1/sources?stream=1", "", "application/json")
	if w.Header().Get("Cache-Control") != "no-cache" {
		t.Fatal("unrelated SSE policy changed")
	}
}
