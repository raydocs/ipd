package api

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"ipd/internal/app"
	"ipd/internal/config"
	"ipd/internal/leak"
	"ipd/internal/store"
)

func TestDNSSessionDisabled(t *testing.T) {
	_, h := contractHandler(t, false)
	for _, method := range []string{"GET", "POST"} {
		path := "/v1/dnsleak"
		if method == "GET" {
			path += "/not-issued"
		}
		w := contractRequest(h, method, path, "", "application/json")
		if w.Code != 503 {
			t.Errorf("%s disabled status = %d, want 503", method, w.Code)
		}
	}
}

func sessionHTTP(t *testing.T, h http.Handler, method, path string, status int) *httptest.ResponseRecorder {
	t.Helper()
	w := contractRequest(h, method, path, "", "application/json")
	if w.Code != status {
		t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("missing no-store")
	}
	template, verb := "/v1/dnsleak/{token}", "get"
	if method == "POST" {
		template, verb = "/v1/dnsleak", "post"
	}
	validateContractResponse(t, contractDoc(t), template, verb, w)
	return w
}

func TestDNSSessionLocalEndToEnd(t *testing.T) {
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cfg := &config.Config{Domain: "example.test", Offline: true, DNSSessionsEnabled: true, AnonymousRPM: 1000, DataDir: t.TempDir()}
	svc := app.New(cfg, db)
	var clock atomic.Int64
	clock.Store(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano())
	svc.Now = func() time.Time { return time.Unix(0, clock.Load()).UTC() }
	h := New(svc).Handler()
	// Real loopback HTTP as well as real UDP/TCP, all offline.
	httpServer := httptest.NewServer(h)
	defer httpServer.Close()
	httpCall := func(method, path string, status int) *httptest.ResponseRecorder {
		t.Helper()
		req, _ := http.NewRequest(method, httpServer.URL+path, nil)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("X-Forwarded-For", "192.0.2.55")
		res, err := httpServer.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		w := httptest.NewRecorder()
		w.HeaderMap = res.Header.Clone()
		w.Code = res.StatusCode
		_, _ = io.Copy(w.Body, res.Body)
		if w.Code != status {
			t.Fatalf("HTTP %s %s: %d %s", method, path, w.Code, w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("missing no-store")
		}
		template, verb := "/v1/dnsleak/{token}", "get"
		if method == "POST" {
			template, verb = "/v1/dnsleak", "post"
		}
		validateContractResponse(t, contractDoc(t), template, verb, w)
		return w
	}
	issued := httpCall("POST", "/v1/dnsleak", 200)
	value := decodeContractJSON(t, issued)
	if value["verdict"] != "abstain" {
		t.Fatal("issuance asserted safety")
	}
	var session leak.Session
	if err = json.Unmarshal(mustJSON(t, value["data"]), &session); err != nil {
		t.Fatal(err)
	}
	other, _ := svc.DNSSessions.Issue()
	read := func(token string) leak.SessionResult {
		t.Helper()
		w := httpCall("GET", "/v1/dnsleak/"+token, 200)
		value := decodeContractJSON(t, w)
		if value["verdict"] != "abstain" {
			t.Fatal("observation claimed safety or causality")
		}
		if _, exists := object(t, value["data"])["leak"]; exists {
			t.Fatal("leak boolean leaked into session contract")
		}
		var out leak.SessionResult
		if err := json.Unmarshal(mustJSON(t, value["data"]), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := read(session.Token); len(got.Observations) != 0 {
		t.Fatal("new session not empty")
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
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- svc.DNSSessions.ServeListeners(ctx, udp, tcp) }()
	for i, network := range []string{"udp", "tcp", "udp"} {
		typ := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeTXT}[i]
		m := new(dns.Msg)
		m.SetQuestion(session.QueryNames[i], typ)
		// Different masked ECS proves that both transports reach the same recorder.
		if i == 1 {
			m.SetEdns0(1232, false)
			m.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 32, Address: net.ParseIP("198.51.100.123")}}
		}
		response, _, err := (&dns.Client{Net: network, Timeout: time.Second}).Exchange(m, tcp.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		if response.Rcode != dns.RcodeSuccess || len(response.Answer) != 1 || response.Answer[0].Header().Rrtype != typ {
			t.Fatal(response)
		}
	}
	result := read(session.Token)
	if len(result.Observations) != 2 {
		t.Fatalf("shared/dedup recorder: %#v", result)
	}
	for _, obs := range result.Observations {
		if obs.Resolver != "127.0.0.1" || !obs.At.Equal(svc.Now()) {
			t.Fatal(obs)
		}
	}
	if result.Observations[1].ECS != "198.51.100.0/24" {
		t.Fatal(result)
	}
	if got := read(other.Token); len(got.Observations) != 0 {
		t.Fatal("cross-session read")
	}
	httpCall("GET", "/v1/dnsleak/not-issued", 404)
	clock.Store(session.ExpiresAt.UnixNano())
	httpCall("GET", "/v1/dnsleak/"+session.Token, 404)
	// No raw question, bearer path, caller, or observations may enter SQLite.
	if count, err := db.CountLogs(); err != nil || count != 0 {
		t.Fatalf("DNS request persisted: count=%d err=%v", count, err)
	}
	var count int
	if err := db.DB.QueryRow("SELECT count(*) FROM results").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("DNS observations persisted")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("DNS listeners did not stop")
	}
	for _, network := range []string{"udp", "tcp"} {
		var close func() error
		if network == "udp" {
			pc, err := net.ListenPacket(network, tcp.Addr().String())
			if err != nil {
				t.Fatal("UDP leaked", err)
			}
			close = pc.Close
		} else {
			ln, err := net.Listen(network, tcp.Addr().String())
			if err != nil {
				t.Fatal("TCP leaked", err)
			}
			close = ln.Close
		}
		close()
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDNSSessionCapacityAndDisabledContracts(t *testing.T) {
	svc, h := contractHandler(t, true)
	for _, method := range []string{"POST", "GET"} {
		path := "/v1/dnsleak"
		if method == "GET" {
			path += "/anything"
		}
		sessionHTTP(t, h, method, path, 503)
	}
	svc.DNSSessions = leak.NewDNSServer("example.test", leak.SessionOptions{Enabled: true, MaxSessions: 1})
	sessionHTTP(t, h, "POST", "/v1/dnsleak", 200)
	sessionHTTP(t, h, "POST", "/v1/dnsleak", 503)
	sessionHTTP(t, h, "GET", "/v1/dnsleak/missing", 404)
	if count, err := svc.DB.CountLogs(); err != nil || count != 0 {
		t.Fatal(count, err)
	}
}

func TestDNSSessionPathsNeverPersist(t *testing.T) {
	svc, h := contractHandler(t, true)
	for _, path := range []string{"/v1/dnsleak", "/v1/dnsleak/privatefixture", "/v1//dnsleak/privatefixture", "/v1/other/../dnsleak/privatefixture", "/v1/dnsleak/privatefixture/../../sources"} {
		contractRequest(h, "GET", path, "", "application/json")
	}
	if count, err := svc.DB.CountLogs(); err != nil || count != 0 {
		t.Fatal("bearer/caller logged", count, err)
	}
	// An unrelated route still has its previous logging behavior.
	contractRequest(h, "GET", "/v1/sources", "", "application/json")
	if count, err := svc.DB.CountLogs(); err != nil || count != 1 {
		t.Fatal("unrelated logging changed", count, err)
	}
}
