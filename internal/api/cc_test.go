package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCCUnconfigured(t *testing.T) {
	_, h := contractHandler(t, false)
	r := httptest.NewRequest("GET", "http://untrusted.invalid/cc", nil)
	r.Header.Set("X-Forwarded-Host", "evil.invalid")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "exit 3") {
		t.Fatalf("unconfigured /cc must be an offline error script: status=%d body=%q", w.Code, w.Body.String())
	}
}

func TestCCOrigins(t *testing.T) {
	for _, raw := range []string{"https://example.test", "https://example.test:443/", "http://localhost:1234", "http://127.0.0.1:1234", "http://[::1]:1234"} {
		if _, ok := ccOrigin(raw); !ok {
			t.Errorf("rejected %q", raw)
		}
	}
	for _, raw := range []string{"", "http://example.test", "https://user:pass@example.test", "https://example.test/cc", "https://example.test?x=y", "https://example.test#x", "https://example.test#", "https://example.test';touch /tmp/pwn;'", "https://example.test\n", "https://example.test:", "https://example.test:0", "https://example.test:99999", "https://[::1%25en0]", "//example.test", "https://evil$(id).test"} {
		if _, ok := ccOrigin(raw); ok {
			t.Errorf("accepted %q", raw)
		}
	}
}

func TestCCNoPersistenceAndPeerOnly(t *testing.T) {
	svc, h := contractHandler(t, true)
	for _, tc := range []struct{ peer, want string }{{"192.0.2.1:123", "192.0.2.1\n"}, {"[2001:db8::1]:123", "2001:db8::1\n"}, {"bad", "unknown\n"}} {
		r := httptest.NewRequest("GET", "/cc/ip", nil)
		r.RemoteAddr = tc.peer
		r.Header.Set("X-Forwarded-For", "198.51.100.9")
		svc.Cfg.Offline = false
		svc.Cfg.TrustProxy = true
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 || w.Body.String() != tc.want || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%d %q", w.Code, w.Body.String())
		}
	}
	r := httptest.NewRequest("GET", "/cc", nil)
	r.Host = "evil.invalid"
	r.Header.Set("X-Forwarded-Host", "evil.invalid")
	svc.Cfg.CCOrigin = "https://trusted.example"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if strings.Contains(w.Body.String(), "evil.invalid") || !strings.Contains(w.Body.String(), "origin='https://trusted.example'") {
		t.Fatal("origin not configuration-bound")
	}
	if n, e := svc.DB.CountLogs(); e != nil || n != 0 {
		t.Fatalf("persistent logs %d %v", n, e)
	}
}

func runCC(t *testing.T, script string, dir string, env []string) (string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh")
	cmd.Stdin = strings.NewReader(script)
	cmd.Dir = dir
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "LC_ALL=C"}, env...)
	b, e := cmd.CombinedOutput()
	if e == nil {
		return string(b), 0
	}
	if ex, ok := e.(*exec.ExitError); ok {
		return string(b), ex.ExitCode()
	}
	t.Fatal(e)
	return "", -1
}

func TestCCRealShellCurl(t *testing.T) {
	if _, e := exec.LookPath("curl"); e != nil {
		t.Fatal("installed curl required")
	}
	cases := []struct {
		name, body     string
		status         int
		want           string
		code           int
		chunked, delay bool
	}{
		{"ipv4", "192.0.2.3\n", 200, "terminal_observed_ip=192.0.2.3", 0, false, false},
		{"ipv6", "2001:db8::1\n", 200, "terminal_observed_ip=2001:db8::1", 0, false, false},
		{"v6all", "::\n", 200, "terminal_observed_ip=::", 0, false, false},
		{"json", `{"ip":"2001:db8::2"}`, 200, "terminal_observed_ip=2001:db8::2", 0, false, false},
		{"unknown", "unknown\n", 200, "terminal_observed_ip=unknown", 3, false, false},
		{"badjson", `{"ip":"192.0.2.1","x":"bad"}`, 200, "malformed response", 4, false, false},
		{"shell", "$(touch PWNED)", 200, "malformed response", 4, false, false},
		{"control", "\x1b[31m192.0.2.1", 200, "malformed response", 4, false, false},
		{"newline", "192.0.2.1\nINJECTED", 200, "malformed response", 4, false, false},
		{"json4", `{"ip":"192.0.2.4"}`, 200, "terminal_observed_ip=192.0.2.4", 0, false, false},
		{"full6", "2001:db8:0:1:2:3:4:5", 200, "terminal_observed_ip=2001:db8:0:1:2:3:4:5", 0, false, false},
		{"v4trailing", "192.0.2.3.", 200, "malformed response", 4, false, false},
		{"v6trailing", "2001::db8:", 200, "malformed response", 4, false, false},
		{"v6long", "1:2:3:4:5:6:7::8", 200, "malformed response", 4, false, false},
		{"carriage", "192.0.2.3\r", 200, "malformed response", 4, false, false},
		{"bad4", "999.1.2.3", 200, "malformed response", 4, false, false},
		{"bad6", "1::2::3", 200, "malformed response", 4, false, false},
		{"oversize", strings.Repeat("X", 4096), 200, "request failed", 3, false, false},
		{"chunked", strings.Repeat("X", 4096), 200, "request failed", 3, true, false},
		{"redirect", "", 302, "unexpected HTTP status", 3, false, false},
		{"httpfail", "secret-error", 500, "request failed", 3, false, false},
		{"timeout", "", 200, "request failed", 3, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int32
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != "GET" || r.URL.RequestURI() != "/cc/ip" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.ContentLength > 0 {
					t.Errorf("unexpected request: %s %s %v", r.Method, r.URL, r.Header)
				}
				for _, v := range r.Header {
					for _, s := range v {
						if strings.Contains(s, "PRIVATE_SENTINEL") {
							t.Error("secret uploaded")
						}
					}
				}
				if tc.delay {
					select {
					case <-r.Context().Done():
						return
					case <-time.After(8 * time.Second):
						return
					}
				}
				if tc.status == 302 {
					w.Header().Set("Location", "http://127.0.0.1:1/forbidden")
				}
				w.WriteHeader(tc.status)
				if tc.chunked {
					w.(http.Flusher).Flush()
				}
				fmt.Fprint(w, tc.body)
			}))
			defer ts.Close()
			dir := t.TempDir()
			// A curlrc must not be consulted; it would change the URL/add a secret.
			if err := os.WriteFile(filepath.Join(dir, ".curlrc"), []byte("header = \"X-Leak: PRIVATE_SENTINEL\"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			script := strings.Replace(ccScript, "@ORIGIN@", ts.URL, 1)
			out, code := runCC(t, script, dir, []string{"TEST_SECRET=PRIVATE_SENTINEL"})
			if code != tc.code || !strings.Contains(out, tc.want) {
				t.Fatalf("code %d want %d: %s", code, tc.code, out)
			}
			if strings.Contains(out, "\x1b") || strings.Contains(out, "PRIVATE_SENTINEL") {
				t.Fatal("unsafe output")
			}
			files, e := os.ReadDir(dir)
			if e != nil || len(files) != 1 || files[0].Name() != ".curlrc" {
				t.Fatal("filesystem changed")
			}
			if requests.Load() != 1 {
				t.Fatalf("requests %d", requests.Load())
			}
		})
	}
}

func TestCCOfflineAndMissingCurl(t *testing.T) {
	svc, h := contractHandler(t, false)
	svc.Cfg.CCOrigin = "https://trusted.example"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/cc", nil))
	if _, code := runCC(t, w.Body.String(), t.TempDir(), nil); code != 3 {
		t.Fatalf("offline exit %d", code)
	}
	dir := t.TempDir()
	// Execute absolute /bin/sh with an empty PATH; no network is possible.
	cmd := exec.Command("/bin/sh")
	cmd.Env = []string{"PATH=" + dir}
	cmd.Stdin = strings.NewReader(ccScript)
	b, e := cmd.CombinedOutput()
	if e == nil || !strings.Contains(string(b), "installed curl required") || e.(*exec.ExitError).ExitCode() != 2 {
		t.Fatalf("missing curl: %s %v", b, e)
	}
}

func TestCCHandlerEndToEnd(t *testing.T) {
	svc, h := contractHandler(t, true)
	svc.Cfg.Offline = false
	ts := httptest.NewServer(h)
	defer ts.Close()
	svc.Cfg.CCOrigin = ts.URL
	res, e := http.Get(ts.URL + "/cc")
	if e != nil {
		t.Fatal(e)
	}
	b, e := io.ReadAll(res.Body)
	res.Body.Close()
	if e != nil || res.StatusCode != 200 {
		t.Fatal(e, res.StatusCode)
	}
	dir := t.TempDir()
	out, code := runCC(t, string(b), dir, nil)
	if code != 0 || !strings.Contains(out, "terminal_observed_ip=127.0.0.1") {
		t.Fatalf("%d %s", code, out)
	}
	if n, e := svc.DB.CountLogs(); e != nil || n != 0 {
		t.Fatalf("persisted %d %v", n, e)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatal("script wrote files")
	}
}

func TestCCProxyNoFallback(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); fmt.Fprintln(w, "192.0.2.1") }))
	defer ts.Close()
	out, code := runCC(t, strings.Replace(ccScript, "@ORIGIN@", ts.URL, 1), t.TempDir(), []string{"http_proxy=http://user:PRIVATE_SENTINEL@127.0.0.1:1", "no_proxy=", "NO_PROXY="})
	if code != 3 || calls.Load() != 0 || !strings.Contains(out, "proxy_environment_set=true") || strings.Contains(out, "PRIVATE_SENTINEL") {
		t.Fatalf("%d %d %s", code, calls.Load(), out)
	}
}

func TestCCUntrustedTLS(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("TLS must not be bypassed") }))
	defer ts.Close()
	out, code := runCC(t, strings.Replace(ccScript, "@ORIGIN@", ts.URL, 1), t.TempDir(), nil)
	if code != 3 {
		t.Fatalf("%d %s", code, out)
	}
}
