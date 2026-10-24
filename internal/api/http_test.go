package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ipd/internal/app"
	"ipd/internal/config"
	"ipd/internal/privacy"
	"ipd/internal/store"
)

func testServer(t *testing.T) *httptest.Server {
	t.Helper()
	cfg := config.FromEnv()
	cfg.Offline = true
	cfg.AnonymousRPM = 1000
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	svc := app.New(cfg, db)
	return httptest.NewServer(New(svc).Handler())
}

func TestCurlVerdictAndFormats(t *testing.T) {
	ts := testServer(t)
	defer ts.Close()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/", nil)
	req.Header.Set("User-Agent", "curl/8.5.0")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.HasPrefix(string(body), "VERDICT:") {
		t.Fatalf("text:\n%s", body)
	}
	for _, tc := range []struct{ accept, want string }{
		{"application/json", "{"},
		{"text/markdown", "# VERDICT:"},
		{"text/plain", "VERDICT:"},
	} {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/ip/1.1.1.1", nil)
		req.Header.Set("Accept", tc.accept)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if !strings.HasPrefix(string(b), tc.want) {
			t.Fatalf("%s got %s", tc.accept, b[:min(80, len(b))])
		}
	}
	res, err = http.Get(ts.URL + "/v1/ip/8.8.8.8.json")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.Contains(string(b), `"verdict"`) {
		t.Fatalf("suffix json: %s", b)
	}
	res, err = http.Get(ts.URL + "/v1/ip/8.8.8.8.md")
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.HasPrefix(string(b), "# VERDICT:") {
		t.Fatal(string(b))
	}
}

func TestOpenAPIAndLLMS(t *testing.T) {
	if err := LintOpenAPI(OpenAPI()); err != nil {
		t.Fatal(err)
	}
	text := LLMS("example.test")
	if !strings.Contains(text, "https://example.test/") || !strings.Contains(text, "ip_lookup") {
		t.Fatal(text)
	}
	ts := testServer(t)
	defer ts.Close()
	res, err := http.Get(ts.URL + "/llms.txt")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.Contains(string(b), "ipd") {
		t.Fatal(string(b))
	}
	res, err = http.Get(ts.URL + "/healthz")
	if err != nil || res.StatusCode != 200 {
		t.Fatal(err, res.StatusCode)
	}
}

func TestShareOffAndWebRTCDropped(t *testing.T) {
	ts := testServer(t)
	defer ts.Close()
	res, err := http.Post(ts.URL+"/v1/report", "text/plain", strings.NewReader("host laptop.local 10.1.2.3"))
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("share status %d", res.StatusCode)
	}
	res, err = http.Post(ts.URL+"/v1/leak/webrtc", "application/json", strings.NewReader(`{"leak":true,"candidate_count":2,"candidate_ips":["1.2.3.4"]}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if strings.Contains(string(b), "1.2.3.4") {
		t.Fatalf("stored candidate %s", b)
	}
	if strings.Contains(store.SchemaSQL(), "candidate_ip") {
		t.Fatal("schema has candidate ip")
	}
	raw, _ := json.Marshal(privacy.WebRTCReport{Leak: true, CandidateCount: 2})
	if strings.Contains(string(raw), "candidate_ip") || strings.Contains(string(raw), "1.2.3.4") {
		t.Fatal(string(raw))
	}
}

func TestRateLimit(t *testing.T) {
	cfg := config.FromEnv()
	cfg.Offline = true
	cfg.AnonymousRPM = 2
	svc := app.New(cfg, nil)
	ts := httptest.NewServer(New(svc).Handler())
	defer ts.Close()
	ok := 0
	for i := 0; i < 5; i++ {
		res, err := http.Get(ts.URL + "/v1/sources")
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode == 200 {
			ok++
		}
	}
	if ok != 2 {
		t.Fatalf("allowed %d", ok)
	}
}

func TestBrowserHTML(t *testing.T) {
	ts := testServer(t)
	defer ts.Close()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/", nil)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.Contains(string(b), "无法判定") {
		t.Fatalf("html %s", b[:min(120, len(b))])
	}
	res, err = http.Get(ts.URL + "/static/judge.js")
	if err != nil || res.StatusCode != 200 {
		t.Fatal(res.StatusCode, err)
	}
}

func TestSSE(t *testing.T) {
	ts := testServer(t)
	defer ts.Close()
	res, err := http.Get(ts.URL + "/v1/ip/1.1.1.1?stream=1")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.Contains(string(b), "event: local") || !strings.Contains(string(b), "event: done") {
		t.Fatal(string(b))
	}
}

func TestFavicon(t *testing.T) {
	ts := testServer(t)
	defer ts.Close()
	res, err := http.Get(ts.URL + "/favicon.ico")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(string(b), "<svg") {
		t.Fatalf("status %d body %s", res.StatusCode, b)
	}
	res, err = http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.Contains(string(b), "favicon.svg") {
		t.Fatal("page missing icon link")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
