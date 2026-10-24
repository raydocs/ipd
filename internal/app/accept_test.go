package app

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"ipd/internal/config"
	"ipd/internal/privacy"
	"ipd/internal/store"
	"ipd/internal/unlock"
)

func newSvc(t *testing.T) *Service {
	t.Helper()
	cfg := config.FromEnv()
	cfg.Offline = true
	cfg.ShareEnabled = true
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return New(cfg, db)
}

type fx struct{ body func(url string) string }

func (f fx) Get(ctx context.Context, rawURL string, headers map[string]string) unlock.Response {
	body := "open"
	if f.body != nil {
		if b := f.body(rawURL); b != "" {
			body = b
		}
	}
	if strings.Contains(rawURL, "tiktok") && !strings.Contains(body, "region") {
		body = `"region":"US"`
	}
	if strings.Contains(rawURL, "gemini") && body == "open" {
		body = "gemini ready"
	}
	return unlock.Response{Status: 200, Body: body, FinalURL: rawURL}
}

func TestAIEnvMismatchAndBlock(t *testing.T) {
	s := newSvc(t)
	s.Checks = &unlock.Engine{Get: fx{body: func(u string) string {
		if strings.Contains(u, "claude.ai/cdn-cgi/trace") {
			return "ip=1.1.1.1\nloc=US\n"
		}
		if strings.Contains(u, "cdn-cgi/trace") {
			return "ip=8.8.8.8\nloc=US\n"
		}
		return ""
	}}}
	start := time.Now()
	rep := s.AIEnv(context.Background(), false)
	if time.Since(start) > 8*time.Second {
		t.Fatal("slow")
	}
	blob, _ := json.Marshal(rep.Data)
	var parsed struct {
		Fixes []struct {
			Issue string `json:"issue"`
		} `json:"fixes"`
		IPv6 bool `json:"ipv6_bypass"`
	}
	if err := json.Unmarshal(blob, &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Fixes) == 0 || parsed.Fixes[0].Issue != "egress_mismatch" {
		t.Fatalf("%s", blob)
	}

	s.Checks = &unlock.Engine{Get: fx{body: func(u string) string {
		if strings.Contains(u, "claude.ai/") && !strings.Contains(u, "trace") {
			return "app-unavailable-in-region"
		}
		if strings.Contains(u, "trace") {
			return "ip=1.1.1.1\nloc=US\n"
		}
		return ""
	}}}
	blocked := s.AIEnv(context.Background(), false)
	if blocked.Verdict != "blocked" {
		t.Fatalf("%s %+v", blocked.Verdict, blocked.Data)
	}
}

func TestIPv6Bypass(t *testing.T) {
	s := newSvc(t)
	s.Egress = func(ctx context.Context) (string, string) { return "8.8.8.8", "240e:0:1::1" }
	s.Checks = &unlock.Engine{Get: fx{body: func(u string) string {
		if strings.Contains(u, "trace") {
			return "ip=8.8.8.8\nloc=US\n"
		}
		return ""
	}}}
	rep := s.AIEnv(context.Background(), false)
	if rep.Data.(map[string]any)["ipv6_bypass"] != true {
		t.Fatalf("%+v", rep.Data)
	}
}

func TestShareRedacts(t *testing.T) {
	s := newSvc(t)
	rep, err := s.Share("gateway 10.1.2.3 host mybox.local", []string{"mybox"})
	if err != nil {
		t.Fatal(err)
	}
	body := rep.Data.(map[string]any)["body"].(string)
	if strings.Contains(body, "10.1.2.3") || strings.Contains(body, "mybox") {
		t.Fatal(body)
	}
	s.Cfg.ShareEnabled = false
	if _, err := s.Share("x", nil); err == nil {
		t.Fatal("expected disabled")
	}
}

func TestWatchHMAC(t *testing.T) {
	s := newSvc(t)
	created, err := s.CreateWatch("1.1.1.1", "risk", "http://example.invalid/hook")
	if err != nil {
		t.Fatal(err)
	}
	id := created.Data.(map[string]any)["watch_id"].(string)
	secret := created.Data.(map[string]any)["secret"].(string)
	if err := s.DB.UpdateWatch(id, "stale", time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	var got string
	n, err := s.RunDueWatches(context.Background(), func(url string, body []byte, sig string) error {
		got = sig
		if !strings.HasPrefix(sig, "sha256=") {
			t.Fatal(sig)
		}
		return nil
	})
	if err != nil || n != 1 || !strings.HasPrefix(got, "sha256=") || secret == "" {
		t.Fatalf("n=%d err=%v sig=%s", n, err, got)
	}
}

func TestSourcesAndNeighbors(t *testing.T) {
	s := newSvc(t)
	rep := s.Sources()
	blob, _ := json.Marshal(rep.Data)
	var parsed struct {
		Sources []struct {
			ID, License, Attribution, Kind string
			Enabled                        bool
		} `json:"sources"`
	}
	if err := json.Unmarshal(blob, &parsed); err != nil {
		t.Fatal(err)
	}
	local, online, zones := 0, 0, 0
	for _, row := range parsed.Sources {
		if row.License == "" || row.Attribution == "" {
			t.Fatalf("missing credit %+v", row)
		}
		switch row.Kind {
		case "local":
			local++
		case "online":
			online++
		case "dnsbl":
			zones++
		}
	}
	if local < 12 || online < 6 || zones < 15 {
		t.Fatalf("local %d online %d dnsbl %d", local, online, zones)
	}
	for i := 0; i < 100; i++ {
		rep, err := s.Prefix("3.1." + itoa(i) + ".0/24")
		if err != nil {
			t.Fatal(err)
		}
		blob, _ := json.Marshal(rep.Data)
		var comp struct {
			Contamination float64 `json:"contamination"`
		}
		_ = json.Unmarshal(blob, &comp)
		if comp.Contamination < 0.8 {
			t.Fatalf("3.1.%d.0/24 contamination %v", i, comp.Contamination)
		}
	}
	risk, err := s.Risk(context.Background(), "24.1.2.3", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(risk.Sources) == 0 || len(risk.Attribution) == 0 {
		t.Fatalf("sources %+v attr %+v", risk.Sources, risk.Attribution)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [4]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func TestPeakAndCanary(t *testing.T) {
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	var samples []time.Time
	for i := 0; i < 160; i++ {
		samples = append(samples, start.Add(time.Duration(i)*time.Hour))
	}
	end := start.Add(168 * time.Hour)
	if PeakCoverage(samples, start, end) < 0.95 {
		t.Fatal(PeakCoverage(samples, start, end))
	}
	alerts := CanaryDiff(map[string]map[string]string{
		"la-direct": {"claude": "no", "chatgpt": "yes", "netflix": "yes", "google_region": "yes"},
	})
	if len(alerts) == 0 {
		t.Fatal("expected canary alert")
	}
}

func TestLogRetention(t *testing.T) {
	s := newSvc(t)
	old := time.Now().Add(-8 * 24 * time.Hour)
	if err := s.DB.InsertLogAt("203.0.113.9", old); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.LogIP("203.0.113.10", "/", time.Now()); err != nil {
		t.Fatal(err)
	}
	n, err := s.DB.PurgeLogs(time.Now(), privacy.Retention)
	if err != nil || n < 1 {
		t.Fatal(n, err)
	}
	left, err := s.DB.CountLogs()
	if err != nil || left != 1 {
		t.Fatal(left, err)
	}
	if err := s.WebRTC(privacy.WebRTCReport{Leak: true, CandidateCount: 3}); err != nil {
		t.Fatal(err)
	}
}
