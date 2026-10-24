package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"ipd/internal/app"
	"ipd/internal/config"
	"ipd/internal/probe"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestLatencyMainSave(t *testing.T) {
	t.Setenv("IPD_DATA_DIR", t.TempDir())
	t.Setenv("IPD_VANTAGE", "self")
	t.Setenv("IPD_OFFLINE", "true")
	path := filepath.Join(t.TempDir(), "card.svg")
	out, code := captureLatencyMain(t, []string{"latency", "192.0.2.10", "--svg", path})
	if code != 10 {
		t.Errorf("exit %d, want 10", code)
	}
	if !strings.Contains(out, "VERDICT: abstain") {
		t.Errorf("missing verdict: %s", out)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "<svg") {
		t.Fatal("not SVG")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("mode %o", info.Mode().Perm())
	}
}

func captureLatencyMain(t *testing.T, args []string) (string, int) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	old := os.Stdout
	os.Stdout = f
	defer func() { os.Stdout = old }()
	code := Main(args)
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return string(b), code
}

type latencyCLIProvider struct {
	samples []probe.Sample
	err     error
	calls   int
}

func (p *latencyCLIProvider) Name() string  { return "fixture" }
func (p *latencyCLIProvider) Enabled() bool { return true }
func (p *latencyCLIProvider) Measure(_ context.Context, _ probe.Query) ([]probe.Sample, error) {
	p.calls++
	return p.samples, p.err
}

func TestLatencyDispatchSave(t *testing.T) {
	for _, tc := range []struct {
		name    string
		samples []probe.Sample
		err     error
		code    int
	}{
		{name: "success", samples: []probe.Sample{{Healthy: true, ICMP: "ok", RTTMS: 12}}, code: 0},
		{name: "empty", code: 10},
		{name: "partial", samples: []probe.Sample{{Healthy: true, ICMP: "ok", RTTMS: 12}, {Healthy: true, ICMP: "timeout"}}, code: 10},
		{name: "failed", samples: []probe.Sample{{Healthy: true, ICMP: "timeout"}}, code: 10},
		{name: "provider_error", err: errors.New("fixture unavailable"), code: 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &latencyCLIProvider{samples: tc.samples, err: tc.err}
			cfg := &config.Config{}
			svc := &app.Service{Cfg: cfg, Vantage: p}
			path := filepath.Join(t.TempDir(), "card.svg")
			rep, err := dispatch(context.Background(), svc, cfg, globals{}, "latency", []string{"192.0.2.10", "--svg=" + path})
			if err != nil {
				t.Fatal(err)
			}
			if app.ExitCode(rep.Verdict) != tc.code {
				t.Errorf("verdict %s", rep.Verdict)
			}
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(b) != rep.Data.(map[string]any)["svg"] {
				t.Error("saved card differs from report")
			}
			body, _ := render("text", rep)
			if !strings.HasPrefix(string(body), "VERDICT: "+rep.Verdict) {
				t.Error("verdict output missing")
			}
			if p.calls != 1 || cfg.ShareEnabled {
				t.Errorf("calls=%d, sharing=%v", p.calls, cfg.ShareEnabled)
			}
		})
	}
}

func TestLatencySaveProtectsPaths(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "existing.svg")
	if err := os.WriteFile(file, []byte("keep me"), 0640); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.svg")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(dir, "dangling.svg")
	if err := os.Symlink(filepath.Join(dir, "absent.svg"), dangling); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{file, dir, link, dangling, filepath.Join(dir, "missing", "card.svg")} {
		p := &latencyCLIProvider{}
		_, err := latencyCmd(context.Background(), &app.Service{Vantage: p}, []string{"192.0.2.10", "--svg", path})
		if err == nil {
			t.Errorf("accepted existing/unwritable path %s", path)
		}
		if p.calls != 0 {
			t.Error("measurement requested despite invalid destination")
		}
	}
	b, err := os.ReadFile(file)
	if err != nil || string(b) != "keep me" {
		t.Fatalf("existing file changed: %q %v", b, err)
	}
	info, err := os.Stat(file)
	if err != nil || info.Mode().Perm() != 0640 {
		t.Fatal("existing permissions changed")
	}
	if _, err := os.Lstat(dangling); err != nil {
		t.Error("existing dangling symlink removed")
	}
}

func TestLatencyUsageAndExitCodes(t *testing.T) {
	t.Setenv("IPD_DATA_DIR", t.TempDir())
	t.Setenv("IPD_OFFLINE", "true")
	t.Setenv("IPD_VANTAGE", "self")
	for _, args := range [][]string{
		{"latency"}, {"latency", "192.0.2.10", "--svg"}, {"latency", "192.0.2.10", "--svg="},
		{"latency", "192.0.2.10", "--more-probes"}, {"latency", "192.0.2.10", "extra"},
		{"latency", "192.0.2.10", "--svg", "--other"},
		{"latency", "192.0.2.10", "--svg=x", "--svg=y"},
	} {
		if _, code := captureLatencyMain(t, args); code != 2 {
			t.Errorf("%v exit %d, want 2", args, code)
		}
	}
	existing := filepath.Join(t.TempDir(), "existing.svg")
	if err := os.WriteFile(existing, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, code := captureLatencyMain(t, []string{"latency", "192.0.2.10", "--svg", existing}); code != 2 {
		t.Errorf("overwrite exit %d", code)
	}
	out, code := captureLatencyMain(t, []string{"latency", "--help"})
	if code != 0 || !strings.Contains(out, "--svg <local-file>") {
		t.Error("latency help unavailable")
	}
	out, code = captureLatencyMain(t, []string{"latency", "192.0.2.10"})
	if code != 10 || !strings.HasPrefix(out, "VERDICT: abstain") {
		t.Errorf("no-save mode: %d %s", code, out)
	}
}

func TestLatencyMainProviderFixtures(t *testing.T) {
	good := `{"probe":{"asn":64512,"city":"Fixture CLI","country":"ZZ"},"result":{"status":"finished","stats":{"avg":12.5,"loss":0}}}`
	failed := `{"probe":{"asn":64512,"city":"Fixture CLI","country":"ZZ"},"result":{"status":"failed","rawOutput":"fixture timeout","stats":{"avg":0,"loss":100}}}`
	for _, tc := range []struct {
		name, results, verdict string
		code                   int
	}{
		{"success", good, "ok", 0},
		{"empty", "", "abstain", 10},
		{"partial", good + "," + failed, "ok_with_caveats", 10},
		{"failed", failed, "abstain", 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var creates, reads atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodPost && r.URL.Path == "/measurements":
					creates.Add(1)
					var request struct {
						Target string `json:"target"`
					}
					if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.Target != "192.0.2.10" {
						t.Errorf("request: %+v %v", request, err)
					}
					_, _ = io.WriteString(w, `{"id":"fixture"}`)
				case r.Method == http.MethodGet && r.URL.Path == "/measurements/fixture":
					reads.Add(1)
					_, _ = io.WriteString(w, `{"status":"finished","results":[`+tc.results+`]}`)
				default:
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			t.Setenv("IPD_DATA_DIR", t.TempDir())
			t.Setenv("IPD_VANTAGE", "globalping")
			t.Setenv("IPD_GLOBALPING_URL", server.URL)
			t.Setenv("IPD_GLOBALPING_TOKEN", "")
			t.Setenv("IPD_OFFLINE", "false")
			t.Setenv("IPD_SHARE_ENABLED", "false")
			path := filepath.Join(t.TempDir(), "main.svg")
			out, code := captureLatencyMain(t, []string{"latency", "192.0.2.10", "--svg", path})
			if code != tc.code || !strings.HasPrefix(out, "VERDICT: "+tc.verdict+" ") {
				t.Errorf("exit=%d, output=%s", code, out)
			}
			card, err := os.ReadFile(path)
			if err != nil || !strings.Contains(string(card), "VERDICT: "+tc.verdict) {
				t.Fatalf("card: %v %s", err, card)
			}
			if creates.Load() != 1 || reads.Load() != 1 {
				t.Errorf("requests: create=%d read=%d", creates.Load(), reads.Load())
			}
		})
	}
}
