package app

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"ipd/internal/config"
	"math"
	"strings"
	"testing"
	"time"

	"ipd/internal/probe"
)

func latencyFixture(samples []probe.Sample) *Service {
	return &Service{Now: func() time.Time { return time.Date(2026, 10, 24, 8, 30, 0, 0, time.FixedZone("fixture", -6*3600)) },
		Vantage: probe.Globalping{Runner: func(context.Context, probe.Query) ([]probe.Sample, error) { return samples, nil }}}
}

func TestLatencyEvidence(t *testing.T) {
	good := probe.Sample{Provider: "fixture", Country: "ZZ", City: "Fixture City", Healthy: true, ICMP: "ok", RTTMS: 12.5}
	failed := probe.Sample{Provider: "fixture", Healthy: true, ICMP: "timeout", Loss: 1}
	for _, tc := range []struct {
		name, verdict          string
		samples                []probe.Sample
		valid, failed, unknown int
	}{
		{"success", "ok", []probe.Sample{good}, 1, 0, 0},
		{"empty", "abstain", nil, 0, 0, 0},
		{"partial", "ok_with_caveats", []probe.Sample{good, failed, {ICMP: "skipped"}}, 1, 1, 1},
		{"all_failed", "abstain", []probe.Sample{failed}, 0, 1, 0},
		{"missing", "abstain", []probe.Sample{{Healthy: true, ICMP: "ok"}}, 0, 0, 1},
		{"contradictory_loss", "abstain", []probe.Sample{{Healthy: true, ICMP: "loss", RTTMS: 12}}, 0, 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep, err := latencyFixture(tc.samples).Latency(context.Background(), "192.0.2.10")
			if err != nil {
				t.Fatal(err)
			}
			if rep.Verdict != tc.verdict {
				t.Errorf("verdict = %q, want %q", rep.Verdict, tc.verdict)
			}
			d := rep.Data.(map[string]any)
			for k, want := range map[string]any{"target": "192.0.2.10", "measured_at": "2026-10-24T14:30:00Z", "sample_count": len(tc.samples), "valid_count": tc.valid, "failed_count": tc.failed, "unknown_count": tc.unknown} {
				if d[k] != want {
					t.Errorf("%s = %v, want %v", k, d[k], want)
				}
			}
			rows := d["rows"].([]map[string]any)
			for _, row := range rows {
				if row["status"] != "valid" && row["rtt_ms"] != nil {
					t.Errorf("invalid sample claims RTT: %+v", row)
				}
			}
			svg := d["svg"].(string)
			if strings.Contains(svg, "0.0 ms") {
				t.Error("invalid zero displayed as measured RTT")
			}
		})
	}
}

func TestLatencySVGInertXML(t *testing.T) {
	attack := `</text><script>alert(1)</script><image href="https://example.invalid/x" onload="alert(2)"/><text>&"'`
	svc := latencyFixture([]probe.Sample{{Provider: attack, Country: attack, City: attack, Healthy: true, ICMP: "ok", RTTMS: 8}})
	rep, err := svc.Latency(context.Background(), attack)
	if err != nil {
		t.Fatal(err)
	}
	svg := rep.Data.(map[string]any)["svg"].(string)
	assertLatencyXML(t, svg)
	if !strings.Contains(svg, "&lt;script&gt;") {
		t.Error("dynamic text was not escaped")
	}
}

func assertLatencyXML(t *testing.T, svg string) {
	t.Helper()
	d := xml.NewDecoder(strings.NewReader(svg))
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("invalid XML: %v", err)
		}
		if el, ok := tok.(xml.StartElement); ok {
			switch el.Name.Local {
			case "svg", "rect", "text":
			default:
				t.Errorf("unexpected SVG element: %s", el.Name.Local)
			}
			for _, a := range el.Attr {
				if strings.HasPrefix(strings.ToLower(a.Name.Local), "on") || a.Name.Local == "href" || strings.Contains(a.Value, "url(") {
					t.Errorf("active/resource attribute: %+v", a)
				}
			}
		}
	}
}

// The fixture implements the provider boundary without any network access.
type latencyProvider struct {
	name    string
	enabled bool
	samples []probe.Sample
	err     error
	calls   int
	query   probe.Query
}

func (p *latencyProvider) Name() string  { return p.name }
func (p *latencyProvider) Enabled() bool { return p.enabled }
func (p *latencyProvider) Measure(_ context.Context, q probe.Query) ([]probe.Sample, error) {
	p.calls++
	p.query = q
	return p.samples, p.err
}

func TestLatencyBudgetAndUnavailable(t *testing.T) {
	good := probe.Sample{Healthy: true, ICMP: "ok", RTTMS: 15}
	for _, tc := range []struct {
		name              string
		offline, disabled bool
		err               error
		samples           []probe.Sample
		want              string
		calls             int
	}{
		{name: "budget", samples: []probe.Sample{good}, want: "ok", calls: 1},
		{name: "provider_error", err: errors.New("fixture unavailable"), want: "abstain", calls: 1},
		{name: "partial_provider_error", err: errors.New("fixture truncated"), samples: []probe.Sample{good}, want: "ok_with_caveats", calls: 1},
		{name: "offline", offline: true, want: "abstain"},
		{name: "disabled", disabled: true, want: "abstain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &latencyProvider{name: "fixture", enabled: !tc.disabled, samples: tc.samples, err: tc.err}
			s := latencyFixture(nil)
			s.Cfg = &config.Config{Offline: tc.offline}
			s.Vantage = p
			rep, err := s.Latency(context.Background(), "192.0.2.10")
			if err != nil {
				t.Fatal(err)
			}
			if rep.Verdict != tc.want || p.calls != tc.calls {
				t.Fatalf("verdict %s, calls %d", rep.Verdict, p.calls)
			}
			if p.calls > 0 && (p.query.Kind != probe.KindPing || p.query.Target != "192.0.2.10" || p.query.Limit != 2 || p.query.Control != 2 || p.query.Packets != 0 || len(p.query.Countries) != 0 || len(p.query.Carriers) != 0) {
				t.Errorf("budget changed: %+v", p.query)
			}
			if s.Cfg.ShareEnabled {
				t.Error("sharing enabled")
			}
			assertLatencyXML(t, rep.Data.(map[string]any)["svg"].(string))
			if tc.err != nil && strings.Contains(rep.Data.(map[string]any)["svg"].(string), tc.err.Error()) {
				t.Error("raw transport error copied into shareable card")
			}
		})
	}
	s := latencyFixture(nil)
	s.Vantage = nil
	rep, err := s.Latency(context.Background(), "192.0.2.10")
	if err != nil || rep.Verdict != "abstain" {
		t.Fatalf("nil provider: %v %+v", err, rep)
	}
	if _, err := s.Latency(context.Background(), " "); err == nil {
		t.Error("empty target accepted")
	}
}

func TestLatencyInvalidNumbersAndLoss(t *testing.T) {
	for _, tc := range []struct {
		name            string
		rtt, loss       float64
		status, verdict string
	}{
		{"loss", 8, .25, "valid", "ok_with_caveats"},
		{"tiny_positive_rtt", .000001, 0, "valid", "ok"},
		{"tiny_positive_loss", 8, .000001, "valid", "ok_with_caveats"},
		{"nan_rtt", math.NaN(), 0, "unknown", "abstain"},
		{"inf_rtt", math.Inf(1), 0, "unknown", "abstain"},
		{"negative_rtt", -1, 0, "unknown", "abstain"},
		{"nan_loss", 8, math.NaN(), "unknown", "abstain"},
		{"inf_loss", 8, math.Inf(1), "unknown", "abstain"},
		{"invalid_loss", 8, 10, "unknown", "abstain"},
		{"negative_loss", 8, -.1, "unknown", "abstain"},
		{"total_loss", 8, 1, "failed", "abstain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep, err := latencyFixture([]probe.Sample{{Healthy: true, ICMP: "ok", RTTMS: tc.rtt, Loss: tc.loss}}).Latency(context.Background(), "192.0.2.10")
			if err != nil {
				t.Fatal(err)
			}
			d := rep.Data.(map[string]any)
			row := d["rows"].([]map[string]any)[0]
			if rep.Verdict != tc.verdict || row["status"] != tc.status {
				t.Errorf("%s %+v", rep.Verdict, row)
			}
			if _, err := json.Marshal(rep); err != nil {
				t.Errorf("non-JSON numeric evidence: %v", err)
			}
			assertLatencyXML(t, d["svg"].(string))
		})
	}
}

func TestLatencySVGDynamicLabels(t *testing.T) {
	attack := `</text><script/><a href="https://example.invalid/" onload="x">&'"`
	p := &latencyProvider{name: attack, enabled: true, samples: []probe.Sample{
		{Provider: attack, City: attack, Country: attack, Healthy: true, ICMP: "ok", RTTMS: 5},
		{Healthy: true, ICMP: "timeout", Error: attack},
		{Healthy: false, ICMP: "timeout"},
	}}
	s := latencyFixture(nil)
	s.Vantage = p
	rep, err := s.Latency(context.Background(), attack)
	if err != nil {
		t.Fatal(err)
	}
	svg := rep.Data.(map[string]any)["svg"].(string)
	assertLatencyXML(t, svg)
	var text strings.Builder
	d := xml.NewDecoder(strings.NewReader(svg))
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if v, ok := tok.(xml.CharData); ok {
			text.Write(v)
		}
	}
	if strings.Count(text.String(), attack) < 6 {
		t.Error("target/source/location labels not preserved")
	}
	if strings.Contains(svg, "0.000 ms") || !strings.Contains(svg, "Packet loss: unknown") {
		t.Error("unknown/failed sample presented as successful")
	}
	// XML-invalid runes must not make an otherwise safe card unparsable.
	rep, err = s.Latency(context.Background(), "192.0.2.10\x00\x01\xff")
	if err != nil {
		t.Fatal(err)
	}
	assertLatencyXML(t, rep.Data.(map[string]any)["svg"].(string))
}

func TestLatencySVGWithholdsRawSampleErrors(t *testing.T) {
	for _, tc := range []struct {
		name, raw, reason string
		healthy           bool
		icmp              string
		secrets           []string
	}{
		{"credential_url", `Get "https://fixture-user:fixture-secret@provider.example.invalid/measure?token=fixture-token": fixture failure`, "provider reported an error", true, "timeout", []string{"fixture-user", "fixture-secret", "provider.example.invalid", "fixture-token"}},
		{"internal_host", "dial tcp probe.internal.example.invalid:443: fixture failure", "probe health unavailable or unhealthy", false, "timeout", []string{"probe.internal.example.invalid"}},
		{"local_path", "open /fixture/private/latency-config: fixture failure", "measurement skipped", true, "skipped", []string{"/fixture/private/latency-config"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := latencyFixture([]probe.Sample{{Provider: "fixture", Healthy: tc.healthy, ICMP: tc.icmp, Error: tc.raw}})
			rep, err := svc.Latency(context.Background(), "192.0.2.10")
			if err != nil {
				t.Fatal(err)
			}
			data := rep.Data.(map[string]any)
			svg := data["svg"].(string)
			assertLatencyXML(t, svg)
			// Inspect decoded text too: XML escaping and line wrapping are not redaction.
			var decoded strings.Builder
			d := xml.NewDecoder(strings.NewReader(svg))
			for {
				tok, err := d.Token()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				if text, ok := tok.(xml.CharData); ok {
					decoded.Write(text)
				}
			}
			for _, secret := range append([]string{tc.raw}, tc.secrets...) {
				if strings.Contains(svg, secret) || strings.Contains(decoded.String(), secret) {
					t.Error("raw provider error or sensitive fixture value leaked into SVG")
				}
			}
			if !strings.Contains(decoded.String(), tc.reason) {
				t.Error("controlled reason missing from SVG")
			}
			row := data["rows"].([]map[string]any)[0]
			if row["error"] != tc.raw {
				t.Error("raw evidence unexpectedly changed; JSON is explicitly not redacted")
			}
			if rep.Verdict != "abstain" {
				t.Errorf("verdict = %s", rep.Verdict)
			}
		})
	}
}
