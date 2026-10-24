package app

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"ipd/internal/unlock"
)

type aiGetter func(context.Context, string) unlock.Response

func (f aiGetter) Get(ctx context.Context, u string, _ map[string]string) unlock.Response {
	return f(ctx, u)
}

func aiData(t *testing.T, r Report) map[string]any {
	t.Helper()
	b, err := json.Marshal(r.Data)
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	return d
}
func aiRows(t *testing.T, d map[string]any) []any {
	t.Helper()
	rows, ok := d["per_service"].([]any)
	if !ok || len(rows) != 7 {
		t.Fatalf("expected seven service observations: %+v", d)
	}
	return rows
}
func aiResponse(u string) unlock.Response {
	body := "open"
	if strings.Contains(u, "gemini") {
		body = "gemini ready"
	}
	if strings.Contains(u, "meta.ai") {
		body = "KadabraRootContainer"
	}
	return unlock.Response{Status: 200, Body: body, FinalURL: u}
}

func TestAIEnvUnknownRegressions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		checks *unlock.Engine
	}{
		{"nil engine", nil},
		{"nil getter", &unlock.Engine{}},
		{"timeout", &unlock.Engine{Get: aiGetter(func(context.Context, string) unlock.Response { return unlock.Response{Err: context.DeadlineExceeded} })}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Service{Checks: tc.checks}
			r := s.AIEnv(context.Background(), false)
			if r.Verdict != "abstain" {
				t.Errorf("unknown must abstain, got %s", r.Verdict)
			}
			d := aiData(t, r)
			for _, key := range []string{"egress_consistency", "ipv6_bypass", "dns_leak", "timezone_mismatch"} {
				if d[key] != nil {
					t.Errorf("%s must be null without observations, got %v", key, d[key])
				}
			}
			for _, raw := range aiRows(t, d) {
				row := raw.(map[string]any)
				if row["available"] != nil || row["availability"] != "unknown" || row["evidence"] == "" {
					t.Errorf("unknown lost evidence or became unavailable: %+v", row)
				}
			}
		})
	}
}

func TestAIEnvMissingTraceAndPartialUnknown(t *testing.T) {
	s := &Service{Checks: &unlock.Engine{Get: aiGetter(func(_ context.Context, u string) unlock.Response {
		if strings.Contains(u, "trace") || strings.Contains(u, "grok.com") {
			return unlock.Response{Err: context.DeadlineExceeded}
		}
		return aiResponse(u)
	})}}
	r := s.AIEnv(context.Background(), false)
	if r.Verdict != "abstain" {
		t.Errorf("partial unknown must not be safe/blocked: %s", r.Verdict)
	}
	d := aiData(t, r)
	if d["egress_consistency"] != nil {
		t.Errorf("missing trace cannot prove consistency: %v", d["egress_consistency"])
	}
	for _, raw := range aiRows(t, d) {
		row := raw.(map[string]any)
		if row["service"] == "grok" && (row["available"] != nil || (row["status"] != "error" && row["status"] != "abstain") || !strings.Contains(row["evidence"].(string), "context deadline exceeded")) {
			t.Errorf("lost per-service evidence: %+v", row)
		}
	}
}

func TestAIEnvGenericDenialNotIPAttribution(t *testing.T) {
	s := &Service{Checks: &unlock.Engine{Get: aiGetter(func(_ context.Context, u string) unlock.Response {
		if u == "https://claude.ai/" {
			return unlock.Response{Status: 403, Body: "account suspended", FinalURL: u}
		}
		return aiResponse(u)
	})}}
	r := s.AIEnv(context.Background(), false)
	if r.Verdict == "blocked" || r.Verdict == "safe" {
		t.Errorf("generic HTTP denial cannot establish regional/IP ban: %s", r.Verdict)
	}
	d := aiData(t, r)
	b, _ := json.Marshal(d["fixes"])
	if strings.Contains(string(b), "switch to an egress") {
		t.Errorf("unmeasured IP-switch advice: %s", b)
	}
	for _, raw := range aiRows(t, d) {
		row := raw.(map[string]any)
		if row["service"] == "claude" && row["evidence"] == nil {
			t.Errorf("denial evidence missing: %+v", row)
		}
	}
}

func TestAIEnvDualStackRegression(t *testing.T) {
	s := &Service{Checks: &unlock.Engine{Get: aiGetter(func(_ context.Context, u string) unlock.Response {
		if strings.Contains(u, "trace") {
			ip := "192.0.2.10"
			if strings.Contains(u, "chatgpt") || strings.Contains(u, "statsig") {
				ip = "2001:db8::10"
			}
			return unlock.Response{Status: 200, FinalURL: u, Body: "ip=" + ip + "\nloc=US\n"}
		}
		return aiResponse(u)
	})}}
	d := aiData(t, s.AIEnv(context.Background(), false))
	if d["egress_consistency"] != true {
		t.Errorf("legal dual-stack addresses must not be treated as mismatched egress: %v", d["egress_consistency"])
	}
}

func TestAIEnvServiceFixOrderRegression(t *testing.T) {
	s := &Service{Checks: &unlock.Engine{Get: aiGetter(func(_ context.Context, u string) unlock.Response {
		r := aiResponse(u)
		if strings.Contains(u, "trace") {
			r.Body = "ip=192.0.2.10\nloc=US\n"
		}
		if u == "https://claude.ai/" {
			r.Body = "app-unavailable-in-region"
		}
		if strings.Contains(u, "cookie_requirements") {
			r.Body = "unsupported_country"
		}
		if strings.Contains(u, "ios.chat.openai.com") {
			r.Body = "not available in your region VPN"
		}
		return r
	})}}
	d := aiData(t, s.AIEnv(context.Background(), false))
	var services []string
	for _, raw := range d["fixes"].([]any) {
		issue := raw.(map[string]any)["issue"].(string)
		if strings.HasPrefix(issue, "claude_") {
			services = append(services, "claude")
		}
		if strings.HasPrefix(issue, "chatgpt_") {
			services = append(services, "chatgpt")
		}
	}
	if !reflect.DeepEqual(services, []string{"chatgpt", "claude"}) {
		t.Errorf("same-priority fixes must be stable, not service append order: %v", services)
	}
}

// These are documentation addresses in synthetic observations, never live probes.
func aiPositiveResults() []unlock.Result {
	var results []unlock.Result
	for _, id := range aiServices {
		results = append(results, unlock.Result{Service: id, Status: "yes", Evidence: "recognized positive marker", Region: "US", Method: "native"})
	}
	return results
}
func aiCompleteTraces() []traceHit {
	var traces []traceHit
	for _, u := range aiTraceURLs {
		traces = append(traces, traceHit{URL: u, IP: "192.0.2.10", Loc: "US", Status: "observed", Evidence: "synthetic trace"})
	}
	return traces
}
func aiFixtureService() *Service {
	return &Service{Now: func() time.Time { return time.Date(2026, 10, 24, 12, 0, 0, 0, time.FixedZone("fixture", -7*3600)) }}
}
func aiFixtureDiagnosis(s *Service, results []unlock.Result, traces []traceHit, resolvers []dnsblLike, cli *bool) Report {
	return s.aiDiagnosis(results, traces, "192.0.2.10", "2001:db8::10", "US", "US", resolvers, cli)
}

func TestAIEnvEvidenceAndVerdict(t *testing.T) {
	for _, tc := range []struct {
		name, status, evidence, want, availability string
		available                                  any
	}{
		{"positive", "yes", "recognized positive marker", "safe", "available", true},
		{"all_unknown", "abstain", "unrecognized response", "abstain", "unknown", nil},
		{"transport_error", "error", "timeout", "abstain", "unknown", nil},
		{"empty_status", "", "missing status", "abstain", "unknown", nil},
		{"future_status", "future", "new status", "abstain", "unknown", nil},
		{"no_evidence", "yes", "", "abstain", "unknown", nil},
		{"absence_not_positive", "yes", "no block marker", "abstain", "unknown", nil},
		{"web_app_fail_open", "yes", "web and app open", "abstain", "unknown", nil},
		{"redirect_not_positive", "yes", "claude.ai stayed on claude.ai", "abstain", "unknown", nil},
		{"regional_denial", "no", "explicit regional denial", "blocked", "unavailable", false},
		{"baseline_denial", "no", "redirected to app-unavailable-in-region", "blocked", "unavailable", false},
		{"pr4_chatgpt_denial", "no", "web=no app=no", "blocked", "unavailable", false},
		{"account_denial", "no", "account suspended", "risky", "unavailable", false},
		{"web_only", "web_only", "web=yes app=no", "risky", "limited", true},
		{"app_only", "app_only", "web=no app=yes", "risky", "limited", true},
		{"partial", "partial", "partial observation", "risky", "limited", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			results := aiPositiveResults()
			for i := range results {
				results[i].Status = tc.status
				results[i].Evidence = tc.evidence
			}
			r := aiFixtureDiagnosis(aiFixtureService(), results, aiCompleteTraces(), []dnsblLike{{CC: "US"}}, nil)
			if r.Verdict != tc.want {
				t.Errorf("want %s got %s", tc.want, r.Verdict)
			}
			d := aiData(t, r)
			for _, raw := range aiRows(t, d) {
				row := raw.(map[string]any)
				if row["status"] != tc.status || row["evidence"] != tc.evidence || row["region"] != "US" || row["method"] != "native" || row["available"] != tc.available || row["availability"] != tc.availability {
					t.Errorf("lost evidence or unknown: %+v", row)
				}
			}
			if tc.want == "safe" && len(d["fixes"].([]any)) != 0 {
				t.Errorf("safe with fixes: %+v", d)
			}
		})
	}
}

func TestAIEnvUnknownCannotHideOrInventKnownIssues(t *testing.T) {
	results := aiPositiveResults()
	results[0] = unlock.Result{Service: "claude", Status: "abstain", Evidence: "timeout"}
	r := aiFixtureDiagnosis(aiFixtureService(), results, aiCompleteTraces(), []dnsblLike{{CC: "US"}}, nil)
	if r.Verdict != "abstain" {
		t.Errorf("partial unknown must abstain: %s", r.Verdict)
	}
	results[1] = unlock.Result{Service: "chatgpt", Status: "no", Evidence: "explicit regional denial"}
	r = aiFixtureDiagnosis(aiFixtureService(), results, nil, nil, nil)
	if r.Verdict != "blocked" {
		t.Errorf("known regional denial must survive other unknowns: %s", r.Verdict)
	}
	d := aiData(t, r)
	if d["egress_consistency"] != nil || d["dns_leak"] != nil {
		t.Errorf("denial must not invent other observations: %+v", d)
	}
}

func TestAIEnvTraceCoverageAndDualStack(t *testing.T) {
	for _, mode := range []string{"none", "one", "partial", "all_same", "multi_egress", "dual_stack", "mapped_v4", "v6_mismatch"} {
		t.Run(mode, func(t *testing.T) {
			traces := aiCompleteTraces()
			var want any = true
			switch mode {
			case "none":
				traces = nil
				want = nil
			case "one":
				traces = traces[:1]
				want = nil
			case "partial":
				traces[4].Status = "unknown"
				want = nil
			case "multi_egress":
				traces[4].IP = "192.0.2.20"
				want = false
			case "dual_stack":
				traces[1].IP = "2001:db8::10"
				traces[3].IP = "2001:db8::10"
			case "mapped_v4":
				traces[1].IP = "::ffff:192.0.2.10"
			case "v6_mismatch":
				traces[1].IP = "2001:db8::10"
				traces[3].IP = "2001:db8::20"
				want = false
			}
			r := aiFixtureDiagnosis(aiFixtureService(), aiPositiveResults(), traces, []dnsblLike{{CC: "US"}}, nil)
			d := aiData(t, r)
			if d["egress_consistency"] != want {
				t.Errorf("want %v got %v", want, d["egress_consistency"])
			}
			if d["ipv6_bypass"] != false {
				t.Errorf("different family addresses with the same country are not bypass: %+v", d)
			}
			if (mode == "dual_stack" || mode == "mapped_v4") && r.Verdict != "safe" {
				t.Errorf("legitimate dual stack: %s", r.Verdict)
			}
		})
	}
}

func TestAIEnvTraceRejectsFailedAndInvalidObservations(t *testing.T) {
	for _, mode := range []string{"error", "http_error", "empty", "invalid_ip", "private_ip", "redirect", "valid"} {
		t.Run(mode, func(t *testing.T) {
			s := &Service{Checks: &unlock.Engine{Get: aiGetter(func(_ context.Context, u string) unlock.Response {
				r := unlock.Response{Status: 200, FinalURL: u, Body: "ip=192.0.2.10\r\nloc=US\r\n"}
				switch mode {
				case "error":
					r.Err = context.DeadlineExceeded
				case "http_error":
					r.Status = 503
				case "empty":
					r.Body = "loc=US"
				case "invalid_ip":
					r.Body = "ip=not-an-ip"
				case "private_ip":
					r.Body = "ip=127.0.0.1"
				case "redirect":
					r.FinalURL = "https://example.invalid/"
				}
				return r
			})}}
			traces := s.traces(context.Background())
			if len(traces) != 5 {
				t.Fatalf("missing target evidence: %+v", traces)
			}
			for _, trace := range traces {
				if trace.Evidence == "" || (mode != "valid" && (trace.Status != "unknown" || trace.IP != "")) || (mode == "valid" && (trace.Status != "observed" || trace.IP != "192.0.2.10")) {
					t.Errorf("bad trace evidence: %+v", trace)
				}
			}
		})
	}
}

func TestAIEnvMissingComparisonsAndTimezoneClock(t *testing.T) {
	for _, tc := range []struct {
		name, v4, v6, cc4, cc6    string
		resolvers                 []dnsblLike
		wantIPv6, wantDNS, wantTZ any
	}{
		{name: "no observations"},
		{name: "empty countries", v4: "192.0.2.10", v6: "2001:db8::10", resolvers: []dnsblLike{{CC: "US"}}},
		{name: "no IPv6", v4: "192.0.2.10", cc4: "US", resolvers: []dnsblLike{{CC: "US"}}, wantDNS: false, wantTZ: false},
		{name: "unknown resolver", v4: "192.0.2.10", cc4: "US", resolvers: []dnsblLike{{CC: "US"}, {}}, wantTZ: false},
		{name: "resolver mismatch with missing", v4: "192.0.2.10", cc4: "US", resolvers: []dnsblLike{{CC: "CN"}, {}}, wantDNS: true, wantTZ: false},
		{name: "country mismatch", v4: "192.0.2.10", v6: "2001:db8::10", cc4: "US", cc6: "CN", wantIPv6: true, wantTZ: false},
		{name: "unsupported timezone", v4: "192.0.2.10", v6: "2001:db8::10", cc4: "AU", cc6: "AU", wantIPv6: false},
		{name: "known timezone mismatch", v4: "192.0.2.10", cc4: "JP", wantTZ: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := aiFixtureService()
			r := s.aiDiagnosis(aiPositiveResults(), aiCompleteTraces(), tc.v4, tc.v6, tc.cc4, tc.cc6, tc.resolvers, nil)
			d := aiData(t, r)
			if d["ipv6_bypass"] != tc.wantIPv6 || d["dns_leak"] != tc.wantDNS || d["timezone_mismatch"] != tc.wantTZ {
				t.Errorf("wrong comparison: %+v", d)
			}
			obs := d["observations"].(map[string]any)
			for _, key := range []string{"ipv6_bypass", "dns_leak", "timezone_mismatch"} {
				o := obs[key].(map[string]any)
				if d[key] == nil && (o["status"] != "unknown" || o["reason"] == "") {
					t.Errorf("missing unknown reason: %+v", o)
				}
			}
		})
	}
	s := aiFixtureService()
	s.Now = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.FixedZone("fixture", 9*3600)) }
	r := s.aiDiagnosis(aiPositiveResults(), aiCompleteTraces(), "192.0.2.10", "2001:db8::10", "JP", "JP", []dnsblLike{{CC: "JP"}}, nil)
	if r.Verdict != "safe" {
		t.Errorf("timezone must use injected report clock, not machine clock: %+v", r)
	}
}

func TestAIEnvFixPriorityAndStableDeduplication(t *testing.T) {
	results := aiPositiveResults()
	results[0].Status = "no"
	results[0].Evidence = "explicit regional denial"
	results[1].Status = "no"
	results[1].Evidence = "explicit regional denial"
	traces := aiCompleteTraces()
	traces[4].IP = "192.0.2.20"
	cli := false
	s := aiFixtureService()
	r := s.aiDiagnosis(results, traces, "192.0.2.10", "2001:db8::10", "JP", "CN", []dnsblLike{{CC: "US"}}, &cli)
	d := aiData(t, r)
	var issues []string
	for _, raw := range d["fixes"].([]any) {
		f := raw.(map[string]any)
		issues = append(issues, f["issue"].(string))
		if f["how"] == "" {
			t.Errorf("missing actionable check: %+v", f)
		}
	}
	want := []string{"egress_mismatch", "ipv6_bypass", "chatgpt_region_denied", "claude_region_denied", "dns_leak", "timezone_mismatch", "cli_proxy_unset"}
	if !reflect.DeepEqual(issues, want) {
		t.Errorf("want %v got %v", want, issues)
	}
	for i, j := 0, len(results)-1; i < j; i, j = i+1, j-1 {
		results[i], results[j] = results[j], results[i]
	}
	again := aiData(t, s.aiDiagnosis(results, traces, "192.0.2.10", "2001:db8::10", "JP", "CN", []dnsblLike{{CC: "US"}}, &cli))
	if !reflect.DeepEqual(d["fixes"], again["fixes"]) {
		t.Error("fix order depends on service append order")
	}
	fixes := []aiFix{{20, "high", "b", "z"}, {10, "high", "a", "check"}, {20, "high", "b", "a"}, {10, "high", "a", "check"}}
	wantFixes := aiSortFixes(append([]aiFix(nil), fixes...))
	if len(wantFixes) != 2 {
		t.Fatalf("not deduplicated: %+v", wantFixes)
	}
	for i := 0; i < 20; i++ {
		first := fixes[0]
		fixes = append(fixes[1:], first)
		if !reflect.DeepEqual(aiSortFixes(append([]aiFix(nil), fixes...)), wantFixes) {
			t.Fatal("unstable fix order")
		}
	}
}

func TestAIEnvCLIEnvironmentDoesNotProvePath(t *testing.T) {
	for _, key := range []string{"HTTPS_PROXY", "https_proxy"} {
		t.Setenv(key, "")
	}
	s := &Service{}
	d := aiData(t, s.AIEnv(context.Background(), true))
	o := d["observations"].(map[string]any)["cli_proxy_configured"].(map[string]any)
	if o["value"] != false || !strings.Contains(o["reason"].(string), "does not measure") {
		t.Errorf("proxy config must not claim path equality: %+v", o)
	}
	t.Setenv("https_proxy", "http://proxy.example.invalid:8080")
	d = aiData(t, s.AIEnv(context.Background(), true))
	o = d["observations"].(map[string]any)["cli_proxy_configured"].(map[string]any)
	if o["value"] != true || d["egress_consistency"] != nil {
		t.Errorf("config cannot prove consistency: %+v", d)
	}
	d = aiData(t, s.AIEnv(context.Background(), false))
	if _, ok := d["observations"].(map[string]any)["cli_proxy_configured"]; ok {
		t.Error("unrequested CLI check should not be measured")
	}
}
