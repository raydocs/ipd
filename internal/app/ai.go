package app

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"ipd/internal/unlock"
)

var aiServices = []string{"claude", "chatgpt", "gemini", "grok", "copilot", "meta_ai", "perplexity"}
var aiTraceURLs = []string{
	"https://claude.ai/cdn-cgi/trace",
	"https://chatgpt.com/cdn-cgi/trace",
	"https://api.anthropic.com/cdn-cgi/trace",
	"https://statsigapi.net/cdn-cgi/trace",
	"https://browser.sentry.io/cdn-cgi/trace",
}

// aiObservation reports only a measured comparison, not proof of a leak or ban.
// Value is nil for unknown, including unsupported comparisons.
type aiObservation struct {
	Value  *bool  `json:"value"`
	Status string `json:"status"`
	Reason string `json:"reason"`
}

func aiUnknown(reason string) aiObservation { return aiObservation{Status: "unknown", Reason: reason} }
func aiObserved(value bool, reason string) aiObservation {
	return aiObservation{Value: &value, Status: "observed", Reason: reason}
}

type aiFix struct {
	Priority int    `json:"priority"`
	Severity string `json:"severity"`
	Issue    string `json:"issue"`
	How      string `json:"how"`
}

func aiSortFixes(fixes []aiFix) []aiFix {
	sort.Slice(fixes, func(i, j int) bool {
		a, b := fixes[i], fixes[j]
		if a.Priority != b.Priority {
			return a.Priority < b.Priority
		}
		if a.Issue != b.Issue {
			return a.Issue < b.Issue
		}
		if a.How != b.How {
			return a.How < b.How
		}
		return a.Severity < b.Severity
	})
	out := make([]aiFix, 0, len(fixes))
	seen := map[string]bool{}
	for _, f := range fixes {
		if !seen[f.Issue] {
			out = append(out, f)
			seen[f.Issue] = true
		}
	}
	return out
}

// aiEnv diagnoses the current probe process. Unknown observations never imply
// safety, service denial, an IP ban, or a confirmed DNS/IPv6 leak.
func (s *Service) aiEnv(ctx context.Context, includeCLI bool) Report {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	var results []unlock.Result
	if s.Checks != nil && s.Checks.Get != nil {
		results = s.Checks.Check(ctx, aiServices)
	}
	traces := s.traces(ctx)
	v4, v6 := "", ""
	if s.Egress != nil {
		v4, v6 = s.Egress(ctx)
	}
	cc4, cc6 := s.lookupCC(v4), s.lookupCC(v6)
	var resolvers []dnsblLike
	if s.DNS != nil {
		resolvers = s.DNS.Resolvers(ctx)
	}
	var cli *bool
	if includeCLI {
		configured := os.Getenv("HTTPS_PROXY") != "" || os.Getenv("https_proxy") != ""
		cli = &configured
	}
	return s.aiDiagnosis(results, traces, v4, v6, cc4, cc6, resolvers, cli)
}

func (s *Service) aiDiagnosis(results []unlock.Result, traces []traceHit, v4, v6, cc4, cc6 string, resolvers []dnsblLike, cli *bool) Report {
	byService := map[string]unlock.Result{}
	for _, r := range results {
		byService[r.Service] = r
	}
	per := []map[string]any{}
	fixes := []aiFix{}
	blocked, risky, unknown := false, false, false
	for _, id := range aiServices {
		r, ok := byService[id]
		if !ok {
			r = unlock.Result{Service: id, Status: "abstain", Evidence: "service observation missing; configure the check client and retry"}
		}
		availability, available := aiAvailability(r)
		if available == nil {
			unknown = true
			fixes = append(fixes, aiFix{50, "info", "service_observation_missing", "Check connectivity, timeout and proxy settings; rerun ipd ai --json and inspect per_service.status/evidence before diagnosing denial."})
		}
		if availability == "limited" {
			risky = true
			fixes = append(fixes, aiFix{40, "medium", id + "_limited", "Retry the required web/app surface separately; partial access is not full service availability or an account diagnosis."})
		}
		if availability == "unavailable" {
			risky = true
			if aiRegionalDenial(r) {
				blocked = true
				fixes = append(fixes, aiFix{20, "high", id + "_region_denied", "After checking egress and proxy-path consistency, verify the service's supported regions and the explicit region-denial evidence; retry the same request. Do not infer an account ban or blindly replace the IP."})
			} else {
				fixes = append(fixes, aiFix{40, "medium", id + "_access_denied", "Inspect the service HTTP/error evidence and retry; distinguish authentication, account restrictions, rate limits and network failures. An access denial alone does not identify an IP or region cause; use official account support if needed."})
			}
		}
		seen := ""
		host := ""
		if id == "claude" {
			host = "claude.ai"
		}
		if id == "chatgpt" {
			host = "chatgpt.com"
		}
		for _, t := range traces {
			u, _ := url.Parse(t.URL)
			if u != nil && u.Hostname() == host && t.Status == "observed" {
				seen = t.IP
			}
		}
		per = append(per, map[string]any{"service": id, "status": r.Status, "evidence": r.Evidence, "method": r.Method, "region": r.Region, "available": aiBoolValue(available), "availability": availability, "known": available != nil, "assessment_reason": aiAssessmentReason(availability), "seen_ip": seen})
	}
	consistency := aiTraceConsistency(traces)
	ipv6 := aiUnknown("both valid IPv4/IPv6 egress addresses and countries are needed; no IPv6 observation does not prove IPv6 is disabled")
	if a, ok := aiPublicIP(v4); ok && a.Is4() {
		if b, ok := aiPublicIP(v6); ok && b.Is6() && cc4 != "" && cc6 != "" {
			ipv6 = aiObserved(cc4 != cc6, "compares IPv4/IPv6 egress countries only; a mismatch suggests a path check, not proof of bypass")
		}
	}
	dns := aiUnknown("resolver countries and a known egress country are needed; missing resolvers do not prove no DNS leak")
	if cc4 != "" && len(resolvers) > 0 {
		complete, mismatch := true, false
		for _, r := range resolvers {
			if r.CC == "" {
				complete = false
			} else if r.CC != cc4 {
				mismatch = true
			}
		}
		if mismatch || complete {
			dns = aiObserved(mismatch, "compares resolver country with IPv4 egress country; geography alone does not prove a DNS leak")
		}
	}
	tz := timezoneIssue(cc4, s.now())
	observations := map[string]aiObservation{"egress_consistency": consistency, "ipv6_bypass": ipv6, "dns_leak": dns, "timezone_mismatch": tz}
	if consistency.Value == nil {
		fixes = append(fixes, aiFix{12, "info", "egress_observation_missing", "Retry the five /cdn-cgi/trace URLs in traces through the same proxy; check HTTP status and valid ip= lines. Compare multiple domains within each address family; missing traces cannot establish a common path."})
	} else if !*consistency.Value {
		fixes = append(fixes, aiFix{10, "high", "egress_mismatch", "Repeat the trace requests and inspect proxy rules for AI/API/telemetry domains within each address family. Confirm the intended path before changing routing; multiple observed egress addresses do not establish an account ban."})
	}
	if ipv6.Value == nil {
		fixes = append(fixes, aiFix{11, "info", "ipv6_observation_missing", "Measure IPv4 and IPv6 egress separately (curl -4 and curl -6 to a trace URL through the intended proxy); verify whether IPv6 is enabled and repeat AIEnv with both observations. Different IPv4/IPv6 addresses are normal dual-stack behavior."})
	} else if *ipv6.Value {
		fixes = append(fixes, aiFix{11, "high", "ipv6_bypass", "Repeat curl -4/-6 trace checks and compare countries and proxy rules. If an unintended direct IPv6 path is confirmed, route IPv6 through the intended proxy or disable that path, then retest; country disagreement alone is not proof of bypass."})
	}
	if dns.Value == nil {
		fixes = append(fixes, aiFix{30, "info", "dns_observation_missing", "Collect resolver observations using ipd leak --json and compare their countries with the measured egress; then retry. No resolver observations means unknown, not no leak."})
	} else if *dns.Value {
		fixes = append(fixes, aiFix{30, "medium", "dns_leak", "Inspect ipd leak --json resolver evidence and the proxy DNS configuration. Verify the intended DNS path before changing resolvers, then retry; a country mismatch alone is not proof of leakage."})
	}
	if tz.Value == nil {
		fixes = append(fixes, aiFix{31, "info", "timezone_observation_missing", "Check date +%z and the measured egress country; unsupported country/timezone comparisons remain unknown. A timezone difference is not a service-ban diagnosis."})
	} else if *tz.Value {
		fixes = append(fixes, aiFix{31, "medium", "timezone_mismatch", "Check date +%z, the system timezone and the intended egress country. If consistency is intended, correct the timezone and retry; timezone changes cannot promise account access."})
	}
	if cli != nil {
		observations["cli_proxy_configured"] = aiObserved(*cli, "HTTPS_PROXY/https_proxy presence only; this does not measure browser/CLI path equality")
		if !*cli {
			risky = true
			fixes = append(fixes, aiFix{32, "medium", "cli_proxy_unset", "Inspect HTTPS_PROXY/https_proxy and the CLI's proxy/NO_PROXY settings; configure the intended proxy if required, then compare CLI and browser trace requests. An unset variable may be legitimate direct access."})
		}
	}
	for key, o := range observations {
		if o.Value == nil {
			unknown = true
			continue
		}
		if key == "egress_consistency" {
			risky = risky || !*o.Value
		} else if key != "cli_proxy_configured" {
			risky = risky || *o.Value
		}
	}
	verdict := "safe"
	if blocked {
		verdict = "blocked"
	} else if risky {
		verdict = "risky"
	} else if unknown {
		verdict = "abstain"
	}
	fixes = aiSortFixes(fixes)
	summary := "AI environment " + verdict + "; probe-process observations only, not an account/IP-ban diagnosis"
	if len(fixes) > 0 {
		summary += "; next: " + fixes[0].Issue + " — " + fixes[0].How
	}
	data := map[string]any{"verdict": verdict, "fixes": fixes, "per_service": per, "observations": observations, "traces": traces, "schema_version": "ai-diagnosis-v1", "scope": "current probe process; no account-status or browser/CLI path measurement"}
	for _, key := range []string{"egress_consistency", "ipv6_bypass", "dns_leak", "timezone_mismatch"} {
		data[key] = aiBoolValue(observations[key].Value)
	}
	return Report{Verdict: verdict, Summary: summary, Data: data, Sources: []Source{{ID: "unlock"}, {ID: "trace"}}, CachedAt: s.now()}
}

func aiBoolValue(value *bool) any {
	if value == nil {
		return nil
	}
	return *value
}

func aiAvailability(r unlock.Result) (string, *bool) {
	value := true
	if strings.TrimSpace(r.Evidence) == "" {
		return "unknown", nil
	}
	switch r.Status {
	case unlock.Yes:
		// Fail-open evidence (for example "no block marker") cannot vote positive.
		// Accept recognized marker evidence from the baseline and PR4 engines.
		switch r.Evidence {
		case "recognized positive marker", "positive marker", "gemini page available", "web=yes app=yes":
		default:
			return "unknown", nil
		}
		return "available", &value
	case unlock.WebOnly, unlock.AppOnly, unlock.Partial:
		return "limited", &value
	case unlock.No:
		value = false
		return "unavailable", &value
	default: // Includes PR4's literal "abstain" without depending on its symbol.
		return "unknown", nil
	}
}
func aiAssessmentReason(availability string) string {
	if availability == "unknown" {
		return "no conclusive availability evidence; raw status/evidence retained"
	}
	return "availability of the probed surface only; not account status or IP reputation"
}

func aiRegionalDenial(r unlock.Result) bool {
	if r.Status != unlock.No {
		return false
	}
	e := strings.ToLower(r.Evidence)
	for _, marker := range []string{"app-unavailable-in-region", "unsupported_country", "not available in your region", "unsupported region", "unavailable in your region", "abrageoblockederrorroot", "explicit regional denial", "web=no app=no"} {
		if strings.Contains(e, marker) {
			return true
		}
	}
	return false
}

type traceHit struct {
	URL      string `json:"url"`
	IP       string `json:"ip"`
	Loc      string `json:"loc"`
	Status   string `json:"status"`
	Evidence string `json:"evidence"`
}

func (s *Service) traces(ctx context.Context) []traceHit {
	out := make([]traceHit, 0, len(aiTraceURLs))
	for _, u := range aiTraceURLs {
		t := traceHit{URL: u, Status: "unknown", Evidence: "trace client missing"}
		if s.Checks != nil && s.Checks.Get != nil {
			r := s.Checks.Get.Get(ctx, u, nil)
			switch {
			case r.Err != nil:
				t.Evidence = r.Err.Error()
			case r.Status < 200 || r.Status >= 300:
				t.Evidence = fmt.Sprintf("trace HTTP %d; not a successful observation", r.Status)
			case r.FinalURL != u:
				t.Evidence = "trace final URL missing or redirected away from the target"
			default:
				for _, line := range strings.Split(r.Body, "\n") {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "ip=") {
						t.IP = strings.TrimSpace(strings.TrimPrefix(line, "ip="))
					}
					if strings.HasPrefix(line, "loc=") {
						t.Loc = strings.TrimSpace(strings.TrimPrefix(line, "loc="))
					}
				}
				if ip, ok := aiPublicIP(t.IP); ok {
					t.IP = ip.String()
					t.Status = "observed"
					t.Evidence = "successful HTTP trace with a public ip= address"
				} else {
					t.IP = ""
					t.Evidence = "trace has no valid public ip= address"
				}
			}
		}
		out = append(out, t)
	}
	return out
}
func aiPublicIP(raw string) (netip.Addr, bool) {
	ip, err := netip.ParseAddr(raw)
	ip = ip.Unmap()
	return ip, err == nil && ip.Zone() == "" && ip.IsGlobalUnicast() && !ip.IsPrivate()
}
func aiTraceConsistency(traces []traceHit) aiObservation {
	ips := map[bool]map[netip.Addr]bool{true: {}, false: {}}
	seen := map[string]bool{}
	for _, t := range traces {
		if t.Status != "observed" {
			continue
		}
		ip, ok := aiPublicIP(t.IP)
		if !ok {
			continue
		}
		ips[ip.Is4()][ip] = true
		seen[t.URL] = true
	}
	if len(ips[true]) > 1 || len(ips[false]) > 1 {
		return aiObserved(false, "multiple egress addresses observed within the same address family; repeat to distinguish split paths from rotation")
	}
	for _, u := range aiTraceURLs {
		if !seen[u] {
			return aiUnknown("trace coverage incomplete; no consistency claim from missing or failed observations")
		}
	}
	return aiObserved(true, "all five trace targets observed; addresses agree within each family only, not proof of identical routes or browser/CLI paths")
}
func (s *Service) lookupCC(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil || s.Look == nil {
		return ""
	}
	return s.Look.Lookup(addr).CC
}
func timezoneIssue(cc string, at time.Time) aiObservation {
	_, offset := at.Zone()
	min, max := 0, 0
	switch cc {
	case "CN", "HK", "SG":
		min, max = 8*3600, 8*3600
	case "JP":
		min, max = 9*3600, 9*3600
	case "US":
		min, max = -10*3600, -4*3600
	case "GB":
		min, max = 0, 3600
	case "DE":
		min, max = 3600, 2*3600
	default:
		return aiUnknown("egress country missing or timezone comparison unsupported")
	}
	return aiObserved(offset < min || offset > max, "coarse country/UTC-offset comparison at the report clock; not a service requirement or proof of user location")
}
