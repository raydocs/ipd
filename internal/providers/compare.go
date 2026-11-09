package providers

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"time"

	"ipd/internal/privacy"
)

// Comparison never exports payloads, arbitrary provider text, or a combined score.
type Comparison struct {
	ID           string         `json:"id"`
	Status       string         `json:"status"`
	Skipped      string         `json:"skipped"`
	Error        string         `json:"error"`
	Timestamp    *time.Time     `json:"timestamp"`
	Scope        string         `json:"scope"`
	Licensing    string         `json:"licensing"`
	Confidence   string         `json:"confidence"`
	Version      string         `json:"version,omitempty"`
	Attribution  string         `json:"attribution"`
	Fields       map[string]any `json:"fields"`
	Score        *int           `json:"score,omitempty"`
	ScoreMeaning string         `json:"score_meaning,omitempty"`
}

// CompareOnline normalizes only explicitly supported schemas.
// Other adapters remain present in All; do not pretend their raw data is normalized.
// Fixed official endpoints ignore configurable legacy bases to prevent credential forwarding.
func CompareOnline(ctx context.Context, ip netip.Addr, keys map[string]string, live, offline bool, client *http.Client) []Comparison {
	out := make([]Comparison, 0, 5)
	bases := map[string]string{"ipqs": "https://ipqualityscore.com/api/json/ip", "abuseipdb": "https://api.abuseipdb.com/api/v2/check", "ipapiis": "https://api.ipapi.is/", "proxycheck": "https://proxycheck.io/v3"}
	for _, p := range All(keys, bases, client) {
		if p.ID() != "scamalytics" && p.ID() != "ipqs" && p.ID() != "ipapiis" && p.ID() != "proxycheck" && p.ID() != "abuseipdb" {
			continue
		}
		row := Comparison{ID: p.ID(), Status: "skipped", Scope: "online IP lookup", Licensing: p.License(), Attribution: p.Attribution(), Confidence: "unknown", Fields: map[string]any{}}
		switch {
		case !privacy.IsPublic(ip):
			row.Skipped = "public_ip_required"
		case offline:
			row.Skipped = "offline"
		case !live:
			row.Skipped = "live_opt_in_required"
		case !p.Enabled():
			row.Skipped = "missing_key"
		case bases[p.ID()] == "":
			row.Skipped = "schema_adapter_pending"
		default:
			at := time.Now().UTC()
			row.Timestamp = &at
			bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
			raw, err := p.Lookup(bounded, ip)
			cancel()
			if err != nil {
				row.Status = "error"
				row.Error = "provider_request_failed"
			} else {
				row = normalizeComparison(row, raw, ip)
			}
		}
		out = append(out, row)
	}
	return out
}

func normalizeComparison(row Comparison, raw map[string]any, ip netip.Addr) Comparison {
	if row.ID == "proxycheck" {
		return normalizeProxycheck(row, raw, ip)
	}
	if row.ID == "ipapiis" {
		return normalizeIPAPIIS(row, raw, ip)
	}
	fail := func() Comparison {
		row.Status = "error"
		row.Error = "invalid_provider_response"
		row.Fields = map[string]any{}
		row.Score = nil
		return row
	}
	var data map[string]any
	var scoreKey, ccKey string
	switch row.ID {
	case "ipqs":
		if ok, _ := raw["success"].(bool); !ok {
			return fail()
		}
		data = raw
		scoreKey = "fraud_score"
		ccKey = "country_code"
		row.ScoreMeaning = "IPQS fraud propensity (0-100); not abuse-report confidence"
	case "abuseipdb":
		data, _ = raw["data"].(map[string]any)
		returnedIP, _ := data["ipAddress"].(string)
		parsedIP, parseErr := netip.ParseAddr(returnedIP)
		if data == nil || parseErr != nil || parsedIP.Zone() != "" || parsedIP.Unmap() != ip.Unmap() {
			return fail()
		}
		scoreKey = "abuseConfidenceScore"
		ccKey = "countryCode"
		row.ScoreMeaning = "AbuseIPDB confidence of abuse (0-100); report-based, not fraud propensity"
	default:
		return fail()
	}
	n, ok := data[scoreKey].(float64)
	if !ok || n < 0 || n > 100 || n != float64(int(n)) {
		return fail()
	}
	// Only closed-value fields leave the adapter. Unknown and null stay absent.
	if cc, exists := data[ccKey]; exists && cc != nil {
		s, ok := cc.(string)
		if !ok || len(s) != 2 || s[0] < 'A' || s[0] > 'Z' || s[1] < 'A' || s[1] > 'Z' {
			return fail()
		}
		row.Fields["country"] = s
	}
	if row.ID == "ipqs" {
		for _, k := range []string{"proxy", "vpn", "tor"} {
			if v, exists := data[k]; exists && v != nil {
				b, ok := v.(bool)
				if !ok {
					return fail()
				}
				row.Fields[k] = b
			}
		}
		if v, exists := data["ASN"]; exists && v != nil {
			a, ok := v.(float64)
			if !ok || a <= 0 || a > 4294967295 || a != float64(uint32(a)) {
				return fail()
			}
			row.Fields["asn"] = uint32(a)
		}
	}
	i := int(n)
	row.Score = &i
	row.Status = "ok"
	row.Confidence = "provider_assertion_not_calibrated"
	return row
}

// Differences compares only explicit comparable observations, never scores or missing sources.
func Differences(rows []Comparison) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, field := range []string{"country", "asn", "proxy", "vpn", "tor"} {
		values := map[string]any{}
		unique := map[string]bool{}
		for _, r := range rows {
			if r.Status != "ok" {
				continue
			}
			if v, ok := r.Fields[field]; ok {
				values[r.ID] = v
				unique[fmt.Sprint(v)] = true
			}
		}
		if len(unique) > 1 {
			out[field] = values
		}
	}
	return out
}
