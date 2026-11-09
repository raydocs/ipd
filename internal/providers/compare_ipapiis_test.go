package providers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
)

func TestComparisonIPAPIIS(t *testing.T) {
	good := `{"ip":"1.1.1.1","location":{"country_code":"US"},"asn":{"asn":64512},"is_proxy":false,"is_vpn":true,"is_tor":null,"company":{"name":"SYNTHETIC_ONLY"},"error_echo":"SYNTHETIC_KEY"}`
	for _, tc := range []struct{ name, body, status string }{
		{"typed", good, "ok"},
		{"false_observation", `{"ip":"1.1.1.1","is_proxy":false}`, "ok"},
		{"missing", `{"ip":"1.1.1.1"}`, "unknown"},
		{"nulls", `{"ip":"1.1.1.1","is_proxy":null,"is_vpn":null,"is_tor":null,"location":null,"asn":null}`, "unknown"},
		{"wrong_identity", strings.Replace(good, "1.1.1.1", "8.8.8.8", 1), "error"},
		{"zone", strings.Replace(good, "1.1.1.1", "::ffff:1.1.1.1%secret", 1), "error"},
		{"mapped", strings.Replace(good, "1.1.1.1", "::ffff:1.1.1.1", 1), "ok"},
		{"anonymous", `{"ip":"1.1.1.1","docs":"SYNTHETIC_KEY","asn":"AS64512","country":"SYNTHETIC_ONLY"}`, "error"},
		{"error", `{"ip":"1.1.1.1","error":"SYNTHETIC_KEY","error_code":"ERR_QUOTA_EXCEEDED","is_proxy":false}`, "error"},
		{"string_bool", `{"ip":"1.1.1.1","is_proxy":"false"}`, "error"},
		{"truthy_vpn", `{"ip":"1.1.1.1","is_vpn":{"service":"SYNTHETIC_ONLY"}}`, "error"},
		{"country_type", `{"ip":"1.1.1.1","location":{"country_code":7}}`, "error"},
		{"country_case", `{"ip":"1.1.1.1","location":{"country_code":"us"}}`, "error"},
		{"location_type", `{"ip":"1.1.1.1","location":[]}`, "error"},
		{"asn_type", `{"ip":"1.1.1.1","asn":{"asn":"64512"}}`, "error"},
		{"asn_fraction", `{"ip":"1.1.1.1","asn":{"asn":12.5}}`, "error"},
		{"asn_range", `{"ip":"1.1.1.1","asn":{"asn":4294967296}}`, "error"},
		{"null", "null", "error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: comparisonTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != "GET" || r.URL.Scheme != "https" || r.URL.Host != "api.ipapi.is" || r.URL.Path != "/" || r.URL.Query().Get("q") != "1.1.1.1" || r.URL.Query().Get("key") != "SYNTHETIC_KEY" {
					t.Fatalf("unexpected fixed endpoint/request")
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})}
			rows := CompareOnline(context.Background(), netip.MustParseAddr("1.1.1.1"), map[string]string{"ipapiis": "SYNTHETIC_KEY"}, true, false, client)
			for _, row := range rows {
				if row.ID != "ipapiis" {
					continue
				}
				if row.Status != tc.status || calls != 1 {
					t.Fatalf("row=%+v calls=%d", row, calls)
				}
				b, _ := json.Marshal(row)
				if strings.Contains(string(b), "SYNTHETIC") {
					t.Fatalf("raw/provider text leaked: %s", b)
				}
				if row.Score != nil || row.ScoreMeaning != "" {
					t.Fatal("invented combined score")
				}
				if tc.status == "error" && len(row.Fields) != 0 {
					t.Fatal("partial facts survived failed schema")
				}
				if tc.name == "typed" && (len(row.Fields) != 4 || row.Fields["vpn"] != true || row.Fields["proxy"] != false || row.Fields["country"] != "US" || row.Fields["asn"] != uint32(64512)) {
					t.Fatalf("%+v", row)
				}
				if tc.status == "unknown" && (row.Skipped != "no_comparable_observation" || len(row.Fields) != 0 || row.Confidence != "unknown") {
					t.Fatal(row)
				}
			}
		})
	}
}

func TestComparisonIPAPIISGates(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: comparisonTransport(func(*http.Request) (*http.Response, error) { calls++; return nil, context.Canceled })}
	for _, tc := range []struct {
		live, offline bool
		keys          map[string]string
		reason        string
	}{
		{false, false, map[string]string{"ipapiis": "SYNTHETIC_KEY"}, "live_opt_in_required"},
		{true, true, map[string]string{"ipapiis": "SYNTHETIC_KEY"}, "offline"},
		{true, false, nil, "missing_key"},
	} {
		for _, row := range CompareOnline(context.Background(), netip.MustParseAddr("1.1.1.1"), tc.keys, tc.live, tc.offline, client) {
			if row.ID == "ipapiis" && (row.Skipped != tc.reason || row.Timestamp != nil) {
				t.Fatal(row)
			}
		}
	}
	if calls != 0 {
		t.Fatal("gate sent request")
	}
}

func TestComparisonIPAPIISRequestFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		body string
		fail bool
	}{
		{"quota", 429, "SYNTHETIC_KEY", false},
		{"forbidden", 403, "SYNTHETIC_KEY", false},
		{"server", 503, "SYNTHETIC_KEY", false},
		{"redirect", 302, "SYNTHETIC_KEY", false},
		{"oversize", 200, strings.Repeat(" ", (1<<20)+1), false},
		{"malformed", 200, "{SYNTHETIC_KEY", false},
		{"transport", 200, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: comparisonTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if _, ok := r.Context().Deadline(); !ok {
					t.Error("missing provider deadline")
				}
				if tc.fail {
					return nil, context.DeadlineExceeded
				}
				return &http.Response{StatusCode: tc.code, Header: http.Header{"Location": {"https://untrusted.invalid/SYNTHETIC_KEY"}}, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})}
			for _, row := range CompareOnline(context.Background(), netip.MustParseAddr("1.1.1.1"), map[string]string{"ipapiis": "SYNTHETIC_KEY"}, true, false, client) {
				if row.ID == "ipapiis" && (row.Status != "error" || row.Error != "provider_request_failed" || len(row.Fields) != 0 || row.Score != nil) {
					t.Fatal(row)
				}
			}
			if calls != 1 {
				t.Fatalf("calls=%d", calls)
			}
		})
	}
}

func TestComparisonIPAPIISIPv6AndDifferences(t *testing.T) {
	ip := netip.MustParseAddr("2001:4860:4860::8888")
	row := normalizeComparison(Comparison{ID: "ipapiis", Fields: map[string]any{}}, map[string]any{"ip": "2001:4860:4860:0:0:0:0:8888", "is_proxy": false}, ip)
	if row.Status != "ok" {
		t.Fatal(row)
	}
	differences := Differences([]Comparison{row, {ID: "other", Status: "ok", Fields: map[string]any{"proxy": true}}, {ID: "missing", Status: "unknown", Fields: map[string]any{}}})
	if len(differences) != 1 || len(differences["proxy"]) != 2 {
		t.Fatal(differences)
	}
}
