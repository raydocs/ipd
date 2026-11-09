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

func TestComparisonProxycheckV3(t *testing.T) {
	good := `{"status":"ok","1.1.1.1":{"risk":50,"network":{"asn":"AS64512"},"location":{"isocode":"ZZ"},"detections":{"proxy":false,"vpn":true,"tor":null},"operator":{"name":"SYNTHETIC_SECRET"}}}`
	for _, tc := range []struct{ name, body, status string }{
		{"typed", good, "ok"},
		{"warning", strings.Replace(good, `"status":"ok"`, `"status":"warning","message":"SYNTHETIC_SECRET"`, 1), "ok"},
		{"empty", `{"status":"ok","1.1.1.1":{"detections":{}}}`, "unknown"},
		{"null_facts", `{"status":"ok","1.1.1.1":{"risk":null,"network":null,"location":null,"detections":{"proxy":null,"vpn":null,"tor":null}}}`, "unknown"},
		{"false", `{"status":"ok","1.1.1.1":{"detections":{"proxy":false}}}`, "ok"},
		{"different_ip", strings.Replace(good, "1.1.1.1", "8.8.8.8", 1), "error"},
		{"zone", strings.Replace(good, "1.1.1.1", "::ffff:1.1.1.1%secret", 1), "error"},
		{"mapped", strings.Replace(good, "1.1.1.1", "::ffff:1.1.1.1", 1), "ok"},
		{"extra_ip", strings.Replace(good, `"status":"ok"`, `"status":"ok","8.8.8.8":{}`, 1), "error"},
		{"duplicate_identity", strings.Replace(good, `"status":"ok"`, `"status":"ok","::ffff:1.1.1.1":{}`, 1), "error"},
		{"status_error", strings.Replace(good, `"status":"ok"`, `"status":"error"`, 1), "error"},
		{"status_denied", strings.Replace(good, `"status":"ok"`, `"status":"denied"`, 1), "error"},
		{"status_missing", `{"1.1.1.1":{"detections":{"proxy":false}}}`, "error"},
		{"v2", `{"status":"ok","1.1.1.1":{"proxy":"yes","type":"VPN","risk":50}}`, "error"},
		{"string_bool", `{"status":"ok","1.1.1.1":{"detections":{"proxy":"no"}}}`, "error"},
		{"risk_type", strings.Replace(good, `"risk":50`, `"risk":"50"`, 1), "error"},
		{"risk_range", strings.Replace(good, `"risk":50`, `"risk":101`, 1), "error"},
		{"risk_fraction", strings.Replace(good, `"risk":50`, `"risk":50.5`, 1), "error"},
		{"country_bad", strings.Replace(good, `"isocode":"ZZ"`, `"isocode":"SYNTHETIC_SECRET"`, 1), "error"},
		{"asn_bad", strings.Replace(good, `"asn":"AS64512"`, `"asn":"AS-1"`, 1), "error"},
		{"asn_overflow", strings.Replace(good, `"asn":"AS64512"`, `"asn":"AS4294967296"`, 1), "error"},
		{"null", "null", "error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: comparisonTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != "GET" || r.URL.Scheme != "https" || r.URL.Host != "proxycheck.io" || r.URL.Path != "/v3/1.1.1.1" || r.URL.Query().Get("key") != "SYNTHETIC_SECRET" {
					t.Fatal("wrong fixed request")
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})}
			for _, row := range CompareOnline(context.Background(), netip.MustParseAddr("1.1.1.1"), map[string]string{"proxycheck": "SYNTHETIC_SECRET"}, true, false, client) {
				if row.ID != "proxycheck" {
					continue
				}
				if calls != 1 || row.Status != tc.status {
					t.Fatalf("calls=%d row=%+v", calls, row)
				}
				b, _ := json.Marshal(row)
				if strings.Contains(string(b), "SYNTHETIC_SECRET") {
					t.Fatalf("raw leak %s", b)
				}
				if tc.status == "error" && (len(row.Fields) != 0 || row.Score != nil) {
					t.Fatal("partial invalid evidence")
				}
				if tc.name == "typed" && (len(row.Fields) != 4 || row.Fields["proxy"] != false || row.Fields["vpn"] != true || row.Fields["country"] != "ZZ" || row.Fields["asn"] != uint32(64512) || row.Score == nil || *row.Score != 50) {
					t.Fatal(row)
				}
				if tc.name == "warning" && row.Error != "provider_warning" {
					t.Fatal("warning silently lost")
				}
				if tc.status == "unknown" && (row.Skipped != "no_comparable_observation" || row.Score != nil) {
					t.Fatal(row)
				}
			}
		})
	}
}
func TestComparisonProxycheckGates(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: comparisonTransport(func(*http.Request) (*http.Response, error) { calls++; return nil, context.Canceled })}
	for _, tc := range []struct {
		live, offline bool
		keys          map[string]string
		reason        string
	}{
		{false, false, map[string]string{"proxycheck": "SYNTHETIC_SECRET"}, "live_opt_in_required"},
		{true, true, map[string]string{"proxycheck": "SYNTHETIC_SECRET"}, "offline"},
		{true, false, nil, "missing_key"},
	} {
		for _, row := range CompareOnline(context.Background(), netip.MustParseAddr("1.1.1.1"), tc.keys, tc.live, tc.offline, client) {
			if row.ID == "proxycheck" && (row.Skipped != tc.reason || row.Timestamp != nil) {
				t.Fatal(row)
			}
		}
	}
	if calls != 0 {
		t.Fatal("gates issued calls")
	}
}

func TestComparisonProxycheckFailuresAndIdentity(t *testing.T) {
	for _, code := range []int{302, 403, 429, 503} {
		calls := 0
		client := &http.Client{Transport: comparisonTransport(func(r *http.Request) (*http.Response, error) {
			calls++
			if _, ok := r.Context().Deadline(); !ok {
				t.Error("unbounded request")
			}
			return &http.Response{StatusCode: code, Header: http.Header{"Location": {"https://untrusted.invalid/SYNTHETIC_SECRET"}}, Body: io.NopCloser(strings.NewReader("SYNTHETIC_SECRET"))}, nil
		})}
		for _, row := range CompareOnline(context.Background(), netip.MustParseAddr("1.1.1.1"), map[string]string{"proxycheck": "SYNTHETIC_SECRET"}, true, false, client) {
			if row.ID == "proxycheck" && (row.Status != "error" || row.Error != "provider_request_failed" || row.Score != nil || len(row.Fields) != 0) {
				t.Fatal(row)
			}
		}
		if calls != 1 {
			t.Fatal("redirect/retry unexpectedly followed")
		}
	}
	ip := netip.MustParseAddr("2001:4860:4860::8888")
	row := normalizeComparison(Comparison{ID: "proxycheck", Fields: map[string]any{}}, map[string]any{"status": "ok", "2001:4860:4860:0:0:0:0:8888": map[string]any{"detections": map[string]any{"proxy": false}}}, ip)
	if row.Status != "ok" {
		t.Fatal(row)
	}
	differences := Differences([]Comparison{row, {ID: "other", Status: "ok", Fields: map[string]any{"proxy": true}}})
	if len(differences["proxy"]) != 2 {
		t.Fatal(differences)
	}
}

func TestComparisonProxycheckOpaqueKey(t *testing.T) {
	key := "SYNTHETIC&next=bad ?value"
	client := &http.Client{Transport: comparisonTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("key") != key || r.URL.Query().Get("next") != "" {
			t.Fatal("key changed query structure")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"status":"ok","1.1.1.1":{"detections":{"proxy":false}}}`))}, nil
	})}
	for _, row := range CompareOnline(context.Background(), netip.MustParseAddr("1.1.1.1"), map[string]string{"proxycheck": key}, true, false, client) {
		if row.ID == "proxycheck" && row.Status != "ok" {
			t.Fatal(row)
		}
	}
}
