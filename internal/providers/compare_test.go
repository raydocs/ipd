package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type comparisonTransport func(*http.Request) (*http.Response, error)

func (f comparisonTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestComparisonOptIn(t *testing.T) {
	var calls atomic.Int32
	client := &http.Client{Transport: comparisonTransport(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		t.Error("unexpected network")
		return nil, context.Canceled
	})}
	for _, tc := range []struct {
		live, offline bool
		keys          map[string]string
		reason        string
	}{
		{false, false, map[string]string{"ipqs": "secret"}, "live_opt_in_required"},
		{true, true, map[string]string{"ipqs": "secret"}, "offline"},
		{true, false, nil, "missing_key"},
	} {
		rows := CompareOnline(context.Background(), netip.MustParseAddr("1.1.1.1"), tc.keys, tc.live, tc.offline, client)
		if len(rows) != 5 {
			t.Fatal(rows)
		}
		for _, r := range rows {
			if r.Status != "skipped" || r.Skipped != tc.reason || r.Timestamp != nil {
				t.Fatal(r)
			}
		}
	}
	rows := CompareOnline(context.Background(), netip.MustParseAddr("127.0.0.1"), map[string]string{"ipqs": "secret"}, true, false, client)
	if rows[1].Skipped != "public_ip_required" || calls.Load() != 0 {
		t.Fatal(rows, calls.Load())
	}
}

func TestComparisonPendingAdaptersNeverCall(t *testing.T) {
	client := &http.Client{Transport: comparisonTransport(func(r *http.Request) (*http.Response, error) {
		t.Fatal("pending adapter called")
		return nil, context.Canceled
	})}
	rows := CompareOnline(context.Background(), netip.MustParseAddr("1.1.1.1"), map[string]string{"scamalytics": "secret", "proxycheck": "secret"}, true, false, client)
	for _, r := range rows {
		if (r.ID == "scamalytics" || r.ID == "proxycheck") && r.Skipped != "schema_adapter_pending" {
			t.Fatal(r)
		}
	}
}

func TestComparisonFixtures(t *testing.T) {
	for _, id := range []string{"ipqs", "abuseipdb"} {
		good := `{"success":true,"fraud_score":42,"country_code":"US","ASN":13335,"proxy":false,"vpn":true,"tor":null,"echo":"secret"}`
		if id == "abuseipdb" {
			good = `{"data":{"ipAddress":"1.1.1.1","abuseConfidenceScore":42,"countryCode":"DE","echo":"secret"}}`
		}
		for _, tc := range []struct {
			name, body string
			code       int
			delay      bool
			ok         bool
		}{
			{"positive", good, 200, false, true}, {"null", "null", 200, false, false}, {"wrong_type", `{"success":true,"fraud_score":"42","data":null}`, 200, false, false},
			{"different_schema", `{"status":"ok","risk":42}`, 200, false, false}, {"malformed", "{secret", 200, false, false},
			{"oversize", good + strings.Repeat(" ", 1<<20), 200, false, false}, {"429", "secret", 429, false, false}, {"5xx", "secret", 503, false, false}, {"redirect", "secret", 302, false, false}, {"timeout", good, 200, true, false},
		} {
			t.Run(id+"/"+tc.name, func(t *testing.T) {
				var calls atomic.Int32
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					if tc.delay {
						select {
						case <-r.Context().Done():
							return
						case <-time.After(100 * time.Millisecond):
						}
					}
					w.Header().Set("Location", "http://untrusted.invalid/secret")
					w.WriteHeader(tc.code)
					w.Write([]byte(tc.body))
				}))
				defer srv.Close()
				target, _ := url.Parse(srv.URL)
				client := &http.Client{Transport: comparisonTransport(func(r *http.Request) (*http.Response, error) {
					if id == "ipqs" {
						if r.URL.Host != "ipqualityscore.com" || r.URL.Path != "/api/json/ip/secret/1.1.1.1" {
							t.Error("auth/endpoint mismatch")
						}
					} else if r.URL.Host != "api.abuseipdb.com" || r.Header.Get("Key") != "secret" || r.URL.Query().Get("ipAddress") != "1.1.1.1" {
						t.Error("auth/endpoint mismatch")
					}
					clone := r.Clone(r.Context())
					u := *r.URL
					u.Scheme = target.Scheme
					u.Host = target.Host
					clone.URL = &u
					return http.DefaultTransport.RoundTrip(clone)
				})}
				ctx := context.Background()
				if tc.delay {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, 10*time.Millisecond)
					defer cancel()
				}
				rows := CompareOnline(ctx, netip.MustParseAddr("1.1.1.1"), map[string]string{id: "secret"}, true, false, client)
				for _, r := range rows {
					if r.ID == id {
						if (r.Status == "ok") != tc.ok {
							t.Fatalf("%+v", r)
						}
						b, _ := json.Marshal(r)
						if strings.Contains(string(b), "secret") || strings.Contains(string(b), "http") {
							t.Fatalf("unsafe response: %s", b)
						}
						if tc.ok && (r.Score == nil || *r.Score != 42 || r.Timestamp == nil) {
							t.Fatal(r)
						}
					}
				}
				if calls.Load() > 1 {
					t.Fatal("redirect followed")
				}
			})
		}
	}
}

func TestComparisonDisagreementNotVotes(t *testing.T) {
	ip := netip.MustParseAddr("1.1.1.1")
	a := normalizeComparison(Comparison{ID: "ipqs", Fields: map[string]any{}}, map[string]any{"success": true, "fraud_score": float64(42), "country_code": "US", "proxy": false}, ip)
	b := normalizeComparison(Comparison{ID: "abuseipdb", Fields: map[string]any{}}, map[string]any{"data": map[string]any{"ipAddress": "1.1.1.1", "abuseConfidenceScore": float64(42), "countryCode": "DE"}}, ip)
	if *a.Score != *b.Score || a.ScoreMeaning == b.ScoreMeaning {
		t.Fatal("lost distinct semantics")
	}
	diffs := Differences([]Comparison{a, b, {ID: "missing", Status: "skipped", Fields: map[string]any{"proxy": true}}})
	if len(diffs) != 1 || len(diffs["country"]) != 2 {
		t.Fatal(diffs)
	}
	for _, raw := range []map[string]any{
		{"success": true, "fraud_score": nil}, {"success": true, "fraud_score": 42.5}, {"success": true, "fraud_score": 101.0},
		{"success": true, "fraud_score": 42.0, "proxy": "false"}, {"success": true, "fraud_score": 42.0, "ASN": "AS13335"},
	} {
		if r := normalizeComparison(Comparison{ID: "ipqs", Fields: map[string]any{}}, raw, ip); r.Status != "error" {
			t.Fatal(r)
		}
	}
}

func TestReviewEquivalentIPv6Identity(t *testing.T) {
	ip := netip.MustParseAddr("2606:4700:4700::1111")
	raw := map[string]any{"data": map[string]any{"ipAddress": "2606:4700:4700:0000:0000:0000:0000:1111", "abuseConfidenceScore": float64(0)}}
	r := normalizeComparison(Comparison{ID: "abuseipdb", Fields: map[string]any{}}, raw, ip)
	if r.Status != "ok" {
		t.Fatal("same IPv6 rejected solely due to equivalent expanded representation")
	}
}
