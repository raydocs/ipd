package probe

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGlobalpingRequestAndDecode(t *testing.T) {
	g := Globalping{}
	for _, tc := range []struct {
		kind Kind
		want string
	}{
		{KindPing, "ping"},
		{KindTCP, "ping"},
		{KindTrace, "traceroute"},
		{KindMTR, "mtr"},
		{KindDNS, "dns"},
		{KindHTTP, "http"},
	} {
		body := g.request(Query{Kind: tc.kind, Target: "1.1.1.1", Port: 443, DNSName: "example.com"})
		if body["type"] != tc.want {
			t.Fatalf("%s type %v", tc.kind, body["type"])
		}
	}
	tcp := g.request(Query{Kind: KindTCP, Target: "1.1.1.1", Port: 443})
	opts := tcp["measurementOptions"].(map[string]any)
	if opts["protocol"] != "TCP" || opts["port"] != 443 {
		t.Fatal(opts)
	}
	if _, ok := opts["ipVersion"]; ok {
		t.Fatal("ipVersion is rejected for an address target")
	}
	host := g.request(Query{Kind: KindDNS, Target: "example.com", DNSName: "example.com"})
	if host["measurementOptions"].(map[string]any)["ipVersion"] != 4 {
		t.Fatalf("hostname options %#v", host["measurementOptions"])
	}
	raw := []byte(`{"status":"finished","results":[{"probe":{"asn":4134,"city":"Shanghai","country":"CN"},"result":{"status":"finished","rawOutput":"","stats":{"loss":50,"avg":12.5},"hops":[{"resolvedAddress":"59.43.1.1","timings":[{"rtt":10},{"rtt":12}],"asn":4809}],"answers":[{"value":"1.2.3.4"}]}}]}`)
	var doc gpDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	got := decodeGP(doc, Query{Kind: KindTrace})
	if len(got) != 1 || got[0].Network != "ct" || got[0].Loss != 0.5 || len(got[0].Hops) != 1 {
		t.Fatalf("%+v", got)
	}
	if got[0].Hops[0].IP != "59.43.1.1" || got[0].Hops[0].ASN != 4809 || got[0].Hops[0].RTTMS != 11 {
		t.Fatalf("%+v", got[0].Hops)
	}
	if got[0].DNSAddrs[0] != "1.2.3.4" {
		t.Fatal(got[0].DNSAddrs)
	}
	ping := decodeGP(doc, Query{Kind: KindPing})
	if ping[0].ICMP != "loss" {
		t.Fatal(ping[0].ICMP)
	}
}

func TestGlobalpingRetryAfter(t *testing.T) {
	var posts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts++
			if posts == 1 {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte("slow down"))
				return
			}
			_, _ = w.Write([]byte(`{"id":"m1"}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"finished","results":[{"probe":{"asn":15169,"city":"Ashburn","country":"US"},"result":{"status":"finished","stats":{"loss":0,"avg":1.2}}}]}`))
	}))
	defer srv.Close()
	g := Globalping{BaseURL: srv.URL, MinInterval: -1, Client: srv.Client()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := g.Measure(ctx, Query{Kind: KindPing, Countries: []string{"US"}, Limit: 1, Packets: 1, Target: "1.1.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Network != "control" || got[0].ICMP != "ok" || got[0].RTTMS != 1.2 {
		t.Fatalf("%+v", got)
	}
}
