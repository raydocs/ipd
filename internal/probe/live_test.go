package probe

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestLiveGlobalpingPingAndTrace(t *testing.T) {
	if !reachable("api.globalping.io:443", 3*time.Second) {
		t.Skip("globalping api unreachable")
	}
	g := Globalping{MinInterval: 200 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
	defer cancel()
	ping, err := g.Measure(ctx, Query{
		Kind: KindPing, Target: "1.1.1.1", Countries: []string{"US"}, Limit: 1, Packets: 1,
	})
	if err != nil {
		t.Skipf("live ping: %v", err)
	}
	if len(ping) == 0 || ping[0].Country == "" {
		t.Fatalf("ping %+v", ping)
	}
	t.Logf("ping %+v", ping[0])
	tr, err := g.Measure(ctx, Query{
		Kind: KindTrace, Target: "1.1.1.1", Countries: []string{"US"}, Limit: 1, MaxHops: 8,
	})
	if err != nil {
		t.Skipf("live traceroute: %v", err)
	}
	if len(tr) == 0 || len(tr[0].Hops) == 0 {
		t.Fatalf("traceroute %+v", tr)
	}
	t.Logf("hops %d first %s", len(tr[0].Hops), tr[0].Hops[0].IP)
	for _, q := range []Query{
		{Kind: KindTCP, Target: "1.1.1.1", Port: 443, Countries: []string{"US"}, Limit: 1, Packets: 1},
		{Kind: KindDNS, Target: "example.com", DNSName: "example.com", Countries: []string{"US"}, Limit: 1},
		{Kind: KindHTTP, Target: "example.com", Port: 443, Countries: []string{"US"}, Limit: 1},
	} {
		got, err := g.Measure(ctx, q)
		if err != nil {
			if strings.Contains(err.Error(), "400") || strings.Contains(err.Error(), "validation") {
				t.Fatalf("%s: %v", q.Kind, err)
			}
			t.Logf("%s skipped: %v", q.Kind, err)
			continue
		}
		if len(got) == 0 {
			t.Fatalf("%s empty", q.Kind)
		}
		t.Logf("%s network=%s icmp=%s tcp=%v sni=%s dns=%v", q.Kind, got[0].Network, got[0].ICMP, got[0].TCP, got[0].SNI, got[0].DNSAddrs)
	}
}

func reachable(addr string, d time.Duration) bool {
	c, err := net.DialTimeout("tcp", addr, d)
	if err != nil {
		return false
	}
	_ = c.Close()
	_ = http.DefaultClient
	return true
}
