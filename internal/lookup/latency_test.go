package lookup

import (
	"fmt"
	"net/netip"
	"os"
	"sort"
	"testing"
	"time"
)

func TestLookupLatency(t *testing.T) {
	e := New()
	ip := netip.MustParseAddr("1.1.1.1")
	var ds []time.Duration
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		t0 := time.Now()
		_ = e.Lookup(ip)
		ds = append(ds, time.Since(t0))
	}
	if len(ds) < 400 {
		t.Fatalf("throughput %d in 2s, want >= 200 rps", len(ds))
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	p95 := ds[int(float64(len(ds))*0.95)]
	p99 := ds[int(float64(len(ds))*0.99)]
	if p95 > 20*time.Millisecond || p99 > 50*time.Millisecond {
		t.Fatalf("p95 %s p99 %s n %d", p95, p99, len(ds))
	}
}

func TestLookupLatencyLong(t *testing.T) {
	if os.Getenv("IPD_LONG_BENCH") == "" {
		t.Skip("set IPD_LONG_BENCH=1 to run the 10 minute sample")
	}
	e := New()
	ip := netip.MustParseAddr("8.8.8.8")
	var ds []time.Duration
	deadline := time.Now().Add(10 * time.Minute)
	for time.Now().Before(deadline) {
		t0 := time.Now()
		_ = e.Lookup(ip)
		ds = append(ds, time.Since(t0))
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	p95 := ds[int(float64(len(ds))*0.95)]
	p99 := ds[int(float64(len(ds))*0.99)]
	if p95 > 20*time.Millisecond || p99 > 50*time.Millisecond {
		t.Fatalf("p95 %s p99 %s n %d", p95, p99, len(ds))
	}
}

func TestHopASN(t *testing.T) {
	e := New()
	want := map[string]int{
		"59.43.1.1":     4809,
		"202.97.1.1":    4134,
		"219.158.1.1":   4837,
		"218.105.1.1":   9929,
		"210.51.1.1":    10099,
		"223.120.1.1":   58453,
		"223.118.1.1":   58807,
		"223.119.1.1":   58807,
		"221.176.1.1":   9808,
		"1.1.1.1":       13335,
		"8.8.8.8":       15169,
		"24.1.2.3":      7922,
		"114.80.10.5":   4812,
		"172.58.1.20":   21928,
		"185.220.101.5": 60729,
		"76.100.50.10":  64512,
		"45.76.20.10":   20473,
		"3.1.2.4":       16509,
		"34.1.2.3":      15169,
		"47.74.1.1":     45102,
	}
	hit := 0
	for ip, asn := range want {
		got := e.Lookup(netip.MustParseAddr(ip)).ASN
		if got == asn {
			hit++
		} else {
			t.Logf("%s asn %d want %d", ip, got, asn)
		}
	}
	if float64(hit)/float64(len(want)) < 0.95 {
		t.Fatalf("%d/%d", hit, len(want))
	}
}

func TestAWSComposition(t *testing.T) {
	e := New()
	p := e.Lookup(netip.MustParseAddr("3.1.2.4"))
	t.Logf("asn %d cloud %q type %q", p.ASN, p.Cloud, p.ASType)
	for i := 0; i < 100; i++ {
		c := e.Composition(fmt.Sprintf("3.1.%d.0/24", i))
		if c.Contamination < 0.8 {
			t.Fatalf("%s %+v", c.CIDR, c)
		}
	}
}

func TestLocalSourceCount(t *testing.T) {
	e := New()
	n := 0
	for _, s := range e.Sources(time.Now()) {
		if s.Kind == "local" {
			n++
		}
	}
	if n < 12 {
		t.Fatal(n)
	}
}
