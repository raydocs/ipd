package providers

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

type slow struct{}

func (slow) ID() string          { return "slow" }
func (slow) Enabled() bool       { return true }
func (slow) Attribution() string { return "test" }
func (slow) License() string     { return "test" }
func (slow) Lookup(ctx context.Context, ip netip.Addr) (map[string]any, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestDisabledWithoutKey(t *testing.T) {
	all := All(nil, nil, nil)
	if len(all) < 6 {
		t.Fatal(len(all))
	}
	for _, p := range all {
		if p.Enabled() {
			t.Fatalf("%s enabled without a key", p.ID())
		}
	}
}

func TestEnrichDoesNotBlockOnSlowSource(t *testing.T) {
	f := New([]Provider{slow{}, slow{}}, 200*time.Millisecond)
	start := time.Now()
	out := f.Lookup(context.Background(), netip.MustParseAddr("1.1.1.1"))
	if time.Since(start) > 1500*time.Millisecond {
		t.Fatal(time.Since(start))
	}
	if len(out) != 2 || out[0].Status == "ok" {
		t.Fatalf("%+v", out)
	}
}
