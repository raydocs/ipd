package probe

import (
	"testing"
	"time"
)

func TestProbeHealthAndQuota(t *testing.T) {
	var h Health
	if !h.Healthy("4134/Shanghai") {
		t.Fatal("unknown probe should vote")
	}
	h.Observe("4134/Shanghai", false)
	h.Observe("4134/Shanghai", false)
	if !h.Healthy("4134/Shanghai") {
		t.Fatal("two failures are not yet a trend")
	}
	h.Observe("4134/Shanghai", false)
	if h.Healthy("4134/Shanghai") {
		t.Fatal("three failures should drop the probe")
	}
	h.Observe("4837/Beijing", true)
	h.Observe("4837/Beijing", true)
	h.Observe("4837/Beijing", false)
	if !h.Healthy("4837/Beijing") {
		t.Fatal("a probe that mostly answers stays healthy")
	}

	var b hourBudget
	now := time.Date(2026, 10, 24, 1, 0, 0, 0, time.UTC)
	for i := 0; i < 250; i++ {
		if err := b.take(250, now); err != nil {
			t.Fatalf("take %d: %v", i, err)
		}
	}
	if err := b.take(250, now); err != ErrQuota {
		t.Fatalf("251st take: %v", err)
	}
	if err := b.take(250, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	var authed hourBudget
	if err := authed.take(500, now); err != nil {
		t.Fatal(err)
	}
}
