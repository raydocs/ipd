package probe

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestAnchorHistoryAgingRecoveryAndBounds(t *testing.T) {
	now := time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)
	h := Health{now: func() time.Time { return now }}
	if s := h.Snapshot("p"); s.Known || s.Weight != nil || s.Samples != 0 {
		t.Fatal(s)
	}
	for i := 0; i < 3; i++ {
		h.ObserveAnchor("p", fmt.Sprint(i), false)
	}
	if h.ObserveAnchor("p", "0", true) {
		t.Fatal("replayed anchor counted")
	}
	if s := h.Snapshot("p"); !s.Known || s.Samples != 3 || *s.Weight != 0 || h.Healthy("p") {
		t.Fatal(s)
	}
	for i := 0; i < 3; i++ {
		h.ObserveAnchor("p", fmt.Sprint("recovery", i), true)
	}
	if s := h.Snapshot("p"); !h.Healthy("p") || *s.Weight != 0.5 {
		t.Fatal(s)
	}
	// Expire failures, retain fresh successful anchors, then expire all.
	now = now.Add(anchorTTL - time.Minute)
	for i := 0; i < 3; i++ {
		h.ObserveAnchor("p", fmt.Sprint("fresh", i), true)
	}
	now = now.Add(time.Minute)
	if s := h.Snapshot("p"); s.Samples != 3 || *s.Weight != 1 {
		t.Fatal(s)
	}
	now = now.Add(anchorTTL)
	if s := h.Snapshot("p"); s.Known || s.Weight != nil || s.Samples != 0 || !h.Healthy("p") {
		t.Fatal(s)
	}
	for i := 0; i < maxAnchorEvents+9; i++ {
		h.ObserveAnchor("p", fmt.Sprint(i), true)
	}
	if s := h.Snapshot("p"); s.Samples != maxAnchorEvents {
		t.Fatal(s)
	}
	s := h.Snapshot("p")
	*s.Weight = 0
	if *h.Snapshot("p").Weight != 1 {
		t.Fatal("snapshot aliases storage")
	}
	for i := 0; i < maxAnchorProbes+1; i++ {
		now = now.Add(time.Second)
		h.ObserveAnchor(fmt.Sprint(i), "a", true)
	}
	if len(h.n) != maxAnchorProbes || h.Snapshot("p").Samples != 0 || h.Snapshot("0").Samples != 0 {
		t.Fatal("bucket cap/eviction failed")
	}
	if h.ObserveAnchor("", "x", true) || h.ObserveAnchor("x", "", true) {
		t.Fatal("empty identity accepted")
	}
}

func TestAnchorHistoryConcurrency(t *testing.T) {
	h := Health{now: func() time.Time { return time.Unix(100, 0) }}
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				h.ObserveAnchor("p", fmt.Sprint(j), j%2 == 0)
				h.Healthy("p")
				h.Snapshot("p")
			}
		}()
	}
	wg.Wait()
	if s := h.Snapshot("p"); s.Samples != 20 || s.Failures != 10 || *s.Weight != 0.5 {
		t.Fatal(s)
	}
}

func TestDecodeOnlyReadsAnchorHistory(t *testing.T) {
	id := "4134/history-isolation"
	for i := 0; i < 3; i++ {
		DefaultHealth.ObserveAnchor(id, fmt.Sprint(i), false)
	}
	for _, kind := range []Kind{KindPing, KindTCP, KindDNS, KindHTTP, KindTrace} {
		for _, status := range []string{"failed", "finished"} {
			var doc gpDoc
			if err := json.Unmarshal([]byte(`{"results":[{"probe":{"asn":4134,"city":"history-isolation","country":"CN"},"result":{"status":"`+status+`"}}]}`), &doc); err != nil {
				t.Fatal(err)
			}
			got := decodeGP(doc, Query{Kind: kind})[0]
			if got.Healthy || got.AnchorHealth.Samples != 3 || got.AnchorHealth.Failures != 3 {
				t.Fatalf("%s/%s: %+v", kind, status, got)
			}
		}
	}
	if s := DefaultHealth.Snapshot("4134/target-isolation"); s.Samples != 0 {
		t.Fatalf("target result polluted history: %+v", s)
	}
}
