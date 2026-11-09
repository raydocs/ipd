package app

import (
	"context"
	"ipd/internal/config"
	"ipd/internal/lookup"
	"ipd/internal/providers"
	"sync"
	"testing"
	"time"
)

func TestReviewAtomicSourceProvenance(t *testing.T) {
	e := lookup.New()
	install := func(version string, asn int) {
		e.MergeSource(lookup.SourceMeta{ID: "ipinfo_lite", Version: version, UpdatedAt: time.Date(2026, 11, 1, 0, 0, 0, asn, time.UTC), License: "license-" + version}, []lookup.SourceRow{{Source: "ipinfo_lite", Rec: lookup.Rec{Prefix: "1.1.1.0/24", CC: "US", ASN: asn}}})
	}
	install("A", 65001)
	refresh, done := make(chan struct{}), make(chan struct{})
	go func() { <-refresh; install("B", 65002); close(done) }()
	var once sync.Once
	s := &Service{Cfg: &config.Config{Offline: true}, Look: e, Now: func() time.Time { once.Do(func() { close(refresh); <-done }); return time.Now() }}
	rep, err := s.Compare(context.Background(), "1.1.1.1", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rep.Data.(map[string]any)["rows"].([]providers.Comparison) {
		if r.ID == "ipinfo_lite" && ((r.Version == "A" && r.Fields["asn"] != 65001) || (r.Version == "B" && r.Fields["asn"] != 65002)) {
			t.Fatalf("mixed snapshot generation: version=%s asn=%v", r.Version, r.Fields["asn"])
		}
	}
}

func TestReviewMappedReservedRejected(t *testing.T) {
	s := &Service{Cfg: &config.Config{Offline: true}, Look: lookup.New()}
	for _, ip := range []string{"::ffff:192.0.2.1", "::ffff:100.64.0.1", "::ffff:198.18.0.1"} {
		if _, err := s.Compare(context.Background(), ip, true); err == nil {
			t.Errorf("non-public IPv4-mapped address accepted: %s", ip)
		}
	}
}
