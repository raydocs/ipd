package app

import (
	"context"
	"ipd/internal/config"
	"ipd/internal/lookup"
	"ipd/internal/providers"
	"testing"
)

func TestCompareLocalContract(t *testing.T) {
	s := &Service{Cfg: &config.Config{Offline: true, ProviderKeys: map[string]string{"ipqs": "secret"}}, Look: lookup.New()}
	rep, err := s.Compare(context.Background(), "1.1.1.1", true)
	if err != nil || rep.Verdict != "abstain" {
		t.Fatal(rep, err)
	}
	rows := rep.Data.(map[string]any)["rows"].([]providers.Comparison)
	if len(rows) != 7 {
		t.Fatal(rows)
	}
	for _, r := range rows {
		switch r.ID {
		case "ipinfo_lite":
			if r.Status != "ok" || r.Version != "fixture-2026.10.23" || r.Timestamp == nil || r.Fields["asn"] != 13335 {
				t.Fatal(r)
			}
		case "maxmind_geolite":
			if r.Status != "unknown" || r.Skipped != "local_dataset_not_loaded" || r.Timestamp != nil || len(r.Fields) != 0 {
				t.Fatal(r)
			}
		default:
			if r.Skipped != "offline" {
				t.Fatal(r)
			}
		}
	}
	for _, ip := range []string{"bad", "127.0.0.1", "192.0.2.1", "::1", "::ffff:127.0.0.1", "::ffff:1.1.1.1%en0"} {
		if _, err := s.Compare(context.Background(), ip, true); err == nil {
			t.Fatal(ip)
		}
	}
}
