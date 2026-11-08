package app

import (
	"context"
	"fmt"
	"net/netip"

	"ipd/internal/privacy"
	"ipd/internal/providers"
)

// Compare is separate from Risk: it neither feeds purity nor records history.
func (s *Service) Compare(ctx context.Context, ip string, live bool) (Report, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !privacy.IsPublic(addr) {
		return Report{}, fmt.Errorf("public IP required")
	}
	addr = addr.Unmap()
	offline := s.Cfg == nil || s.Cfg.Offline
	var keys map[string]string
	if s.Cfg != nil {
		keys = s.Cfg.ProviderKeys
	}
	rows := providers.CompareOnline(ctx, addr, keys, live, offline, nil)
	p := s.Look.Lookup(addr)
	for _, id := range []string{"maxmind_geolite", "ipinfo_lite"} {
		row := providers.Comparison{ID: id, Status: "unknown", Skipped: "no_source_observation", Scope: "local snapshot country/ASN only", Confidence: "unknown", Fields: map[string]any{}}
		for _, m := range s.Look.Sources(s.now()) {
			if m.ID != id {
				continue
			}
			row.Licensing = m.License
			row.Attribution = m.Attribution
			row.Version = m.Version
			if !m.UpdatedAt.IsZero() {
				at := m.UpdatedAt
				row.Timestamp = &at
			}
			if !m.Enabled {
				row.Skipped = "local_dataset_not_loaded"
			}
		}
		for _, h := range p.Hits {
			if h.Source != id {
				continue
			}
			if h.Rec.CC != "" {
				row.Fields["country"] = h.Rec.CC
			}
			if h.Rec.ASN > 0 {
				row.Fields["asn"] = h.Rec.ASN
			}
			if len(row.Fields) > 0 {
				row.Status = "ok"
				row.Skipped = ""
				row.Confidence = "snapshot_observation_not_calibrated"
			}
		}
		// MMDB only fills merged fields today; never misattribute those fields as a source observation.
		if id == "maxmind_geolite" && row.Status != "ok" && row.Skipped == "no_source_observation" {
			row.Skipped = "source_specific_mmdb_adapter_pending"
			row.Timestamp = nil
		}
		rows = append(rows, row)
	}
	data := map[string]any{"ip": addr.String(), "rows": rows, "differences": providers.Differences(rows)}
	return Report{Verdict: "abstain", Summary: "多源并列（Draft）：缺源不等于否定；分数语义不同，不可互换；一致或无黑名单不证明安全。", Data: data, Sources: []Source{}, CachedAt: s.now()}, nil
}
