package app

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"

	"ipd/internal/privacy"
	"ipd/internal/providers"
)

// Compare is separate from Risk: it neither feeds purity nor records history.
func (s *Service) Compare(ctx context.Context, ip string, live bool) (Report, error) {
	addr, err := netip.ParseAddr(ip)
	addr = addr.Unmap()
	if err != nil || addr.Zone() != "" || !privacy.IsPublic(addr) {
		return Report{}, fmt.Errorf("public IP required")
	}
	addr = addr.Unmap()
	offline := s.Cfg == nil || s.Cfg.Offline
	var keys map[string]string
	if s.Cfg != nil {
		keys = s.Cfg.ProviderKeys
	}
	client := s.comparisonClient
	var proxy func(*http.Request) (*url.URL, error) = http.ProxyFromEnvironment
	if s.Cfg != nil && s.Cfg.Proxy != "" {
		u, parseErr := url.Parse(s.Cfg.Proxy)
		if parseErr != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5" && u.Scheme != "socks5h") {
			return Report{}, fmt.Errorf("invalid comparison proxy configuration")
		}
		proxy = http.ProxyURL(u)
	}
	if client == nil {
		client = &http.Client{Transport: &http.Transport{Proxy: proxy, DisableCompression: true}}
	}
	rows := providers.CompareOnline(ctx, addr, keys, live, offline, client)
	p, metadata := s.Look.LookupWithSources(addr, s.now())
	for _, id := range []string{"maxmind_geolite", "ipinfo_lite"} {
		row := providers.Comparison{ID: id, Status: "unknown", Skipped: "no_source_observation", Scope: "local snapshot country/ASN only", Confidence: "unknown", Fields: map[string]any{}}
		for _, m := range metadata {
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
