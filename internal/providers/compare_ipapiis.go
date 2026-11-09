package providers

import "net/netip"

// normalizeIPAPIIS exports only typed, comparable observations. Provider labels,
// contact details and network "abuser_score" strings are not per-IP risk scores.
func normalizeIPAPIIS(row Comparison, raw map[string]any, ip netip.Addr) Comparison {
	fail := func() Comparison {
		row.Status = "error"
		row.Error = "invalid_provider_response"
		row.Fields = map[string]any{}
		row.Score = nil
		return row
	}
	returned, _ := raw["ip"].(string)
	addr, err := netip.ParseAddr(returned)
	if err != nil || addr.Zone() != "" || addr.Unmap() != ip.Unmap() {
		return fail()
	}
	// Anonymous and error responses are different contracts, not negative detections.
	for _, key := range []string{"docs", "error", "error_code"} {
		if value, exists := raw[key]; exists && value != nil {
			return fail()
		}
	}
	fields := map[string]any{}
	for source, target := range map[string]string{"is_proxy": "proxy", "is_vpn": "vpn", "is_tor": "tor"} {
		if value, exists := raw[source]; exists && value != nil {
			b, ok := value.(bool)
			if !ok {
				return fail()
			}
			fields[target] = b
		}
	}
	for _, key := range []string{"location", "asn"} {
		value, exists := raw[key]
		if !exists || value == nil {
			continue
		}
		object, ok := value.(map[string]any)
		if !ok {
			return fail()
		}
		if key == "location" {
			if value, exists := object["country_code"]; exists && value != nil {
				country, ok := value.(string)
				if !ok || len(country) != 2 || country[0] < 'A' || country[0] > 'Z' || country[1] < 'A' || country[1] > 'Z' {
					return fail()
				}
				fields["country"] = country
			}
		} else if value, exists := object["asn"]; exists && value != nil {
			n, ok := value.(float64)
			if !ok || n <= 0 || n > 4294967295 || n != float64(uint32(n)) {
				return fail()
			}
			fields["asn"] = uint32(n)
		}
	}
	row.Fields = fields
	if len(fields) == 0 {
		row.Status = "unknown"
		row.Skipped = "no_comparable_observation"
		return row
	}
	row.Status = "ok"
	row.Confidence = "provider_assertion_not_calibrated"
	return row
}
