package providers

import (
	"net/netip"
	"strconv"
	"strings"
)

// normalizeProxycheck accepts v3 nested observations, never legacy v2 yes/no.
func normalizeProxycheck(row Comparison, raw map[string]any, ip netip.Addr) Comparison {
	fail := func() Comparison {
		row.Status = "error"
		row.Error = "invalid_provider_response"
		row.Fields = map[string]any{}
		row.Score = nil
		return row
	}
	status, _ := raw["status"].(string)
	if status != "ok" && status != "warning" {
		return fail()
	}
	// A single-address query must have exactly one, unambiguous address result.
	var data map[string]any
	matches := 0
	for key, value := range raw {
		addr, err := netip.ParseAddr(key)
		if err != nil {
			continue
		}
		if addr.Zone() != "" || addr.Unmap() != ip.Unmap() {
			return fail()
		}
		matches++
		data, _ = value.(map[string]any)
	}
	if matches != 1 || data == nil {
		return fail()
	}
	if value, exists := raw["ip"]; exists {
		returned, ok := value.(string)
		addr, err := netip.ParseAddr(returned)
		if !ok || err != nil || addr.Zone() != "" || addr.Unmap() != ip.Unmap() {
			return fail()
		}
	}
	detections, ok := data["detections"].(map[string]any)
	if !ok {
		return fail()
	}
	fields := map[string]any{}
	for _, key := range []string{"proxy", "vpn", "tor"} {
		if value, exists := detections[key]; exists && value != nil {
			b, ok := value.(bool)
			if !ok {
				return fail()
			}
			fields[key] = b
		}
	}
	for _, key := range []string{"location", "network"} {
		value, exists := data[key]
		if !exists || value == nil {
			continue
		}
		object, ok := value.(map[string]any)
		if !ok {
			return fail()
		}
		if key == "location" {
			if value, exists := object["isocode"]; exists && value != nil {
				cc, ok := value.(string)
				if !ok || len(cc) != 2 || cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' {
					return fail()
				}
				fields["country"] = cc
			}
		} else if value, exists := object["asn"]; exists && value != nil {
			asn, ok := value.(string)
			if !ok || !strings.HasPrefix(asn, "AS") || len(asn) < 3 {
				return fail()
			}
			digits := asn[2:]
			for _, r := range digits {
				if r < '0' || r > '9' {
					return fail()
				}
			}
			n, err := strconv.ParseUint(digits, 10, 32)
			if err != nil || n == 0 {
				return fail()
			}
			fields["asn"] = uint32(n)
		}
	}
	var resultScore *int
	if value, exists := data["risk"]; exists && value != nil {
		n, ok := value.(float64)
		if !ok || n < 0 || n > 100 || n != float64(int(n)) {
			return fail()
		}
		score := int(n)
		resultScore = &score
	}
	row.Fields = fields
	row.Score = resultScore
	row.Version = "proxycheck-v3"
	if resultScore != nil {
		row.ScoreMeaning = "proxycheck risk (0-100): detection baseline and attack history; not fraud probability or account safety"
	}
	if status == "warning" {
		row.Error = "provider_warning"
	}
	if len(fields) == 0 && resultScore == nil {
		row.Status = "unknown"
		row.Skipped = "no_comparable_observation"
		return row
	}
	row.Status = "ok"
	row.Confidence = "provider_assertion_not_calibrated"
	return row
}
