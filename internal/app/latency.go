package app

import (
	"context"
	"encoding/xml"
	"fmt"
	"math"
	"strings"
	"time"

	"ipd/internal/probe"
)

// Latency collects the existing ping budget once; saving the card never probes again.
func (s *Service) Latency(ctx context.Context, target string) (Report, error) {
	if strings.TrimSpace(target) == "" {
		return Report{}, fmt.Errorf("latency target required")
	}
	source, note := "none", ""
	var samples []probe.Sample
	if s.Vantage != nil {
		source = s.Vantage.Name()
		if strings.TrimSpace(source) == "" {
			source = "unknown"
		}
	}
	switch {
	case s.Cfg != nil && s.Cfg.Offline:
		note = "Offline: no measurement requested."
	case s.Vantage == nil || !s.Vantage.Enabled():
		note = "Vantage disabled: no measurement requested."
	default:
		var err error
		samples, err = s.Vantage.Measure(ctx, probe.Query{Kind: probe.KindPing, Target: target, Limit: 2, Control: 2})
		if err != nil {
			// Transport errors can contain credential-bearing URLs. A shareable
			// card records the evidence gap without copying raw request errors.
			note = "Provider request failed; batch results may be incomplete."
		}
	}
	at := s.now().UTC()
	rows := make([]map[string]any, 0, len(samples))
	valid, failed, unknown, lossy := 0, 0, 0, 0
	for _, sm := range samples {
		status, reason := latencyStatus(sm)
		row := map[string]any{
			"probe": sm.Provider, "cc": sm.Country, "city": sm.City, "asn": sm.ASN,
			"rtt_ms": nil, "loss": nil, "status": status, "reason": reason,
			"healthy": sm.Healthy, "icmp": sm.ICMP, "error": sm.Error,
		}
		if sm.Provider == "" {
			row["probe"] = source
		}
		// The provider type has no presence bit for loss: zero is only credible
		// alongside a valid RTT. Failed/unknown zeroes must not imply zero loss.
		if latencyFinite(sm.Loss) && sm.Loss >= 0 && sm.Loss <= 1 && (status == "valid" || sm.Loss > 0 && sm.Healthy && sm.ICMP != "skipped") {
			row["loss"] = sm.Loss
			if sm.Loss > 0 {
				lossy++
			}
		}
		switch status {
		case "valid":
			valid++
			row["rtt_ms"] = sm.RTTMS
		case "failed":
			failed++
		default:
			unknown++
		}
		rows = append(rows, row)
	}
	verdict := "ok"
	if valid == 0 {
		verdict = "abstain"
	} else if failed > 0 || unknown > 0 || lossy > 0 || note != "" {
		verdict = "ok_with_caveats"
	}
	summary := fmt.Sprintf("%d samples: %d valid, %d failed, %d unknown; %d with observed packet loss", len(rows), valid, failed, unknown, lossy)
	if valid == 0 {
		summary += "; no valid RTT evidence"
	}
	if note != "" {
		summary += "; " + note
	}
	data := map[string]any{
		"target": target, "measured_at": at.Format(time.RFC3339Nano), "source": source,
		"sample_count": len(rows), "valid_count": valid, "failed_count": failed, "unknown_count": unknown,
		"loss_count": lossy, "note": note, "rows": rows,
	}
	data["svg"] = latencySVG(data, verdict, rows)
	return Report{Verdict: verdict, Summary: summary, Data: data, Sources: []Source{{ID: source}}, CachedAt: at}, nil
}

func latencyFinite(n float64) bool { return !math.IsNaN(n) && !math.IsInf(n, 0) }

func latencyStatus(sm probe.Sample) (string, string) {
	switch {
	case sm.ICMP == "skipped":
		return "unknown", "measurement skipped"
	case !sm.Healthy:
		return "unknown", "probe health unavailable or unhealthy"
	case sm.Error != "":
		return "failed", "provider reported an error"
	case sm.ICMP == "timeout" || sm.ICMP == "reset" || sm.ICMP == "unreachable" || sm.ICMP == "failed" || sm.ICMP == "error":
		return "failed", "ping did not succeed"
	case latencyFinite(sm.Loss) && sm.Loss == 1:
		return "failed", "100% packet loss"
	case sm.ICMP != "ok" && sm.ICMP != "loss":
		return "unknown", "missing or unsupported ping status"
	case !latencyFinite(sm.RTTMS) || sm.RTTMS <= 0:
		return "unknown", "missing or invalid RTT"
	case !latencyFinite(sm.Loss) || sm.Loss < 0 || sm.Loss >= 1:
		return "unknown", "invalid loss fraction"
	case sm.ICMP == "loss" && sm.Loss == 0:
		return "unknown", "loss status without a positive loss fraction"
	default:
		return "valid", "positive RTT from a healthy responding probe"
	}
}

// latencySVG only emits static SVG elements/attributes. Every dynamic value is
// XML text, never markup, a URL, a CSS value or a geographic coordinate.
func latencySVG(data map[string]any, verdict string, rows []map[string]any) string {
	lines := []string{
		"ipd latency | VERDICT: " + verdict,
		fmt.Sprintf("Target: %s", data["target"]),
		fmt.Sprintf("Collected UTC: %s (collection time, not a remote probe timestamp)", data["measured_at"]),
		fmt.Sprintf("Source: %s | ICMP ping; single measurement batch", data["source"]),
		fmt.Sprintf("Samples: %d | Valid RTT: %d | Failed: %d | Unknown: %d | Loss observed: %d", data["sample_count"], data["valid_count"], data["failed_count"], data["unknown_count"], data["loss_count"]),
		"Probe locations are provider labels, not verified coordinates. No map/geolocation inferred.",
		"Failed = reported ping failure; unknown = skipped/unhealthy/missing evidence; neither means 0 ms.",
		"Packet loss is separate from failed/unknown sample counts; unknown loss is not 0%.",
	}
	if note, _ := data["note"].(string); note != "" {
		lines = append(lines, note)
	}
	if len(rows) == 0 {
		lines = append(lines, "No samples returned; no latency conclusion is available.")
	}
	for i, row := range rows {
		rtt, loss := "unknown", "unknown"
		if n, ok := row["rtt_ms"].(float64); ok {
			rtt = fmt.Sprintf("%.6g ms", n)
		}
		if n, ok := row["loss"].(float64); ok {
			loss = fmt.Sprintf("%.4g%%", n*100)
		}
		lines = append(lines,
			fmt.Sprintf("#%d Source: %s | CC: %s | City: %s | AS%d", i+1, row["probe"], row["cc"], row["city"], row["asn"]),
			fmt.Sprintf("  %s | RTT: %s | Packet loss: %s | %s", row["status"], rtt, loss, row["reason"]),
		)
		if err, _ := row["error"].(string); err != "" {
			lines = append(lines, "  Error: "+err)
		}
	}
	// Wrap plain text before escaping so long/untrusted labels cannot hide the
	// evidence off-canvas. Layout coordinates are unrelated to probe geography.
	var wrapped []string
	for _, line := range lines {
		for _, part := range strings.Split(line, "\n") {
			runes := []rune(part)
			for len(runes) > 64 {
				wrapped = append(wrapped, string(runes[:64]))
				runes = runes[64:]
			}
			wrapped = append(wrapped, string(runes))
		}
	}
	height := 32 + len(wrapped)*22
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" width="960" height="%d" viewBox="0 0 960 %d">`, height, height)
	b.WriteString(`<rect width="100%" height="100%" fill="#f4f1ea"/>`)
	for i, line := range wrapped {
		fmt.Fprintf(&b, `<text x="16" y="%d" font-family="monospace" font-size="14" fill="#191919" xml:space="preserve">`, 26+i*22)
		_ = xml.EscapeText(&b, []byte(line))
		b.WriteString(`</text>`)
	}
	b.WriteString(`</svg>`)
	return b.String()
}
