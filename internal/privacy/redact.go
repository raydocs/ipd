// Package privacy implements the non-negotiable constraints from plan section 8:
// no WebRTC candidate storage, short raw-IP retention, and explicit redaction
// before anything can be shared.
package privacy

import (
	"net/netip"
	"regexp"
	"strings"
	"time"
)

// Retention is the maximum age of raw visitor IP logs.
const Retention = 7 * 24 * time.Hour

// WebRTCReport is the only shape the server accepts for a browser leak verdict.
// It deliberately has no IP field. Candidates stay in the browser.
type WebRTCReport struct {
	Leak           bool `json:"leak"`
	CandidateCount int  `json:"candidate_count"`
}

// Expired reports whether a log row older than now-retention must be deleted.
func Expired(ts, now time.Time, retention time.Duration) bool {
	if retention <= 0 {
		retention = Retention
	}
	return now.Sub(ts) > retention
}

var hostRe = regexp.MustCompile(`(?i)\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)\b`)

// Redact removes RFC1918 and other non-public addresses, .local names, and the
// supplied hostnames from a report before it can leave the machine.
func Redact(s string, extraHosts []string) string {
	if s == "" {
		return s
	}
	out := s
	for _, h := range extraHosts {
		if h == "" {
			continue
		}
		out = strings.ReplaceAll(out, h, "[redacted-host]")
	}
	fields := strings.FieldsFunc(out, func(r rune) bool {
		switch r {
		case ' ', '\n', '\t', ',', ';', '"', '\'', '(', ')', '[', ']', '<', '>':
			return true
		default:
			return false
		}
	})
	for _, f := range fields {
		f = strings.Trim(f, ".")
		if ip, err := netip.ParseAddr(f); err == nil && !IsPublic(ip) {
			out = strings.ReplaceAll(out, f, "[redacted-ip]")
		}
	}
	out = hostRe.ReplaceAllStringFunc(out, func(h string) string {
		lh := strings.ToLower(h)
		if strings.HasSuffix(lh, ".local") || lh == "localhost" || strings.HasSuffix(lh, ".localhost") || strings.HasSuffix(lh, ".internal") {
			return "[redacted-host]"
		}
		return h
	})
	return out
}

// IsPublic is false for loopback, private, link-local, documentation,
// benchmarking, CGNAT, and unspecified addresses.
func IsPublic(ip netip.Addr) bool {
	if !ip.IsValid() || !ip.IsGlobalUnicast() {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	if ip.Is4() {
		switch {
		case ip.Compare(netip.MustParseAddr("192.0.2.0")) >= 0 && ip.Compare(netip.MustParseAddr("192.0.2.255")) <= 0:
			return false
		case ip.Compare(netip.MustParseAddr("198.51.100.0")) >= 0 && ip.Compare(netip.MustParseAddr("198.51.100.255")) <= 0:
			return false
		case ip.Compare(netip.MustParseAddr("203.0.113.0")) >= 0 && ip.Compare(netip.MustParseAddr("203.0.113.255")) <= 0:
			return false
		case ip.Compare(netip.MustParseAddr("198.18.0.0")) >= 0 && ip.Compare(netip.MustParseAddr("198.19.255.255")) <= 0:
			return false
		case ip.Compare(netip.MustParseAddr("100.64.0.0")) >= 0 && ip.Compare(netip.MustParseAddr("100.127.255.255")) <= 0:
			return false
		case ip.Compare(netip.MustParseAddr("169.254.0.0")) >= 0 && ip.Compare(netip.MustParseAddr("169.254.255.255")) <= 0:
			return false
		}
	}
	if ip.Is6() {
		if ip.Compare(netip.MustParseAddr("2001:db8::")) >= 0 && ip.Compare(netip.MustParseAddr("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff")) <= 0 {
			return false
		}
	}
	return true
}

// IsProbeTargetAllowed rejects private, reserved, and cloud-metadata addresses
// so probe tasks cannot be turned into an internal scanner.
func IsProbeTargetAllowed(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if host == "169.254.169.254" || !IsPublic(ip) {
			return false
		}
		return true
	}
	lh := strings.ToLower(host)
	if lh == "localhost" || strings.HasSuffix(lh, ".local") || strings.HasSuffix(lh, ".internal") || lh == "metadata.google.internal" {
		return false
	}
	return true
}
