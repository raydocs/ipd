// Package route classifies China-bound paths and runs traceroute from the egress.
// Hop classification is a local reimplementation of well-known backbone patterns.
// NextTrace is not linked.
package route

import (
	"net/netip"
	"strings"
)

// Hop is one traceroute hop annotated from the local prefix database.
type Hop struct {
	IP    string  `json:"ip"`
	ASN   int     `json:"asn"`
	RTTMS float64 `json:"rtt_ms"`
	RDNS  string  `json:"rdns,omitempty"`
	GeoCC string  `json:"geo_cc,omitempty"`
}

// Path is one carrier's route.
type Path struct {
	Carrier    string `json:"carrier"`
	Province   string `json:"province,omitempty"`
	Probe      string `json:"probe,omitempty"`
	Hops       []Hop  `json:"hops"`
	RouteClass string `json:"route_class"`
	Error      string `json:"error,omitempty"`
}

// Result is the route tool payload.
type Result struct {
	Paths         []Path `json:"paths"`
	Summary       string `json:"summary"`
	Claimed       string `json:"claimed,omitempty"`
	ClaimMismatch bool   `json:"claim_mismatch,omitempty"`
}

// Classify returns the route class for a hop list.
func Classify(hops []Hop) string {
	var cn2, ct163, u9929, u10099, u4837, cmin2, cmi, cm bool
	for _, h := range hops {
		ip, err := netip.ParseAddr(h.IP)
		in := func(cidr string) bool {
			if err != nil {
				return false
			}
			p := netip.MustParsePrefix(cidr)
			return p.Contains(ip)
		}
		if in("59.43.0.0/16") || h.ASN == 4809 {
			cn2 = true
		}
		if in("202.97.0.0/16") || h.ASN == 4134 {
			ct163 = true
		}
		if in("218.105.0.0/16") || h.ASN == 9929 {
			u9929 = true
		}
		if in("210.51.0.0/16") || h.ASN == 10099 {
			u10099 = true
		}
		if in("219.158.0.0/16") || h.ASN == 4837 {
			u4837 = true
		}
		if in("223.118.0.0/16") || in("223.119.0.0/16") || h.ASN == 58807 {
			cmin2 = true
		}
		if in("223.120.0.0/16") || h.ASN == 58453 {
			cmi = true
		}
		if h.ASN == 9808 || in("221.176.0.0/16") {
			cm = true
		}
	}
	telecom := ""
	switch {
	case cn2 && ct163:
		telecom = "cn2_gt"
	case cn2:
		telecom = "cn2_gia"
	case ct163:
		telecom = "ct163"
	}
	unicom := ""
	switch {
	case u9929 && u10099:
		unicom = "mixed"
	case u10099:
		unicom = "cu10099"
	case u9929:
		unicom = "cu9929"
	case u4837:
		unicom = "cu4837"
	}
	mobile := ""
	switch {
	case cmin2 && cmi:
		mobile = "mixed"
	case cmin2:
		mobile = "cmin2"
	case cmi:
		mobile = "cmi"
	case cm:
		mobile = "cm_normal"
	}
	var families []string
	if telecom != "" {
		families = append(families, telecom)
	}
	if unicom != "" {
		families = append(families, unicom)
	}
	if mobile != "" {
		families = append(families, mobile)
	}
	switch len(families) {
	case 0:
		return "unknown"
	case 1:
		if families[0] == "mixed" {
			return "mixed"
		}
		return families[0]
	default:
		return "mixed"
	}
}

// NormalizeClaim maps seller wording onto a route class.
func NormalizeClaim(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, "_", "")
	switch s {
	case "", "none":
		return ""
	case "cn2gia", "gia", "cn2":
		return "cn2_gia"
	case "cn2gt", "gt":
		return "cn2_gt"
	case "163", "ct163", "as4134":
		return "ct163"
	case "9929", "cu9929", "cuii":
		return "cu9929"
	case "10099", "cu10099", "cug":
		return "cu10099"
	case "4837", "cu4837", "169":
		return "cu4837"
	case "cmin2", "as58807":
		return "cmin2"
	case "cmi", "as58453":
		return "cmi"
	case "cm", "cmcc", "9808":
		return "cm_normal"
	default:
		return s
	}
}

// ClaimMismatch reports whether the measured class contradicts the seller.
func ClaimMismatch(claimed, class string) bool {
	c := NormalizeClaim(claimed)
	if c == "" || class == "" || class == "unknown" {
		return false
	}
	return c != class
}

// Summarize builds a one-line description.
func Summarize(paths []Path, claimed string) (string, bool) {
	if len(paths) == 0 {
		return "no path", false
	}
	parts := make([]string, 0, len(paths))
	mismatch := false
	for _, p := range paths {
		parts = append(parts, p.Carrier+"="+p.RouteClass)
		if ClaimMismatch(claimed, p.RouteClass) {
			mismatch = true
		}
	}
	s := strings.Join(parts, ", ")
	if claimed != "" {
		if mismatch {
			s += "; claim " + NormalizeClaim(claimed) + " does not match"
		} else {
			s += "; claim " + NormalizeClaim(claimed) + " matches"
		}
	}
	return s, mismatch
}
