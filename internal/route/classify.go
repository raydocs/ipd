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
	IP        string  `json:"ip"`
	ASN       int     `json:"asn"`
	LookupASN int     `json:"lookup_asn,omitempty"`
	RTTMS     float64 `json:"rtt_ms"`
	RDNS      string  `json:"rdns,omitempty"`
	GeoCC     string  `json:"geo_cc,omitempty"`
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
	Direction     string `json:"direction,omitempty"`
	Error         string `json:"error,omitempty"`
	Summary       string `json:"summary"`
	Claimed       string `json:"claimed,omitempty"`
	ClaimMismatch bool   `json:"claim_mismatch,omitempty"`
}

// Classify returns the route class for a hop list.
func Classify(hops []Hop) string {
	var cn2, ct163, u9929, u10099, u4837, cmin2, cmi, cm bool
	for _, h := range hops {
		ip, err := netip.ParseAddr(h.IP)
		if err != nil { // A timeout's ASN or hostname is not an observed router.
			continue
		}
		if h.LookupASN != 0 && h.ASN != 0 && h.LookupASN != h.ASN {
			return "unknown"
		}
		in := func(cidr string) bool {
			p := netip.MustParsePrefix(cidr)
			return p.Contains(ip)
		}
		// Prefix patterns are hints, not independent confirmation of an ASN.
		prefixASN := 0
		switch {
		case in("59.43.0.0/16"):
			prefixASN = 4809
		case in("202.97.0.0/16"):
			prefixASN = 4134
		case in("218.105.0.0/16"):
			prefixASN = 9929
		case in("210.51.0.0/16"):
			prefixASN = 10099
		case in("219.158.0.0/16"):
			prefixASN = 4837
		case in("223.120.0.0/16"):
			prefixASN = 58453
		case in("221.176.0.0/16"):
			prefixASN = 9808
		}
		if prefixASN != 0 && h.ASN != 0 && prefixASN != h.ASN {
			return "unknown"
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
		if h.ASN == 58807 {
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
		telecom = "mixed"
	case cn2:
		telecom = "cn2"
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
	case "cn2":
		return "cn2"
	case "cn2gia", "gia":
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

// comparableClass identifies observed backbone classes, not commercial grades.
func comparableClass(class string) bool {
	switch class {
	case "ct163", "cu9929", "cu10099", "cu4837", "cmin2", "cmi", "cm_normal":
		return true
	}
	return false
}

// ClaimMismatch compares only recognized, comparable backbone classes.
// Product grades (including GIA/GT) cannot be verified from these hops alone.
func ClaimMismatch(claimed, class string) bool {
	c := NormalizeClaim(claimed)
	return comparableClass(c) && comparableClass(class) && c != class
}

// Claims apply to their carrier, not every unrelated carrier in the batch.
func claimCarrier(class string) string {
	switch class {
	case "ct163":
		return "ct"
	case "cu9929", "cu10099", "cu4837":
		return "cu"
	case "cmin2", "cmi", "cm_normal":
		return "cm"
	}
	return ""
}

func reliable(p Path) bool {
	if p.Error != "" || !comparableClass(p.RouteClass) || len(p.Hops) == 0 || Classify(p.Hops) != p.RouteClass {
		return false
	}
	for _, h := range p.Hops {
		if _, err := netip.ParseAddr(h.IP); err != nil {
			return false
		}
	}
	return true
}

// Assess retains observations while withholding conclusions if any path is
// missing, failed, ambiguous or unknown. A false mismatch is not a verified match.
func Assess(paths []Path, claimed string) (string, bool, string) {
	parts := make([]string, 0, len(paths))
	known := 0
	for _, p := range paths {
		part := p.Carrier + "=" + p.RouteClass
		if p.Error != "" {
			part += " (" + p.Error + ")"
		}
		parts = append(parts, part)
		if reliable(p) {
			known++
		}
	}
	s := strings.Join(parts, ", ")
	if len(paths) == 0 {
		s = "no path"
	}
	verdict := "ok"
	if known == 0 {
		verdict = "abstain"
	} else if known != len(paths) {
		verdict = "ok_with_caveats"
	}
	if verdict != "ok" {
		s += "; insufficient route evidence"
	}
	mismatch := false
	if c := NormalizeClaim(claimed); c != "" {
		if verdict != "ok" || !comparableClass(c) {
			s += "; claim " + c + " unverified"
			if verdict == "ok" {
				verdict = "ok_with_caveats"
			}
		} else {
			compared := 0
			for _, p := range paths {
				if p.Carrier != "" && p.Carrier != claimCarrier(c) {
					continue
				}
				compared++
				mismatch = mismatch || ClaimMismatch(c, p.RouteClass)
			}
			if compared == 0 {
				s += "; claim " + c + " unverified (no relevant carrier)"
				verdict = "ok_with_caveats"
			} else if mismatch {
				s += "; claim " + c + " does not match observed backbones"
				verdict = "risky"
			} else {
				s += "; claim " + c + " matches observed backbones"
			}
		}
	}
	return s, mismatch, verdict
}

// Summarize builds an evidence-gated one-line description.
func Summarize(paths []Path, claimed string) (string, bool) {
	s, mismatch, _ := Assess(paths, claimed)
	return s, mismatch
}
