package score

import (
	"strings"

	"ipd/internal/lookup"
	"ipd/internal/version"
)

// Product thresholds. A residential call needs more than one independent
// evidence family. Below minDecideConfidence the result is "cannot determine".
const (
	minDecideConfidence = 0.70
	cannotDetermine     = "cannot determine"
)

// ClassifyObserved is the product classifier. It abstains unless the evidence
// is real: rDNS, prefix age, neighbour signals, and RIR org type, or a
// published enumeration such as a cloud range or a Tor exit list.
func ClassifyObserved(p lookup.Profile, comp lookup.PrefixComposition, features map[string]float64) Class {
	if features == nil {
		features = map[string]float64{}
	}
	base := FeaturesFromProfile(p)
	for k, v := range base {
		if _, ok := features[k]; !ok {
			features[k] = v
		}
	}
	applyEvidence(features, p, comp)
	c := ClassifyResidential(features)
	if !supported(p, features, c) {
		return cannot(c)
	}
	if c.Class == "abstain" || c.Abstained || c.Confidence < minDecideConfidence {
		return cannot(c)
	}
	return c
}

func cannot(prev Class) Class {
	ev := []string{"cannot determine"}
	if prev.Prob > 0 && prev.Prob < minDecideConfidence {
		ev = append(ev, "confidence below threshold")
	}
	return Class{
		Class:        cannotDetermine,
		Prob:         prev.Prob,
		TopFeatures:  prev.TopFeatures,
		Confidence:   prev.Confidence,
		Evidence:     ev,
		ModelVersion: version.ModelResidential,
		Abstained:    true,
	}
}

func applyEvidence(f map[string]float64, p lookup.Profile, comp lookup.PrefixComposition) {
	if p.PrefixAgeDays > 0 {
		v := float64(p.PrefixAgeDays) / 3650
		if v > 1 {
			v = 1
		}
		f["prefix_age"] = v
		if p.PrefixAgeDays < 180 {
			f["prefix_young"] = 1
		}
	}
	if comp.Contamination >= 0.5 {
		f["neighbor_hostile"] = 1
	}
	for _, n := range comp.Notable {
		if strings.Contains(n, "proxy") || strings.Contains(n, "tor") || strings.Contains(n, "vpn") {
			f["neighbor_ports"] = 1
		}
	}
	blob := strings.ToUpper(p.Descr + " " + p.NetName + " " + p.Org)
	if containsAny(blob, "BROADBAND", "DYNAMIC", "PPPOE", "FTTH", "POOL", "CABLE", "DSL", "RESIDENTIAL") {
		f["rir_access"] = 1
		f["keyword_broadband"] = 1
	}
	if containsAny(blob, "MOBILE", "WIRELESS", "CELLULAR") {
		f["rir_mobile"] = 1
	}
	if containsAny(blob, "HOSTING", "DATACENTER", "DATA CENTER", "IDC", "SERVER") {
		f["rir_hosting"] = 1
		f["keyword_idc"] = 1
	}
	if containsAny(blob, "ENTERPRISE", "BUSINESS", "CORP") {
		f["rir_business"] = 1
	}
	if p.Anycast {
		f["anycast"] = 1
		f["as_cdn"] = 1
	}
}

func supported(p lookup.Profile, f map[string]float64, c Class) bool {
	switch c.Class {
	case "", "abstain":
		return false
	case "hosting":
		if f["cloud_hit"] > 0 || f["tor"] > 0 {
			return true
		}
		return f["as_hosting"] > 0 && (f["keyword_idc"] > 0 || f["rir_hosting"] > 0 || f["neighbor_hostile"] > 0 || f["neighbor_ports"] > 0)
	case "cdn_anycast":
		return f["as_cdn"] > 0 || f["anycast"] > 0 || p.Anycast
	case "residential_fixed":
		return f["rdns_dynamic"] > 0 && f["as_cable"]+f["as_dsl"]+f["as_isp"]+f["keyword_broadband"]+f["rir_access"] > 0 && f["announcer_hosting"] == 0 && f["upstream_hosting"] == 0
	case "residential_mobile":
		return f["as_mobile"] > 0 && (f["rir_mobile"] > 0 || f["eyeball"] > 0 || rdnsMobile(p.RDNS))
	case "isp_static":
		strong := f["announcer_hosting"] > 0 || f["upstream_hosting"] > 0 || f["rtt_colo"] > 0 || (f["rdns_missing"] > 0 && f["prefix_young"] > 0)
		return c.SuspectedFakeResidential && strong && f["as_cable"]+f["as_dsl"]+f["as_isp"]+f["keyword_broadband"]+f["rir_access"] > 0
	case "business":
		return f["as_business"] > 0 && (f["rir_business"] > 0 || evidenceFamilies(f) >= 2)
	default:
		return c.Confidence >= minDecideConfidence && evidenceFamilies(f) >= 2
	}
}

func evidenceFamilies(f map[string]float64) int {
	n := 0
	if f["rdns_dynamic"] > 0 {
		n++
	}
	if f["prefix_age"] > 0 || f["prefix_young"] > 0 {
		n++
	}
	if f["neighbor_hostile"] > 0 || f["neighbor_ports"] > 0 {
		n++
	}
	if f["rir_access"] > 0 || f["rir_mobile"] > 0 || f["rir_hosting"] > 0 || f["rir_business"] > 0 || f["keyword_broadband"] > 0 {
		n++
	}
	if f["as_cable"]+f["as_dsl"]+f["as_isp"]+f["as_mobile"]+f["as_business"]+f["as_hosting"]+f["as_cdn"] > 0 {
		n++
	}
	if f["cloud_hit"] > 0 || f["tor"] > 0 || f["anycast"] > 0 {
		n++
	}
	return n
}

func rdnsMobile(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, "mobile") || strings.Contains(l, "wireless") || strings.Contains(l, "lte")
}
