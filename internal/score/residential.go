package score

import (
	"sort"
	"strings"

	"ipd/internal/lookup"
	"ipd/internal/version"
)

// Class is the residential classifier output.
type Class struct {
	Class                    string   `json:"class"`
	Prob                     float64  `json:"prob"`
	TopFeatures              []string `json:"top_features"`
	SuspectedFakeResidential bool     `json:"suspected_fake_residential"`
	Confidence               float64  `json:"confidence"`
	Evidence                 []string `json:"evidence"`
	ModelVersion             string   `json:"model_version"`
	Abstained                bool     `json:"abstained"`
}

const abstainThreshold = 0.55

var forest = loadForest()

// ClassifyResidential applies hard rules first and the published tree second.
// Confidence below the threshold yields class "abstain" ("无法判定").
func ClassifyResidential(features map[string]float64) Class {
	ev := []string{}
	decide := func(class string, conf float64, fake bool, evidence []string, feats []string) Class {
		return Class{
			Class:                    class,
			Prob:                     conf,
			TopFeatures:              feats,
			SuspectedFakeResidential: fake,
			Confidence:               conf,
			Evidence:                 evidence,
			ModelVersion:             version.ModelResidential,
			Abstained:                false,
		}
	}
	if features["cloud_hit"] > 0 && features["as_cdn"] == 0 {
		return decide("hosting", 0.97, false, []string{"cloud range ⇒ hosting"}, []string{"cloud_hit"})
	}
	if features["as_cdn"] > 0 || features["anycast"] > 0 {
		return decide("cdn_anycast", 0.93, false, []string{"anycast or content network"}, []string{"as_cdn"})
	}
	if features["tor"] > 0 {
		return decide("hosting", 0.9, false, []string{"tor exit"}, []string{"tor"})
	}
	if features["as_mobile"] > 0 && features["cloud_hit"] == 0 && features["announcer_hosting"] == 0 {
		return decide("residential_mobile", 0.9, false, []string{"mobile ASN"}, []string{"as_mobile"})
	}
	if fakeResidential(features) {
		return decide("isp_static", 0.86, true, fakeEvidence(features), []string{"announcer_hosting", "upstream_hosting", "rtt_colo", "rdns_missing"})
	}
	if clearResidential(features) {
		return decide("residential_fixed", 0.88, false, []string{"eyeball ISP, dynamic rDNS, announcer matches the access network"}, []string{"rdns_dynamic", "as_cable", "as_dsl", "as_isp"})
	}

	class, prob, _ := forest.predict(features)
	if prob < abstainThreshold || class == "" {
		return Class{
			Class:        "abstain",
			Prob:         prob,
			TopFeatures:  topContrib(features),
			Confidence:   prob,
			Evidence:     append(ev, "confidence below threshold; 无法判定"),
			ModelVersion: version.ModelResidential,
			Abstained:    true,
		}
	}
	return Class{
		Class:        class,
		Prob:         prob,
		TopFeatures:  topContrib(features),
		Confidence:   prob,
		Evidence:     []string{"gbdt vote"},
		ModelVersion: version.ModelResidential,
		Abstained:    false,
	}
}

func fakeResidential(f map[string]float64) bool {
	if !registeredResidential(f) {
		return false
	}
	return f["announcer_hosting"] > 0 || f["upstream_hosting"] > 0 || f["rtt_colo"] > 0 || f["rdns_missing"] > 0
}

func clearResidential(f map[string]float64) bool {
	if !registeredResidential(f) {
		return false
	}
	return f["rdns_dynamic"] > 0 && f["announcer_hosting"] == 0 && f["upstream_hosting"] == 0 && f["rtt_colo"] == 0 && f["rdns_missing"] == 0
}

func registeredResidential(f map[string]float64) bool {
	if f["cloud_hit"] > 0 || f["as_hosting"] > 0 || f["as_cdn"] > 0 {
		return false
	}
	return f["as_cable"]+f["as_dsl"]+f["as_isp"]+f["keyword_broadband"] > 0
}

func fakeEvidence(f map[string]float64) []string {
	var ev []string
	ev = append(ev, "registered as an access ISP")
	if f["announcer_hosting"] > 0 || f["upstream_hosting"] > 0 {
		ev = append(ev, "announcing AS or upstream is a hoster (dual ISP / prefix re-originated)")
	}
	if f["rtt_colo"] > 0 {
		ev = append(ev, "RTT colocated with a datacenter, not the claimed home")
	}
	if f["rdns_missing"] > 0 {
		ev = append(ev, "rDNS missing")
	}
	return ev
}

// FeaturesFromProfile builds the model matrix from a merged lookup.
func FeaturesFromProfile(p lookup.Profile) map[string]float64 {
	f := map[string]float64{}
	if p.Cloud != "" && p.Cloud != "cloudflare" {
		f["cloud_hit"] = 1
	}
	if p.Cloud == "cloudflare" || p.HasFlag("anycast") || p.ASType == "cdn" || p.ASType == "content" {
		f["as_cdn"] = 1
	}
	switch p.ASType {
	case "hosting":
		f["as_hosting"] = 1
	case "mobile":
		f["as_mobile"] = 1
	case "business", "enterprise":
		f["as_business"] = 1
	case "cable":
		f["as_cable"] = 1
	case "dsl":
		f["as_dsl"] = 1
	case "isp":
		f["as_isp"] = 1
	}
	if rdnsDynamic(p.RDNS) {
		f["rdns_dynamic"] = 1
	}
	if p.RDNS == "" || p.RDNS == "missing" {
		f["rdns_missing"] = 1
	}
	if p.UpstreamType == "hosting" {
		f["upstream_hosting"] = 1
		f["announcer_hosting"] = 1
	}
	if strings.HasSuffix(p.RTTRegion, "-colo") {
		f["rtt_colo"] = 1
	}
	blob := strings.ToUpper(p.Descr + " " + p.NetName)
	if containsAny(blob, "BROADBAND", "DYNAMIC", "PPPOE", "FTTH", "POOL") {
		f["keyword_broadband"] = 1
	}
	if containsAny(blob, "HOSTING", "IDC", "SERVER", "DATACENTER") {
		f["keyword_idc"] = 1
	}
	if len(p.Disagreements) > 0 {
		f["geo_disagree"] = 1
	}
	if p.HasFlag("vpn") || p.HasFlag("proxy") {
		f["vpn"] = 1
	}
	if p.HasFlag("tor") {
		f["tor"] = 1
	}
	if p.Eyeball > 0 {
		v := mathLog10(float64(p.Eyeball)) / 8
		if v > 1 {
			v = 1
		}
		f["eyeball"] = v
	}
	return f
}

func rdnsDynamic(s string) bool {
	if s == "" || s == "missing" {
		return false
	}
	l := strings.ToLower(s)
	for _, k := range []string{"dsl", "dhcp", "dyn", "pool", "ppp", "cable", "fttx", "ftth", "hsd", "customer", "dynamic"} {
		if strings.Contains(l, k) {
			return true
		}
	}
	return false
}

func containsAny(s string, keys ...string) bool {
	for _, k := range keys {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

func mathLog10(v float64) float64 {
	if v <= 0 {
		return 0
	}
	// log10 via change of base. Avoid importing math in two styles.
	return ln(v) / ln(10)
}

func ln(x float64) float64 {
	// delegate
	return logFn(x)
}

// topContrib lists the features whose removal changes the winning score the most.
func topContrib(features map[string]float64) []string {
	baseClass, baseProb, _ := forest.predict(features)
	type pair struct {
		k string
		d float64
	}
	var ps []pair
	for k, v := range features {
		if v == 0 {
			continue
		}
		cp := cloneFeat(features)
		cp[k] = 0
		cls, prob, _ := forest.predict(cp)
		delta := baseProb - prob
		if cls != baseClass {
			delta += 1
		}
		ps = append(ps, pair{k, delta})
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].d > ps[j].d })
	var out []string
	for i, p := range ps {
		if i == 5 {
			break
		}
		out = append(out, p.k)
	}
	return out
}

func cloneFeat(m map[string]float64) map[string]float64 {
	o := make(map[string]float64, len(m))
	for k, v := range m {
		o[k] = v
	}
	return o
}
