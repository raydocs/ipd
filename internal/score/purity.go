package score

import (
	"math"
	"sort"

	"gopkg.in/yaml.v3"
	"ipd/internal/version"
	"ipd/models"
)

// Factor is one explained deduction.
type Factor struct {
	ID       string   `json:"id"`
	Delta    int      `json:"delta"`
	Evidence []string `json:"evidence"`
	Sources  []string `json:"sources"`
}

// Purity is the explained 0-100 score.
type Purity struct {
	Score        int      `json:"score"`
	Grade        string   `json:"grade"`
	Verdict      string   `json:"verdict"`
	Factors      []Factor `json:"factors"`
	Confidence   float64  `json:"confidence"`
	ModelVersion string   `json:"model_version"`
}

// PurityInput is everything the purity model is allowed to see.
type PurityInput struct {
	ASType                string
	Cloud                 string
	Flags                 []string
	Disagreement          bool
	LocationInconsistent  bool
	NeighborContamination float64
	AnnouncedByHoster     bool
	Scamalytics           int // 0-100, negative means unknown
	IPQS                  int
	AbuseConfidence       int
	DNSBLHits             int
	ProxyListSources      int
	Captcha               bool
	CFChallenge           bool
	Akamai                bool
	AIUnavailable         bool
}

type weights struct {
	ModelVersion string         `yaml:"model_version"`
	Start        int            `yaml:"start"`
	Grades       map[string]int `yaml:"grades"`
	Verdicts     map[string]int `yaml:"verdicts"`
	Factors      map[string]int `yaml:"factors"`
}

var purityWeights weights

func init() {
	if err := yaml.Unmarshal(models.PurityYAML, &purityWeights); err != nil {
		panic("purity.yaml: " + err.Error())
	}
	if purityWeights.Start == 0 {
		purityWeights.Start = 100
	}
}

// ScorePurity applies the published weights. Unknown online signals are skipped,
// never invented.
func ScorePurity(in PurityInput) Purity {
	w := purityWeights
	score := w.Start
	var factors []Factor
	add := func(id string, delta int, evidence []string, sources []string) {
		if delta == 0 {
			return
		}
		factors = append(factors, Factor{ID: id, Delta: delta, Evidence: evidence, Sources: sources})
		score += delta
	}
	has := func(flag string) bool {
		for _, f := range in.Flags {
			if f == flag {
				return true
			}
		}
		return false
	}

	switch {
	case has("tor"):
		add("tor", w.Factors["tor"], []string{"tor exit list hit"}, []string{"tor_exits"})
	case has("vpn") || has("proxy"):
		add("vpn_or_proxy", w.Factors["vpn"], []string{"public VPN or proxy list hit"}, []string{"vpn_lists"})
	case in.Cloud != "" && (in.ASType == "cdn" || has("anycast") || in.Cloud == "cloudflare"):
		add("cdn", w.Factors["cdn"], []string{"cloud/anycast range: " + in.Cloud}, []string{"cloud_ranges"})
	case in.Cloud != "" || in.ASType == "hosting" || in.AnnouncedByHoster:
		ev := "asn type=hosting"
		if in.Cloud != "" {
			ev = "cloud range: " + in.Cloud
		}
		if in.AnnouncedByHoster && in.Cloud == "" && in.ASType != "hosting" {
			ev = "prefix is announced or upstreamed by a hosting AS"
		}
		add("hosting_asn", w.Factors["hosting"], []string{ev}, []string{"peeringdb", "cloud_ranges", "bgp"})
	case in.ASType == "business" || in.ASType == "enterprise":
		add("business_asn", w.Factors["business"], []string{"asn type=" + in.ASType}, []string{"peeringdb"})
	}

	if !has("vpn") && !has("proxy") && !has("tor") && in.ProxyListSources > 0 {
		delta := in.ProxyListSources * w.Factors["proxy_list_per_source"]
		capv := w.Factors["proxy_list_cap"]
		if delta < capv {
			delta = capv
		}
		add("public_proxy_list", delta, []string{"distinct public proxy sources"}, []string{"vpn_lists"})
	}
	if has("malicious") {
		add("malicious_list", w.Factors["malicious_list"], []string{"firehol/spamhaus/abuse.ch hit"}, []string{"firehol"})
	}
	if in.Scamalytics >= 0 {
		add("scamalytics", scamalyticsDelta(in.Scamalytics, w.Factors["scamalytics_cap"]), []string{"scamalytics score band"}, []string{"scamalytics"})
	}
	if in.IPQS >= 0 {
		delta := -int(math.Round(float64(in.IPQS) / 100.0 * float64(-w.Factors["ipqs_cap"])))
		if delta < w.Factors["ipqs_cap"] {
			delta = w.Factors["ipqs_cap"]
		}
		add("ipqs_fraud", delta, []string{"ipqs fraud_score"}, []string{"ipqs"})
	}
	if in.AbuseConfidence >= 0 {
		delta := -int(math.Round(float64(in.AbuseConfidence) / 100.0 * float64(-w.Factors["abuseipdb_cap"])))
		if delta < w.Factors["abuseipdb_cap"] {
			delta = w.Factors["abuseipdb_cap"]
		}
		add("abuseipdb", delta, []string{"abuseipdb confidence"}, []string{"abuseipdb"})
	}
	if in.DNSBLHits > 0 {
		delta := in.DNSBLHits * w.Factors["dnsbl_each"]
		if delta < w.Factors["dnsbl_cap"] {
			delta = w.Factors["dnsbl_cap"]
		}
		add("dnsbl", delta, []string{"dnsbl hits"}, []string{"dnsbl"})
	}
	if in.NeighborContamination > 0 {
		delta := -int(math.Round(in.NeighborContamination * float64(-w.Factors["neighbor_cap"])))
		add("prefix_contamination", delta, []string{"neighbouring prefix contamination"}, []string{"cloud_ranges", "vpn_lists", "tor_exits"})
	}
	if in.Captcha {
		add("google_captcha", w.Factors["google_captcha"], []string{"google unusual traffic"}, []string{"litmus"})
	}
	if in.CFChallenge {
		add("cloudflare_challenge", w.Factors["cloudflare_challenge"], []string{"cloudflare challenge"}, []string{"litmus"})
	}
	if in.Akamai {
		add("akamai_block", w.Factors["akamai"], []string{"akamai interstitial"}, []string{"litmus"})
	}
	if in.AIUnavailable {
		add("ai_unavailable", w.Factors["ai_unavailable"], []string{"an AI service refused this egress"}, []string{"unlock"})
	}
	if in.Disagreement {
		add("geo_disagreement", w.Factors["geo_disagreement"], []string{"geo sources disagree"}, []string{"local"})
	}
	if in.LocationInconsistent {
		add("location_inconsistent", w.Factors["location_inconsistent"], []string{"registry, announcement, and RTT disagree"}, []string{"rir_delegated", "bgp", "rtt_matrix"})
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	sort.Slice(factors, func(i, j int) bool { return factors[i].Delta < factors[j].Delta })
	conf := 0.55
	if in.ASType != "" {
		conf += 0.2
	}
	if in.Scamalytics >= 0 || in.IPQS >= 0 {
		conf += 0.15
	}
	if conf > 0.95 {
		conf = 0.95
	}
	return Purity{
		Score:        score,
		Grade:        Grade(score),
		Verdict:      purityVerdict(score),
		Factors:      factors,
		Confidence:   conf,
		ModelVersion: version.ModelPurity,
	}
}

func scamalyticsDelta(score, cap int) int {
	// cap is negative.
	var mag int
	switch {
	case score <= 10:
		mag = 0
	case score <= 25:
		mag = 5
	case score <= 50:
		mag = 10
	case score <= 80:
		mag = 18
	default:
		mag = -cap
	}
	if mag > -cap {
		mag = -cap
	}
	return -mag
}

// Grade maps a score onto the published scale. 78 is B+.
func Grade(score int) string {
	order := []string{"A+", "A", "A-", "B+", "B", "C", "D", "F"}
	for _, g := range order {
		if score >= purityWeights.Grades[g] {
			return g
		}
	}
	return "F"
}

func purityVerdict(score int) string {
	switch {
	case score >= purityWeights.Verdicts["ok"]:
		return "ok"
	case score >= purityWeights.Verdicts["ok_with_caveats"]:
		return "ok_with_caveats"
	case score >= purityWeights.Verdicts["risky"]:
		return "risky"
	default:
		return "bad"
	}
}
