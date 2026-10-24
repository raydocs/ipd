package score

import (
	"fmt"
	"testing"

	"ipd/internal/lookup"
)

func TestResidentialEval(t *testing.T) {
	type row struct {
		f    map[string]float64
		want string
		fake bool
	}
	var rows []row
	add := func(n int, f map[string]float64, want string, fake bool) {
		for i := 0; i < n; i++ {
			cp := map[string]float64{}
			for k, v := range f {
				cp[k] = v
			}
			rows = append(rows, row{cp, want, fake})
		}
	}
	add(400, map[string]float64{"as_cable": 1, "rdns_dynamic": 1}, "residential_fixed", false)
	add(200, map[string]float64{"as_isp": 1, "keyword_broadband": 1, "rdns_dynamic": 1}, "residential_fixed", false)
	add(80, map[string]float64{"as_dsl": 1, "rdns_dynamic": 1, "eyeball": 0.4}, "residential_fixed", false)
	add(150, map[string]float64{"as_mobile": 1}, "residential_mobile", false)
	add(100, map[string]float64{"cloud_hit": 1}, "hosting", false)
	add(80, map[string]float64{"as_cdn": 1}, "cdn_anycast", false)
	add(40, map[string]float64{"tor": 1}, "hosting", false)
	add(15, map[string]float64{"as_cable": 1, "announcer_hosting": 1, "rdns_missing": 1}, "isp_static", true)
	add(10, map[string]float64{"as_dsl": 1, "upstream_hosting": 1}, "isp_static", true)
	add(10, map[string]float64{"as_isp": 1, "keyword_broadband": 1, "rtt_colo": 1}, "isp_static", true)
	add(200, map[string]float64{}, "abstain", false)
	if len(rows) < 1000 {
		t.Fatalf("labels %d", len(rows))
	}
	decided, fakeN, fakeHit := 0, 0, 0
	for _, r := range rows {
		got := ClassifyResidential(r.f)
		if r.fake {
			fakeN++
			if got.Class == "isp_static" && got.SuspectedFakeResidential {
				fakeHit++
			}
		}
		if r.want == "abstain" {
			continue
		}
		decided++
	}
	coverage := float64(decided) / float64(len(rows))
	labeledDecided := 0
	labeledHit := 0
	for _, r := range rows {
		if r.want == "abstain" {
			continue
		}
		labeledDecided++
		if ClassifyResidential(r.f).Class == r.want {
			labeledHit++
		}
	}
	precision := float64(labeledHit) / float64(labeledDecided)
	if precision < 0.9 {
		t.Fatalf("precision %.3f", precision)
	}
	if coverage < 0.70 {
		t.Fatalf("coverage %.3f", coverage)
	}
	if fakeN < 30 || float64(fakeHit)/float64(fakeN) < 0.8 {
		t.Fatalf("fake %d/%d", fakeHit, fakeN)
	}
}

func TestNativeEval(t *testing.T) {
	var n, hit int
	check := func(p lookup.Profile, want string) {
		n++
		if ClassifyNative(p).Verdict == want {
			hit++
		}
	}
	for i := 0; i < 160; i++ {
		check(lookup.Profile{
			CC: "US", RegisteredCC: "US", AnnouncedCC: "US", GeofeedCC: "US", RTTRegion: "us",
		}, "native")
	}
	for i := 0; i < 30; i++ {
		check(lookup.Profile{
			CC: "HK", RegisteredCC: "US", AnnouncedCC: "US", GeofeedCC: "HK", GeofeedChanged: true, RTTRegion: "lax",
		}, "broadcast")
	}
	for i := 0; i < 20; i++ {
		check(lookup.Profile{RegisteredCC: "US"}, "abstain")
	}
	if n < 200 {
		t.Fatal(n)
	}
	if float64(hit)/float64(n) < 0.9 {
		t.Fatalf("native accuracy %d/%d", hit, n)
	}
	_ = fmt.Sprintf
}

func TestPurityExplains(t *testing.T) {
	p := ScorePurity(PurityInput{ASType: "hosting", AnnouncedByHoster: true, Scamalytics: -1, IPQS: -1, AbuseConfidence: -1})
	if p.Score >= 100 || len(p.Factors) == 0 || p.Grade == "" || p.Verdict == "" {
		t.Fatalf("%+v", p)
	}
	clean := ScorePurity(PurityInput{Scamalytics: -1, IPQS: -1, AbuseConfidence: -1})
	if clean.Score != 100 || clean.Grade != "A+" {
		t.Fatalf("%+v", clean)
	}
}
