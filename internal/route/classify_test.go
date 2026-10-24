package route

import (
	"strings"
	"testing"
)

func hops(asns ...int) []Hop {
	out := make([]Hop, len(asns))
	for i, a := range asns {
		out[i] = Hop{IP: "203.0.113.1", ASN: a, RTTMS: float64(10 + i)}
	}
	return out
}

func TestRouteClasses(t *testing.T) {
	cases := []struct {
		name  string
		paths [][]Hop
		want  string
	}{
		{"cn2", [][]Hop{hops(4809), hops(6939, 4809), hops(4809, 4809)}, "cn2"},
		{"cn2_and_163", [][]Hop{hops(4809, 4134), hops(4134, 4809), hops(4809, 4134, 4134)}, "mixed"},
		{"ct163", [][]Hop{hops(4134), hops(4134, 4134), hops(1299, 4134)}, "ct163"},
		{"cu9929", [][]Hop{hops(9929), hops(9929, 4837), hops(174, 9929)}, "cu9929"},
		{"cu10099", [][]Hop{hops(10099), hops(10099, 10099), hops(1299, 10099)}, "cu10099"},
		{"cu4837", [][]Hop{hops(4837), hops(4837, 4837), hops(3356, 4837)}, "cu4837"},
		{"cmin2", [][]Hop{hops(58807), hops(58807, 9808), hops(174, 58807)}, "cmin2"},
		{"cmi", [][]Hop{hops(58453), hops(58453, 58453), hops(1299, 58453)}, "cmi"},
		{"cm_normal", [][]Hop{hops(9808), hops(9808, 9808), hops(9808, 64500)}, "cm_normal"},
		{"mixed", [][]Hop{hops(4809, 9929), hops(4134, 58807), hops(10099, 58453)}, "mixed"},
		{"unknown", [][]Hop{hops(64500), hops(15169), hops(13335)}, "unknown"},
	}
	for _, tc := range cases {
		if len(tc.paths) < 3 {
			t.Fatal(tc.name)
		}
		for i, p := range tc.paths {
			// cm_normal with 58453 first is cmi+cm → mixed. Keep the third path pure.
			got := Classify(p)
			if got != tc.want {
				t.Fatalf("%s path %d: got %s want %s", tc.name, i, got, tc.want)
			}
		}
	}
	if !ClaimMismatch("cu9929", "cu4837") {
		t.Fatal("known backbone mismatch")
	}
	if ClaimMismatch("CN2-GIA", "cn2_gia") {
		t.Fatal("normalized claim should match")
	}
	if len(Targets("core")) < 3 {
		t.Fatal("core targets")
	}
}

func TestConservativeEvidence(t *testing.T) {
	for _, tc := range []struct {
		name string
		hops []Hop
		want string
	}{
		{"empty", nil, "unknown"},
		{"timeout ASN", []Hop{{IP: "*", ASN: 4809}}, "unknown"},
		{"hostname ASN", []Hop{{IP: "cn2-gia.example.invalid", ASN: 4809}}, "unknown"},
		{"rDNS only", []Hop{{IP: "203.0.113.1", RDNS: "cn2-gia.example.invalid"}}, "unknown"},
		{"CN2 ASN", hops(4809), "cn2"},
		{"CN2 prefix", []Hop{{IP: "59.43.0.1"}}, "cn2"},
		{"CN2 repeated", hops(4809, 4809), "cn2"},
		{"CN2 plus 163", hops(4809, 4134), "mixed"},
		{"prefix ASN conflict", []Hop{{IP: "59.43.0.1", ASN: 4134}}, "unknown"},
		{"annotation conflict", []Hop{{IP: "203.0.113.1", ASN: 4134, LookupASN: 13335}}, "unknown"},
		{"ambiguous mobile prefix", []Hop{{IP: "223.118.0.1"}}, "unknown"},
		{"known ASN", hops(4134), "ct163"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.hops); got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
	for _, class := range []string{"unknown", "mixed", "cn2", "cn2_gia", "cn2_gt", ""} {
		if ClaimMismatch("ct163", class) {
			t.Fatalf("unsupported class %q treated as mismatch", class)
		}
	}
	for _, claim := range []string{"gia", "gt", "premium", "cn2"} {
		if ClaimMismatch(claim, "ct163") {
			t.Fatalf("unverifiable claim %q treated as mismatch", claim)
		}
	}
	if NormalizeClaim("cn2") == NormalizeClaim("gia") {
		t.Fatal("CN2 family conflated with GIA grade")
	}
}

func TestAssessInsufficientEvidence(t *testing.T) {
	known := Path{Carrier: "ct", Hops: hops(4134), RouteClass: "ct163"}
	failed := known
	failed.Error = "fixture trace failed"
	for _, tc := range []struct {
		name  string
		paths []Path
		want  string
	}{
		{"none", nil, "abstain"},
		{"unknown", []Path{{RouteClass: "unknown", Hops: hops(64500)}}, "abstain"},
		{"failed", []Path{failed}, "abstain"},
		{"partial", []Path{known, failed}, "ok_with_caveats"},
		{"empty classified path", []Path{{RouteClass: "ct163"}}, "abstain"},
		{"forged classification", []Path{{RouteClass: "ct163", Hops: hops(64500)}}, "abstain"},
		{"mixed", []Path{{RouteClass: "mixed", Hops: hops(4134, 9929)}}, "abstain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			summary, mismatch, verdict := Assess(tc.paths, "cu9929")
			if mismatch || verdict != tc.want || !strings.Contains(summary, "unverified") {
				t.Fatalf("%s mismatch=%v verdict=%s", summary, mismatch, verdict)
			}
			if sum, mismatch := Summarize(tc.paths, "cu9929"); sum != summary || mismatch {
				t.Fatal("Summarize bypassed evidence gate")
			}
		})
	}
}

func TestAssessClaimCarrierScope(t *testing.T) {
	paths := []Path{
		{Carrier: "ct", RouteClass: "ct163", Hops: hops(4134)},
		{Carrier: "cu", RouteClass: "cu9929", Hops: hops(9929)},
		{Carrier: "cm", RouteClass: "cmi", Hops: hops(58453)},
	}
	if sum, mismatch, v := Assess(paths, "cu9929"); mismatch || v != "ok" {
		t.Fatalf("%s %v %s", sum, mismatch, v)
	}
	if sum, mismatch, v := Assess(paths[:1], "cu9929"); mismatch || v != "ok_with_caveats" {
		t.Fatalf("%s %v %s", sum, mismatch, v)
	}
	if sum, mismatch, v := Assess(paths, "cu4837"); !mismatch || v != "risky" {
		t.Fatalf("%s %v %s", sum, mismatch, v)
	}
}
