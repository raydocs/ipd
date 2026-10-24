package route

import "testing"

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
		{"cn2_gia", [][]Hop{hops(4809), hops(6939, 4809), hops(4809, 4809)}, "cn2_gia"},
		{"cn2_gt", [][]Hop{hops(4809, 4134), hops(4134, 4809), hops(4809, 4134, 4134)}, "cn2_gt"},
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
	if !ClaimMismatch("cn2gia", "ct163") {
		t.Fatal("claim")
	}
	if ClaimMismatch("CN2-GIA", "cn2_gia") {
		t.Fatal("normalized claim should match")
	}
	if len(Targets("core")) < 3 {
		t.Fatal("core targets")
	}
}
