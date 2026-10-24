package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"ipd/internal/lookup"
	"ipd/internal/probe"
	"ipd/internal/route"
)

func TestRouteForwardEvidence(t *testing.T) {
	reached := true
	known := probe.Sample{DestinationReached: &reached, Network: "ct", City: "fixture", Healthy: true, ICMP: "ok", Hops: []probe.Hop{{IP: "203.0.113.1", ASN: 4134, RTTMS: 12}}}
	failed := known
	failed.Error = "probe failed"
	timeout := known
	timeout.ICMP = "timeout"
	unhealthy := known
	unhealthy.Healthy = false
	incomplete := known
	incomplete.DestinationReached = nil
	stopped := known
	notReached := false
	stopped.DestinationReached = &notReached
	cn2 := known
	cn2.Hops = []probe.Hop{{IP: "203.0.113.1", ASN: 4809}}
	unknown := known
	unknown.Hops = []probe.Hop{{IP: "203.0.113.2", RTTMS: 15}}
	for _, tc := range []struct {
		name    string
		samples []probe.Sample
		err     error
		verdict string
	}{
		{"empty", nil, nil, "abstain"},
		{"control only", []probe.Sample{{Network: "control"}}, nil, "abstain"},
		{"unknown", []probe.Sample{unknown}, nil, "abstain"},
		{"unknown completion", []probe.Sample{incomplete}, nil, "abstain"},
		{"stopped", []probe.Sample{stopped}, nil, "abstain"},
		{"partial completion", []probe.Sample{known, stopped}, nil, "ok_with_caveats"},
		{"timeout", []probe.Sample{timeout}, nil, "abstain"},
		{"unhealthy", []probe.Sample{unhealthy}, nil, "abstain"},
		{"CN2 not GIA", []probe.Sample{cn2}, nil, "abstain"},
		{"no hops", []probe.Sample{{Network: "ct", Healthy: true}}, nil, "abstain"},
		{"partial", []probe.Sample{known, failed}, nil, "ok_with_caveats"},
		{"failed", []probe.Sample{failed}, nil, "abstain"},
		{"provider error with evidence", []probe.Sample{known}, errors.New("provider failed"), "ok_with_caveats"},
		{"provider failure", nil, errors.New("provider failed"), "abstain"},
		{"known", []probe.Sample{known}, nil, "ok"},
		{"missing carriers", []probe.Sample{known}, nil, "ok_with_caveats"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Service{Look: lookup.New()}
			s.Tracer = func(context.Context, string) ([]route.Hop, error) {
				t.Fatal("forward used local return tracer")
				return nil, nil
			}
			carriers := []string{"ct"}
			if tc.name == "missing carriers" {
				carriers = nil
			}
			s.Vantage = probe.Globalping{Runner: func(_ context.Context, q probe.Query) ([]probe.Sample, error) {
				if q.Kind != probe.KindTrace || q.Target != "192.0.2.1" || !reflect.DeepEqual(q.Carriers, carriers) {
					t.Fatalf("query %+v", q)
				}
				return tc.samples, tc.err
			}}
			rep, err := s.RouteForward(context.Background(), "192.0.2.1", carriers)
			if err != nil || rep.Verdict != tc.verdict {
				t.Fatalf("report %+v err %v", rep, err)
			}
			result := rep.Data.(route.Result)
			if result.Direction != "forward" {
				t.Fatalf("direction %q", result.Direction)
			}
			if len(tc.samples) > 0 && tc.samples[0].Network != "control" && !reflect.DeepEqual(result.Paths[0].Hops, s.annotate(tc.samples[0].Hops)) {
				t.Fatalf("lost hops: %+v", result)
			}
			if !reflect.DeepEqual(rep.Sources[0].Raw, tc.samples) {
				t.Fatal("lost measurement evidence")
			}
			if tc.err != nil && !strings.Contains(result.Error, tc.err.Error()) {
				t.Fatal("lost provider error")
			}
			if tc.name == "failed" && result.Paths[0].Error != failed.Error {
				t.Fatal("lost sample error")
			}
		})
	}
}

func TestRouteReturnEvidence(t *testing.T) {
	known := []route.Hop{{IP: "203.0.113.1", ASN: 4134, RTTMS: 17}}
	unknown := []route.Hop{{IP: "203.0.113.2", RDNS: "cn2-gia.example.invalid", RTTMS: 20}}
	for _, tc := range []struct {
		name       string
		hops       []route.Hop
		err        error
		firstKnown bool
		verdict    string
		mismatch   bool
	}{
		{name: "empty", verdict: "abstain"},
		{name: "unknown", hops: unknown, verdict: "abstain"},
		{name: "CN2 not GIA", hops: []route.Hop{{IP: "203.0.113.1", ASN: 4809}}, verdict: "abstain"},
		{name: "all failed", hops: known, err: errors.New("trace failed"), verdict: "abstain"},
		{name: "partial failed", hops: known, err: errors.New("trace failed"), firstKnown: true, verdict: "ok_with_caveats"},
		{name: "partial unknown", hops: unknown, firstKnown: true, verdict: "ok_with_caveats"},
		{name: "known mismatch", hops: known, verdict: "risky", mismatch: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Service{}
			calls := 0
			targets := route.Targets("core")
			s.Vantage = probe.Globalping{Runner: func(context.Context, probe.Query) ([]probe.Sample, error) {
				t.Fatal("return used forward provider")
				return nil, nil
			}}
			s.Tracer = func(_ context.Context, target string) ([]route.Hop, error) {
				if calls >= len(targets) || target != targets[calls].IP {
					t.Fatalf("wrong return target %s", target)
				}
				calls++
				if tc.firstKnown && calls == 1 {
					return known, nil
				}
				return tc.hops, tc.err
			}
			rep, err := s.RouteReturn(context.Background(), "core", "cu9929")
			if err != nil || rep.Verdict != tc.verdict {
				t.Fatalf("report %+v err %v", rep, err)
			}
			result := rep.Data.(route.Result)
			if calls != len(targets) || len(result.Paths) != calls || result.Direction != "return" || result.ClaimMismatch != tc.mismatch {
				t.Fatalf("result %+v calls %d", result, calls)
			}
			for i, p := range result.Paths {
				want := tc.hops
				if tc.firstKnown && i == 0 {
					want = known
				}
				if !reflect.DeepEqual(p.Hops, want) {
					t.Fatalf("lost hops %+v", p)
				}
				if tc.err != nil && !(tc.firstKnown && i == 0) && p.Error != tc.err.Error() {
					t.Fatalf("lost trace error %+v", p)
				}
			}
			if !tc.mismatch && (strings.Contains(rep.Summary, "does not match") || strings.Contains(rep.Summary, " matches")) {
				t.Fatal(rep.Summary)
			}
		})
	}
}

func TestClassifyPathEvidence(t *testing.T) {
	s := &Service{}
	for _, tc := range []struct {
		name             string
		hops             []route.Hop
		claimed, verdict string
		mismatch         bool
	}{
		{name: "empty", claimed: "gia", verdict: "abstain"},
		{name: "unknown", hops: []route.Hop{{IP: "203.0.113.1", RDNS: "cn2-gia.example.invalid"}}, claimed: "gia", verdict: "abstain"},
		{name: "single CN2", hops: []route.Hop{{IP: "203.0.113.1", ASN: 4809}}, claimed: "gia", verdict: "abstain"},
		{name: "missing hop", hops: []route.Hop{{IP: "*"}, {IP: "203.0.113.1", ASN: 4134}}, claimed: "gia", verdict: "abstain"},
		{name: "known match", hops: []route.Hop{{IP: "203.0.113.1", ASN: 4134}}, claimed: "ct163", verdict: "ok"},
		{name: "known mismatch", hops: []route.Hop{{IP: "203.0.113.1", ASN: 4134}}, claimed: "cu9929", verdict: "risky", mismatch: true},
		{name: "unknown claim", hops: []route.Hop{{IP: "203.0.113.1", ASN: 4134}}, claimed: "premium", verdict: "ok_with_caveats"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := s.ClassifyPath(tc.hops, tc.claimed)
			result := rep.Data.(route.Result)
			if rep.Verdict != tc.verdict || result.ClaimMismatch != tc.mismatch || !reflect.DeepEqual(result.Paths[0].Hops, tc.hops) {
				t.Fatalf("%+v %+v", rep, result)
			}
		})
	}
}

func TestAnnotatePreservesConflictingASN(t *testing.T) {
	s := &Service{Look: lookup.New()}
	got := s.annotate([]probe.Hop{{IP: "1.1.1.1", ASN: 4134, RTTMS: 12}})
	if got[0].ASN != 4134 || got[0].LookupASN != 13335 || got[0].RTTMS != 12 {
		t.Fatalf("%+v", got)
	}
	if rep := s.ClassifyPath(got, "cu9929"); rep.Verdict != "abstain" || rep.Data.(route.Result).ClaimMismatch {
		t.Fatalf("%+v", rep)
	}
}

func TestRouteUnavailableAndCanceled(t *testing.T) {
	s := &Service{}
	if rep, err := s.RouteForward(context.Background(), "192.0.2.1", nil); err != nil || rep.Verdict != "abstain" {
		t.Fatalf("%+v %v", rep, err)
	}
	if rep, err := s.RouteReturn(context.Background(), "core", "gia"); err != nil || rep.Verdict != "abstain" || rep.Data.(route.Result).ClaimMismatch {
		t.Fatalf("%+v %v", rep, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.Tracer = func(context.Context, string) ([]route.Hop, error) { t.Fatal("called canceled tracer"); return nil, nil }
	rep, err := s.RouteReturn(ctx, "core", "ct163")
	if err != nil || rep.Verdict != "abstain" {
		t.Fatalf("%+v %v", rep, err)
	}
	for _, p := range rep.Data.(route.Result).Paths {
		if p.Error != context.Canceled.Error() {
			t.Fatalf("lost cancellation %+v", p)
		}
	}
	s.Vantage = probe.Globalping{Runner: func(context.Context, probe.Query) ([]probe.Sample, error) {
		reached := true
		return []probe.Sample{{DestinationReached: &reached, Network: "ct", Healthy: true, Hops: []probe.Hop{{IP: "203.0.113.1", ASN: 4134}}}}, nil
	}}
	rep, err = s.RouteForward(ctx, "192.0.2.1", []string{"ct"})
	if err != nil || rep.Verdict != "ok_with_caveats" || rep.Data.(route.Result).Error != context.Canceled.Error() {
		t.Fatalf("%+v %v", rep, err)
	}
}

func TestRouteReturnKnownClaimMatch(t *testing.T) {
	s := &Service{Tracer: func(context.Context, string) ([]route.Hop, error) {
		return []route.Hop{{IP: "203.0.113.1", ASN: 9929, RTTMS: 17}}, nil
	}}
	rep, err := s.RouteReturn(context.Background(), "core", "cu9929")
	if err != nil || rep.Verdict != "ok" || rep.Data.(route.Result).ClaimMismatch || !strings.Contains(rep.Summary, "matches observed backbones") {
		t.Fatalf("%+v %v", rep, err)
	}
}

func TestRouteForwardGlobalpingCompletion(t *testing.T) {
	for _, tc := range []struct{ name, result, verdict string }{
		{"early stop", `{"status":"finished","resolvedAddress":"192.0.2.1","hops":[{"resolvedAddress":"203.0.113.1","asn":4134,"timings":[{"rtt":12}]}]}`, "abstain"},
		{"reached", `{"status":"finished","resolvedAddress":"192.0.2.1","hops":[{"resolvedAddress":"192.0.2.1","asn":4134,"timings":[{"rtt":12}]}]}`, "ok"},
		{"unknown destination", `{"status":"finished","hops":[{"resolvedAddress":"203.0.113.1","asn":4134,"timings":[{"rtt":12}]}]}`, "abstain"},
		{"no destination reply", `{"status":"finished","resolvedAddress":"192.0.2.1","hops":[{"resolvedAddress":"192.0.2.1","asn":4134,"timings":[]}]}`, "abstain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					fmt.Fprint(w, `{"id":"fixture"}`)
					return
				}
				fmt.Fprintf(w, `{"status":"finished","results":[{"probe":{"asn":4134,"city":"completion-fixture","country":"CN"},"result":%s}]}`, tc.result)
			}))
			defer srv.Close()
			s := &Service{Vantage: probe.Globalping{BaseURL: srv.URL, Client: srv.Client(), MinInterval: -1}}
			rep, err := s.RouteForward(context.Background(), "target.example.invalid", []string{"ct"})
			if err != nil || rep.Verdict != tc.verdict {
				t.Fatalf("%+v err %v", rep, err)
			}
			result := rep.Data.(route.Result)
			if len(result.Paths) != 1 || len(result.Paths[0].Hops) != 1 || (tc.name != "no destination reply" && result.Paths[0].Hops[0].RTTMS != 12) {
				t.Fatalf("lost evidence %+v", result)
			}
			measurement := rep.Sources[0].Raw.([]probe.Sample)[0]
			if !reflect.DeepEqual(result.Paths[0].DestinationReached, measurement.DestinationReached) {
				t.Fatal("lost completion evidence")
			}
			if tc.verdict == "ok" && (measurement.DestinationReached == nil || !*measurement.DestinationReached) {
				t.Fatal("missing reached evidence")
			}
			if tc.verdict != "ok" && (result.Paths[0].Error == "" || result.ClaimMismatch) {
				t.Fatalf("missing completion caveat %+v", result)
			}
		})
	}
}
