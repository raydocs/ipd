package score

import (
	"encoding/json"
	"ipd/internal/unlock"
	"reflect"
	"testing"
	"time"
)

var scenarioClock = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

func scenarioFixture(service, status, evidence string) ScenarioObservation {
	at := scenarioClock.Add(-time.Hour)
	return ScenarioObservation{Source: "unlock", Result: unlock.Result{Service: service, Status: status, Evidence: evidence}, ObservedAt: &at}
}
func streamFixture() []ScenarioObservation {
	return []ScenarioObservation{scenarioFixture("netflix", "yes", "original=yes licensed=yes"), scenarioFixture("prime", "yes", "recognized positive marker")}
}

func TestScenarioCompleteAndIsolation(t *testing.T) {
	for _, tc := range []struct {
		status, evidence string
		want             int
	}{{"yes", "original=yes licensed=yes", 100}, {"originals_only", "original=yes licensed=no", 75}, {"no", "original=no licensed=no", 50}} {
		in := streamFixture()
		in[0].Result.Status = tc.status
		in[0].Result.Evidence = tc.evidence
		rows := AssessScenarios(scenarioClock, in)
		a := rows[2]
		if a.Score == nil || *a.Score != tc.want || a.Abstained || a.Coverage != 1 || a.Confidence != 1 {
			t.Fatalf("bad synthesis: %+v", a)
		}
		for _, i := range []int{0, 1, 3, 4} {
			if rows[i].Score != nil || !rows[i].Abstained {
				t.Fatal("cross scenario score", rows[i])
			}
		}
	}
	for i, spec := range scenarioSpecs[:3] {
		in := []ScenarioObservation{}
		for _, id := range spec.services {
			e := "recognized positive marker"
			if id == "chatgpt" {
				e = "web=yes app=yes"
			}
			if id == "netflix" {
				e = "original=yes licensed=yes"
			}
			in = append(in, scenarioFixture(id, "yes", e))
		}
		a := AssessScenarios(scenarioClock, in)[i]
		if a.Score == nil || *a.Score != 100 {
			t.Fatalf("complete scenario %s: %+v", spec.id, a)
		}
	}
}

func TestScenarioAbstention(t *testing.T) {
	for _, mode := range []string{"missing", "unknown_time", "zero_time", "future", "stale", "untrusted", "no_marker", "unknown_status", "conflict", "invalid_duplicate"} {
		t.Run(mode, func(t *testing.T) {
			in := streamFixture()
			switch mode {
			case "missing":
				in = in[:1]
			case "unknown_time":
				in[0].ObservedAt = nil
			case "zero_time":
				z := time.Time{}
				in[0].ObservedAt = &z
			case "future":
				z := scenarioClock.Add(time.Second)
				in[0].ObservedAt = &z
			case "stale":
				z := scenarioClock.Add(-24*time.Hour - time.Nanosecond)
				in[0].ObservedAt = &z
			case "untrusted":
				in[0].Source = "purity"
			case "no_marker":
				in[0].Result.Evidence = "no block marker"
			case "unknown_status":
				in[0].Result.Status = "future-status"
			case "conflict":
				in = append(in, scenarioFixture("netflix", "no", "original=no licensed=no"))
			case "invalid_duplicate":
				in = append(in, scenarioFixture("netflix", "yes", "no block marker"))
			}
			a := AssessScenarios(scenarioClock, in)[2]
			if a.Score != nil || !a.Abstained || a.Coverage != 0.5 || a.Confidence != 0.5 {
				t.Fatalf("unknown became score: %+v", a)
			}
		})
	}
	at := scenarioClock.Add(-24 * time.Hour)
	in := streamFixture()
	in[0].ObservedAt = &at
	if AssessScenarios(scenarioClock, in)[2].Score == nil {
		t.Fatal("inclusive freshness boundary rejected")
	}
	if AssessScenarios(time.Time{}, in)[2].Score != nil {
		t.Fatal("unknown assessment clock scored")
	}
}

func TestScenarioStableOrderingAndNull(t *testing.T) {
	in := streamFixture()
	in = append(in, scenarioFixture("prime", "no", "explicit regional denial"), scenarioFixture("tiktok", "no", "explicit regional denial"))
	first := AssessScenarios(scenarioClock, in)
	for i, j := 0, len(in)-1; i < j; i, j = i+1, j-1 {
		in[i], in[j] = in[j], in[i]
	}
	if !reflect.DeepEqual(first, AssessScenarios(scenarioClock, in)) {
		t.Fatal("input order changes output")
	}
	if first[2].Checks[0].ID != "prime" || first[2].Checks[0].Priority != 30 {
		t.Fatal("unknown checks must precede positive checks")
	}
	empty := AssessScenarios(scenarioClock, nil)
	b, err := json.Marshal(empty)
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	if err = json.Unmarshal(b, &rows); err != nil {
		t.Fatal(err)
	}
	for _, a := range rows {
		v, ok := a["score"]
		if !ok || v != nil || a["abstained"] != true {
			t.Fatal("nullable score lost", a)
		}
	}
	// Same-priority checks must use stable lexical IDs.
	if empty[0].Checks[0].ID != "chatgpt" || empty[0].Checks[1].ID != "claude" {
		t.Fatal("tie sort unstable")
	}
}

func TestScenarioDuplicatesDoNotReweight(t *testing.T) {
	in := streamFixture()
	in[0].Result.Status = "no"
	in[0].Result.Evidence = "original=no licensed=no"
	in = append(in, in[1], in[1])
	a := AssessScenarios(scenarioClock, in)[2]
	if a.Score == nil || *a.Score != 50 {
		t.Fatal("duplicate votes changed weight", a)
	}
	if a.Checks[0].ID != "netflix" || a.Checks[0].Priority != 10 {
		t.Fatal("denial must be checked first")
	}
}
