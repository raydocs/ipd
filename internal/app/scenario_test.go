package app

import (
	"context"
	"encoding/json"
	"ipd/internal/score"
	"ipd/internal/unlock"
	"testing"
)

func TestRiskScenarioMissingEvidenceRegression(t *testing.T) {
	s := newSvc(t)
	rep, err := s.Risk(context.Background(), "192.0.2.1", false)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(rep.Data)
	var d map[string]any
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	rows, ok := d["scenario_assessments"].([]any)
	if !ok || len(rows) != 5 {
		t.Fatalf("missing five scenario assessments: %s", raw)
	}
	for _, r := range rows {
		a := r.(map[string]any)
		v, exists := a["score"]
		if !exists || v != nil || a["abstained"] != true || a["coverage"] != float64(0) {
			t.Fatalf("missing evidence became a score: %+v", a)
		}
	}
	for _, key := range []string{"purity", "residential", "native", "dnsbl", "enrichment"} {
		if _, ok := d[key]; !ok {
			t.Fatal("lost legacy field", key)
		}
	}
}

func TestUnlockScenarioUsesOnlyExistingChecks(t *testing.T) {
	s := newSvc(t)
	calls := 0
	s.Checks = &unlock.Engine{Get: unlockGetter(func(u string) unlock.Response {
		calls++
		return unlock.Response{Status: 403, FinalURL: u, Body: "not available in your region"}
	})}
	rep := s.Unlock(context.Background(), []string{"prime", "netflix"})
	if calls != 3 {
		t.Fatalf("new requests: %d", calls)
	}
	rows := rep.Data.(map[string]any)["scenario_assessments"].([]score.ScenarioAssessment)
	if rows[2].Score == nil || *rows[2].Score != 0 || rows[2].Abstained {
		t.Fatalf("explicit denials not scored: %+v", rows[2])
	}
	for _, i := range []int{0, 1, 3, 4} {
		if rows[i].Score != nil || !rows[i].Abstained {
			t.Fatal("cross-scenario evidence leak")
		}
	}
	s.Checks = nil
	rows = s.Unlock(context.Background(), nil).Data.(map[string]any)["scenario_assessments"].([]score.ScenarioAssessment)
	for _, a := range rows {
		if a.Score != nil {
			t.Fatal("missing engine scored")
		}
	}
}
