package mcp

import (
	"ipd/internal/app"
	"ipd/internal/score"
	"testing"
	"time"
)

func TestScenarioStructuredOutputNullContract(t *testing.T) {
	rows := score.AssessScenarios(time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC), nil)
	out, err := toOut(app.Report{Data: map[string]any{"scenario_assessments": rows}})
	if err != nil {
		t.Fatal(err)
	}
	raw, ok := out.Data["scenario_assessments"].([]any)
	if !ok || len(raw) != 5 {
		t.Fatal("lost scenario output")
	}
	for _, r := range raw {
		a := r.(map[string]any)
		v, ok := a["score"]
		if !ok || v != nil || a["abstained"] != true {
			t.Fatal("MCP coerced unknown score")
		}
	}
}
