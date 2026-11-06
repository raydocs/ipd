package cli

import (
	"encoding/json"
	"testing"
)

func TestRiskScenarioJSONNull(t *testing.T) {
	cliEnv(t)
	_, out, stderr := invokeCLI(t, "", "192.0.2.1", "--json", "--offline")
	if stderr != "" {
		t.Fatal(stderr)
	}
	var rep struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err, out)
	}
	rows, ok := rep.Data["scenario_assessments"].([]any)
	if !ok || len(rows) != 5 {
		t.Fatal("CLI lost scenario rows", out)
	}
	for _, r := range rows {
		a := r.(map[string]any)
		v, ok := a["score"]
		if !ok || v != nil || a["abstained"] != true {
			t.Fatal("CLI changed null")
		}
	}
}
