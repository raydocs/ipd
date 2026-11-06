package api

import (
	"testing"
)

func TestScenarioRiskWireContract(t *testing.T) {
	_, h := contractHandler(t, false)
	rep := decodeContractJSON(t, contractRequest(h, "GET", "/v1/ip/192.0.2.1/risk?live=0&format=json", "", ""))
	schema := contractSchema(t, contractDoc(t), map[string]any{"$ref": "#/components/schemas/RiskReport"})
	if err := schema.Validate(rep); err != nil {
		t.Fatal(err)
	}
	data := object(t, rep["data"])
	rows, ok := data["scenario_assessments"].([]any)
	if !ok || len(rows) != 5 {
		t.Fatal("missing scenario wire rows")
	}
	row := object(t, rows[0])
	if v, ok := row["score"]; !ok || v != nil || row["abstained"] != true {
		t.Fatal("unknown score not serialized null")
	}
	for _, tc := range []struct {
		key   string
		value any
	}{{"score", 101}, {"score", -1}, {"score", false}, {"score", 0.5}, {"coverage", 1.1}, {"confidence", -0.1}, {"model_version", "future"}, {"scenario", "generic"}} {
		old := row[tc.key]
		row[tc.key] = tc.value
		if err := schema.Validate(rep); err == nil {
			t.Errorf("accepted invalid %s=%v", tc.key, tc.value)
		}
		row[tc.key] = old
	}
	delete(row, "score")
	if err := schema.Validate(rep); err == nil {
		t.Fatal("nullable score must still be present")
	}
}
