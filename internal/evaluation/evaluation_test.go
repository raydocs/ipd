package evaluation

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"

	"ipd/internal/score"
)

func fixture(t *testing.T) Dataset {
	t.Helper()
	f, err := os.Open("testdata/synthetic-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	d, err := Load(f)
	if err != nil {
		t.Fatal(err)
	}
	return d
}
func value(t *testing.T, r Ratio, n, d int) {
	t.Helper()
	if r.Numerator != n || r.Denominator != d {
		t.Fatalf("ratio %+v want %d/%d", r, n, d)
	}
	if d == 0 {
		if r.Value != nil {
			t.Fatalf("undefined ratio: %+v", r)
		}
		return
	}
	if r.Value == nil || math.Abs(*r.Value-float64(n)/float64(d)) > 1e-12 {
		t.Fatalf("bad ratio %+v", r)
	}
}
func TestEvaluateRealClassifierAndAccounting(t *testing.T) {
	d := fixture(t)
	r, err := Evaluate(d, "test")
	if err != nil {
		t.Fatal(err)
	}
	if r.Total != 4 || r.Decided != 3 || r.Abstained != 1 || r.Correct != 2 {
		t.Fatalf("counts %+v", r)
	}
	if r.Confusion["hosting"]["hosting"] != 1 || r.Confusion["hosting"]["business"] != 1 || r.Confusion["residential_fixed"]["abstain"] != 1 || r.Confusion["residential_mobile"]["residential_mobile"] != 1 {
		t.Fatal(r.Confusion)
	}
	sum := 0
	for _, row := range r.Confusion {
		for _, n := range row {
			sum += n
		}
	}
	if sum != r.Total {
		t.Fatal("confusion total", sum)
	}
	for i, p := range r.Predictions {
		actual := score.ClassifyResidential(d.Rows[i].Features)
		if p.Predicted != actual.Class || p.Confidence != actual.Confidence {
			t.Fatalf("not actual classifier: %+v %+v", p, actual)
		}
	}
	h := r.Classes["hosting"]
	if h.Support != 2 || h.Predicted != 1 {
		t.Fatal(h)
	}
	value(t, h.Precision, 1, 1)
	value(t, h.Recall, 1, 2)
	b := r.Classes["business"]
	value(t, b.Precision, 0, 1)
	value(t, b.Recall, 0, 0)
	fixed := r.Classes["residential_fixed"]
	value(t, fixed.Precision, 0, 0)
	value(t, fixed.Recall, 0, 1)
	value(t, r.Classes["isp_static"].Precision, 0, 0)
	value(t, r.Classes["isp_static"].Recall, 0, 0)
	value(t, r.Coverage, 3, 4)
	value(t, r.AbstentionRate, 1, 4)
	value(t, r.Accuracy, 2, 4)
	value(t, r.SelectiveAccuracy, 2, 3)
	if r.ProvenanceCounts["synthetic"] != 4 || r.ProvenanceCounts["public"] != 0 || len(r.DatasetSHA256) != 64 {
		t.Fatal("missing report identity")
	}
	golden, err := os.ReadFile("testdata/synthetic-v1.report.json")
	if err != nil {
		t.Fatal(err)
	}
	formatted, _ := json.MarshalIndent(r, "", "  ")
	if !bytes.Equal(append(formatted, '\n'), golden) {
		t.Fatal("checked-in report differs; regenerate with documented CLI command")
	}
	first, _ := json.Marshal(r)
	for range 20 {
		again, err := Evaluate(d, "test")
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(again)
		if !bytes.Equal(first, raw) {
			t.Fatal("nondeterministic report")
		}
	}
	d.Rows[0].Provenance.Reference = "changed attribution"
	changed, _ := Evaluate(d, "test")
	if changed.DatasetSHA256 == r.DatasetSHA256 {
		t.Fatal("digest ignored provenance")
	}
}
func TestAllAbstainAndSplitSelection(t *testing.T) {
	d := fixture(t)
	d.Rows = d.Rows[2:3]
	r, err := Evaluate(d, "test")
	if err != nil {
		t.Fatal(err)
	}
	value(t, r.SelectiveAccuracy, 0, 0)
	value(t, r.Coverage, 0, 1)
	value(t, r.AbstentionRate, 1, 1)
	value(t, r.Accuracy, 0, 1)
	if _, err := Evaluate(d, "validation"); err == nil {
		t.Fatal("accepted empty selection")
	}
	if _, err := Evaluate(d, "all"); err == nil {
		t.Fatal("accepted unknown split")
	}
	d = fixture(t)
	d.Rows[0].Split = "train"
	r, err = Evaluate(d, "train")
	if err != nil || r.Total != 1 {
		t.Fatalf("split: %+v %v", r, err)
	}
}
func TestValidation(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Dataset)
	}{
		{"schema", func(d *Dataset) { d.SchemaVersion = "v2" }},
		{"identity", func(d *Dataset) { d.Revision = "" }},
		{"rationale", func(d *Dataset) { d.GroupRationale = " " }},
		{"split rationale", func(d *Dataset) { d.SplitRationale = "" }},
		{"empty", func(d *Dataset) { d.Rows = nil }},
		{"row limit", func(d *Dataset) { d.Rows = make([]Row, MaxRows+1) }},
		{"duplicate id", func(d *Dataset) { d.Rows[1].ID = d.Rows[0].ID }},
		{"invalid group", func(d *Dataset) { d.Rows[0].Group = "bad group" }},
		{"leakage", func(d *Dataset) { d.Rows[1].Group = d.Rows[0].Group; d.Rows[1].Split = "train" }},
		{"duplicate vector", func(d *Dataset) { d.Rows[1].Features = d.Rows[0].Features }},
		{"implicit zero duplicate", func(d *Dataset) { d.Rows[1].Features = map[string]float64{"eyeball": 0} }},
		{"unknown label", func(d *Dataset) { d.Rows[0].Label = "abstain" }},
		{"unknown feature", func(d *Dataset) { d.Rows[0].Features["typo"] = 1 }},
		{"unknown split", func(d *Dataset) { d.Rows[0].Split = "holdout" }},
		{"unknown provenance", func(d *Dataset) { d.Rows[0].Provenance.Kind = "private" }},
		{"reference", func(d *Dataset) { d.Rows[0].Provenance.Reference = "" }},
		{"label method", func(d *Dataset) { d.Rows[0].Provenance.LabelMethod = "" }},
		{"nil features", func(d *Dataset) { d.Rows[0].Features = nil }},
		{"nan", func(d *Dataset) { d.Rows[0].Features["eyeball"] = math.NaN() }},
		{"infinite", func(d *Dataset) { d.Rows[0].Features["eyeball"] = math.Inf(1) }},
		{"negative", func(d *Dataset) { d.Rows[0].Features["eyeball"] = -1 }},
		{"range", func(d *Dataset) { d.Rows[0].Features["eyeball"] = 1.1 }},
		{"nonbinary", func(d *Dataset) { d.Rows[0].Features["cloud_hit"] = 0.5 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := fixture(t)
			tc.edit(&d)
			if _, err := Evaluate(d, "test"); err == nil {
				t.Fatal("accepted invalid dataset")
			}
		})
	}
	d := fixture(t)
	d.Rows[0].Provenance.Kind = "public"
	d.Rows[0].Features["eyeball"] = 0.42
	d.Rows[1].Group = d.Rows[0].Group
	if err := d.Validate(); err != nil {
		t.Fatal("valid same-split group/public metadata rejected", err)
	}
}
func TestStrictLoad(t *testing.T) {
	raw, _ := os.ReadFile("testdata/synthetic-v1.json")
	cases := []string{
		"", "null", "[]", string(raw) + " {}",
		strings.Replace(string(raw), `"schema_version":`, `"extra":1,"schema_version":`, 1),
		strings.Replace(string(raw), `"cloud_hit":1`, `"cloud_hit":1,"cloud_hit":0`, 1),
		strings.Replace(string(raw), `"cloud_hit":1`, `"cloud_hit":null`, 1),
		strings.Replace(string(raw), `"label":"hosting"`, `"label":"hosting","Label":"business"`, 1),
		strings.Replace(string(raw), `"cloud_hit":1`, `"cloud_hit":"1"`, 1),
		strings.Replace(string(raw), `"cloud_hit":1`, `"cloud_hit":1e999`, 1),
		strings.Repeat(" ", MaxBytes+1), strings.Repeat("[", 18) + strings.Repeat("]", 18),
	}
	for i, s := range cases {
		if _, err := Load(strings.NewReader(s)); err == nil {
			t.Fatalf("accepted malformed input %d", i)
		}
	}
}

func TestLoadRejectsUnicodeSchemaAliases(t *testing.T) {
	raw, err := os.ReadFile("testdata/synthetic-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, old, replacement string }{
		{"literal_split", `"split":"test"`, `"ſplit":"test"`},
		{"escaped_split", `"split":"test"`, `"\u017fplit":"test"`},
		{"duplicate_split", `"split":"test"`, `"split":"train","ſplit":"test"`},
		{"duplicate_features", `"features":{"cloud_hit":1,"vpn":1}`, `"features":{"cloud_hit":1,"vpn":1},"feature\u017f":{"cloud_hit":0,"as_cdn":1}`},
		{"duplicate_rows", `"rows": [`, `"rows":[],"rowſ":[`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := strings.Replace(string(raw), tc.old, tc.replacement, 1)
			if mutated == string(raw) {
				t.Fatal("fixture not changed")
			}
			if _, err := Load(strings.NewReader(mutated)); err == nil {
				t.Fatal("Unicode schema alias accepted")
			}
		})
	}
}
