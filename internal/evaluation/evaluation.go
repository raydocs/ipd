// Package evaluation evaluates frozen feature datasets without lookup or network I/O.
package evaluation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"regexp"
	"strings"

	"ipd/internal/score"
	"ipd/internal/version"
)

const SchemaVersion = "residential-evaluation/v1"
const MaxBytes = 4 << 20
const MaxRows = 10000

var classes = []string{"residential_fixed", "residential_mobile", "isp_static", "business", "hosting", "cdn_anycast"}
var featureNames = strings.Fields("cloud_hit as_cdn anycast tor as_mobile announcer_hosting upstream_hosting rtt_colo rdns_missing as_hosting as_cable as_dsl as_isp keyword_broadband rdns_dynamic as_business keyword_idc geo_disagree vpn eyeball")
var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,79}$`)

type Provenance struct {
	Kind        string `json:"kind"` // synthetic or public; never inferred from features
	Reference   string `json:"reference"`
	LabelMethod string `json:"label_method"`
}
type Row struct {
	ID         string             `json:"id"`
	Group      string             `json:"group"`
	Split      string             `json:"split"`
	Label      string             `json:"label"`
	Provenance Provenance         `json:"provenance"`
	Features   map[string]float64 `json:"features"`
}
type Dataset struct {
	SchemaVersion  string `json:"schema_version"`
	ID             string `json:"id"`
	Revision       string `json:"revision"`
	GroupRationale string `json:"group_rationale"`
	SplitRationale string `json:"split_rationale"`
	Rows           []Row  `json:"rows"`
}

// Load accepts one strict JSON document, bounded before decoding. Repeated JSON
// keys are rejected rather than letting the last value silently replace a label.
func Load(r io.Reader) (Dataset, error) {
	var d Dataset
	raw, err := io.ReadAll(io.LimitReader(r, MaxBytes+1))
	if err != nil {
		return d, err
	}
	if len(raw) > MaxBytes {
		return d, fmt.Errorf("dataset exceeds %d bytes", MaxBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := uniqueKeys(dec, 0); err != nil {
		return d, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return d, fmt.Errorf("expected exactly one JSON document")
	}
	dec = json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return d, err
	}
	return d, d.Validate()
}

func uniqueKeys(d *json.Decoder, depth int) error {
	if depth > 16 {
		return fmt.Errorf("JSON nesting exceeds 16")
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	if t == nil {
		return fmt.Errorf("null values are not supported")
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			k, err := d.Token()
			if err != nil {
				return err
			}
			key, ok := k.(string)
			if !ok || key != strings.ToLower(key) || seen[key] {
				return fmt.Errorf("duplicate or invalid JSON key %v", k)
			}
			seen[key] = true
			if err := uniqueKeys(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := uniqueKeys(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter")
	}
	_, err = d.Token()
	return err
}

func includes(ss []string, s string) bool {
	for _, v := range ss {
		if s == v {
			return true
		}
	}
	return false
}
func textOK(s string) bool { return strings.TrimSpace(s) != "" && len(s) <= 2048 }

// Validate also applies to callers constructing Dataset directly. Duplicates are
// compared after dropping explicit zeroes (missing features mean zero).
func (d Dataset) Validate() error {
	if d.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schema_version %q", d.SchemaVersion)
	}
	if !identifier.MatchString(d.ID) || !identifier.MatchString(d.Revision) || !textOK(d.GroupRationale) || !textOK(d.SplitRationale) {
		return fmt.Errorf("dataset identity and grouping/split rationale required")
	}
	if len(d.Rows) == 0 || len(d.Rows) > MaxRows {
		return fmt.Errorf("rows must contain 1..%d records", MaxRows)
	}
	ids, groups, vectors := map[string]bool{}, map[string]string{}, map[string]string{}
	for i, r := range d.Rows {
		bad := func(s string) error { return fmt.Errorf("row %d (%s): %s", i, r.ID, s) }
		if !identifier.MatchString(r.ID) || !identifier.MatchString(r.Group) || ids[r.ID] {
			return bad("invalid or duplicate id/group")
		}
		ids[r.ID] = true
		if !includes([]string{"train", "validation", "test"}, r.Split) {
			return bad("invalid split")
		}
		if prev, ok := groups[r.Group]; ok && prev != r.Split {
			return bad("group leaks across splits")
		}
		groups[r.Group] = r.Split
		if !includes(classes, r.Label) {
			return bad("unknown ground-truth label (abstain is an output, not a label)")
		}
		if !includes([]string{"synthetic", "public"}, r.Provenance.Kind) || !textOK(r.Provenance.Reference) || !textOK(r.Provenance.LabelMethod) {
			return bad("provenance kind, reference and label_method required")
		}
		if r.Features == nil {
			return bad("features must be an object; use {} for no evidence")
		}
		normalized := map[string]float64{}
		for k, v := range r.Features {
			if !includes(featureNames, k) {
				return bad("unknown feature " + k)
			}
			if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > 1 || (k != "eyeball" && v != 0 && v != 1) {
				return bad("invalid feature value for " + k)
			}
			if v != 0 {
				normalized[k] = v
			}
		}
		b, _ := json.Marshal(normalized)
		key := string(b)
		if prev, ok := vectors[key]; ok {
			return bad("duplicate feature vector of " + prev + " (including implicit zeroes)")
		}
		vectors[key] = r.ID
	}
	return nil
}

// Ratio retains denominators; undefined metrics serialize as null, never NaN or
// a fabricated zero. All records have equal weight.
type Ratio struct {
	Numerator   int      `json:"numerator"`
	Denominator int      `json:"denominator"`
	Value       *float64 `json:"value"`
}

func ratio(n, d int) Ratio {
	r := Ratio{Numerator: n, Denominator: d}
	if d > 0 {
		v := float64(n) / float64(d)
		r.Value = &v
	}
	return r
}

type ClassMetrics struct {
	Support   int   `json:"support"`
	Predicted int   `json:"predicted"`
	Precision Ratio `json:"precision"`
	Recall    Ratio `json:"recall"`
}
type Prediction struct {
	ID         string  `json:"id"`
	Label      string  `json:"label"`
	Predicted  string  `json:"predicted"`
	Confidence float64 `json:"confidence"`
}
type Report struct {
	SchemaVersion     string                    `json:"schema_version"`
	DatasetID         string                    `json:"dataset_id"`
	DatasetRevision   string                    `json:"dataset_revision"`
	DatasetSHA256     string                    `json:"dataset_sha256"`
	ModelVersion      string                    `json:"model_version"`
	Split             string                    `json:"split"`
	Interpretation    string                    `json:"interpretation"`
	ProvenanceCounts  map[string]int            `json:"provenance_counts"`
	Total             int                       `json:"total"`
	Decided           int                       `json:"decided"`
	Abstained         int                       `json:"abstained"`
	Correct           int                       `json:"correct"`
	Labels            []string                  `json:"labels"`
	PredictionLabels  []string                  `json:"prediction_labels"`
	Confusion         map[string]map[string]int `json:"confusion"`
	Classes           map[string]ClassMetrics   `json:"classes"`
	Coverage          Ratio                     `json:"coverage"`
	AbstentionRate    Ratio                     `json:"abstention_rate"`
	Accuracy          Ratio                     `json:"accuracy_including_abstentions_as_errors"`
	SelectiveAccuracy Ratio                     `json:"accuracy_on_decided"`
	Predictions       []Prediction              `json:"predictions"`
}

// Evaluate validates the entire dataset before selecting a split, so excluded
// rows cannot conceal group leakage. No fitting, lookups or threshold tuning.
func Evaluate(d Dataset, split string) (Report, error) {
	var r Report
	if err := d.Validate(); err != nil {
		return r, err
	}
	if !includes([]string{"train", "validation", "test"}, split) {
		return r, fmt.Errorf("invalid evaluation split %q", split)
	}
	canonical, _ := json.Marshal(d)
	sum := sha256.Sum256(canonical)
	r = Report{SchemaVersion: SchemaVersion, DatasetID: d.ID, DatasetRevision: d.Revision, DatasetSHA256: hex.EncodeToString(sum[:]), ModelVersion: version.ModelResidential, Split: split,
		Interpretation:   "Dataset-conditional results only; synthetic rows are regression checks, not measured population accuracy. Public provenance alone does not establish a representative population estimate.",
		ProvenanceCounts: map[string]int{"synthetic": 0, "public": 0}, Labels: append([]string{}, classes...), PredictionLabels: append(append([]string{}, classes...), "abstain"), Confusion: map[string]map[string]int{}, Classes: map[string]ClassMetrics{}}
	for _, c := range classes {
		r.Confusion[c] = map[string]int{}
		for _, p := range r.PredictionLabels {
			r.Confusion[c][p] = 0
		}
	}
	for _, row := range d.Rows {
		if row.Split != split {
			continue
		}
		got := score.ClassifyResidential(row.Features)
		predicted := got.Class
		if got.Abstained {
			predicted = "abstain"
		}
		if !includes(r.PredictionLabels, predicted) {
			return Report{}, fmt.Errorf("unsupported classifier output %q", predicted)
		}
		r.Total++
		r.ProvenanceCounts[row.Provenance.Kind]++
		r.Confusion[row.Label][predicted]++
		if predicted == "abstain" {
			r.Abstained++
		} else {
			r.Decided++
			if predicted == row.Label {
				r.Correct++
			}
		}
		r.Predictions = append(r.Predictions, Prediction{row.ID, row.Label, predicted, got.Confidence})
	}
	if r.Total == 0 {
		return Report{}, fmt.Errorf("no records in split %q", split)
	}
	for _, c := range classes {
		support, predicted := 0, 0
		for _, p := range r.PredictionLabels {
			support += r.Confusion[c][p]
		}
		for _, truth := range classes {
			predicted += r.Confusion[truth][c]
		}
		tp := r.Confusion[c][c]
		r.Classes[c] = ClassMetrics{support, predicted, ratio(tp, predicted), ratio(tp, support)}
	}
	r.Coverage = ratio(r.Decided, r.Total)
	r.AbstentionRate = ratio(r.Abstained, r.Total)
	r.Accuracy = ratio(r.Correct, r.Total)
	r.SelectiveAccuracy = ratio(r.Correct, r.Decided)
	return r, nil
}
