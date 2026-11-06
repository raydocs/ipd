package score

import (
	"encoding/json"
	"sort"
	"time"

	"ipd/internal/unlock"
)

const ScenarioModelVersion = "scenario-evidence-v1"
const scenarioMaxAge = 24 * time.Hour

// ScenarioObservation is trusted in-process collector input, never caller claims.
// ObservedAt is the collection start, not the report/cache/snapshot clock.
type ScenarioObservation struct {
	Source     string        `json:"source"`
	Result     unlock.Result `json:"result"`
	ObservedAt *time.Time    `json:"observed_at"`
}

type ScenarioCheck struct {
	ID           string                `json:"id"`
	Weight       int                   `json:"weight"`
	Status       string                `json:"status"`
	Reason       string                `json:"reason"`
	Priority     int                   `json:"priority"`
	Observations []ScenarioObservation `json:"observations"`
}

type ScenarioAssessment struct {
	Scenario     string          `json:"scenario"`
	ModelVersion string          `json:"model_version"`
	Scope        string          `json:"scope"`
	Score        *int            `json:"score"`
	Abstained    bool            `json:"abstained"`
	Coverage     float64         `json:"coverage"`
	Confidence   float64         `json:"confidence"`
	AssessedAt   time.Time       `json:"assessed_at"`
	Checks       []ScenarioCheck `json:"checks"`
}

type scenarioSpec struct {
	id, scope string
	services  []string
}

var scenarioSpecs = []scenarioSpec{
	{"ai", "seven AI public endpoints only; not authenticated model calls", []string{"claude", "chatgpt", "gemini", "grok", "copilot", "meta_ai", "perplexity"}},
	{"social", "TikTok and Reddit public endpoints only; not posting or account status", []string{"tiktok", "reddit"}},
	{"streaming", "Netflix title markers and Prime territory only; not playback", []string{"netflix", "prime"}},
	{"ecommerce", "checkout evidence not collected; no payment/account inference", nil},
	{"email", "delivery evidence not collected; DNSBL hits/absence cannot prove delivery", nil},
}

// AssessScenarios scores only complete, fresh, explicitly recognized endpoint
// evidence. Equal weights describe endpoint coverage, not commercial importance.
// Confidence is evidence completeness, NOT calibrated predictive accuracy.
func AssessScenarios(now time.Time, input []ScenarioObservation) []ScenarioAssessment {
	out := make([]ScenarioAssessment, 0, len(scenarioSpecs))
	for _, spec := range scenarioSpecs {
		a := ScenarioAssessment{Scenario: spec.id, ModelVersion: ScenarioModelVersion, Scope: spec.scope, Abstained: true, AssessedAt: now, Checks: []ScenarioCheck{}}
		services := spec.services
		if len(services) == 0 {
			services = []string{"not_collected"}
		}
		known, sum := 0, 0
		for _, id := range services {
			c := ScenarioCheck{ID: id, Weight: 1, Status: "missing", Reason: "collect matching endpoint evidence; absence is not a pass", Priority: 30, Observations: []ScenarioObservation{}}
			for _, o := range input {
				if o.Result.Service == id && id != "not_collected" {
					c.Observations = append(c.Observations, o)
				}
			}
			// Canonical order retains conflicting duplicates, independent of input order.
			sort.Slice(c.Observations, func(i, j int) bool {
				x, _ := json.Marshal(c.Observations[i])
				y, _ := json.Marshal(c.Observations[j])
				return string(x) < string(y)
			})
			state, value, invalid := "", 0, false
			var facts *unlock.Result
			for _, o := range c.Observations {
				s, v := scenarioVote(now, o)
				if facts != nil && (facts.Status != o.Result.Status || facts.Evidence != o.Result.Evidence || facts.Region != o.Result.Region) {
					invalid = true
				}
				facts = &o.Result
				if s == "unknown" {
					invalid = true
				}
				if state != "" && state != s {
					invalid = true
				}
				state, value = s, v
			}
			if len(c.Observations) > 0 {
				if invalid {
					c.Status = "unknown"
					c.Reason = "conflicting, unrecognized, untrusted, stale or unknown-time evidence; inspect retained observations"
				} else {
					c.Status = state
					known++
					sum += value
					switch state {
					case "denied":
						c.Priority = 10
						c.Reason = "verify explicit regional denial on this endpoint; not an account ban"
					case "limited":
						c.Priority = 20
						c.Reason = "check required surface separately; partial access is not full availability"
					default:
						c.Priority = 40
						c.Reason = "recognized public endpoint marker only; does not prove login, playback or account safety"
					}
				}
			}
			a.Checks = append(a.Checks, c)
		}
		a.Coverage = float64(known) / float64(len(services))
		a.Confidence = a.Coverage
		if known == len(services) {
			n := (sum + known/2) / known
			a.Score = &n
			a.Abstained = false
		}
		sort.Slice(a.Checks, func(i, j int) bool {
			x, y := a.Checks[i], a.Checks[j]
			if x.Priority != y.Priority {
				return x.Priority < y.Priority
			}
			return x.ID < y.ID
		})
		out = append(out, a)
	}
	return out
}

func scenarioVote(now time.Time, o ScenarioObservation) (string, int) {
	if o.Source != "unlock" || now.IsZero() || o.ObservedAt == nil || o.ObservedAt.IsZero() || o.ObservedAt.After(now) || now.Sub(*o.ObservedAt) > scenarioMaxAge {
		return "unknown", 0
	}
	r := o.Result
	// Accept only the exact evidence language emitted by the existing engine.
	switch r.Status {
	case unlock.Yes:
		if (r.Service != "chatgpt" && r.Service != "netflix" && r.Evidence == "recognized positive marker") || (r.Service == "chatgpt" && r.Evidence == "web=yes app=yes") || (r.Service == "netflix" && r.Evidence == "original=yes licensed=yes") {
			return "observed", 100
		}
	case unlock.No:
		if (r.Service != "chatgpt" && r.Service != "netflix" && r.Evidence == "explicit regional denial") || (r.Service == "chatgpt" && r.Evidence == "web=no app=no") || (r.Service == "netflix" && r.Evidence == "original=no licensed=no") {
			return "denied", 0
		}
	case unlock.WebOnly:
		if r.Service == "chatgpt" && r.Evidence == "web=yes app=no" {
			return "limited", 50
		}
	case unlock.AppOnly:
		if r.Service == "chatgpt" && r.Evidence == "web=no app=yes" {
			return "limited", 50
		}
	case unlock.OriginalsOnly:
		if r.Service == "netflix" && r.Evidence == "original=yes licensed=no" {
			return "limited", 50
		}
	case unlock.Partial:
		if r.Service == "netflix" && r.Evidence == "original=no licensed=yes" {
			return "limited", 50
		}
	case unlock.IDC:
		if r.Service == "tiktok" && r.Evidence == "region only present when gzip is requested" {
			return "limited", 50
		}
	}
	return "unknown", 0
}
