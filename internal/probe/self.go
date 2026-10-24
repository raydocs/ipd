package probe

import "context"

// Self measures from the local machine. It has no China perspective.
type Self struct{}

func (Self) Name() string  { return "self" }
func (Self) Enabled() bool { return true }
func (Self) Measure(ctx context.Context, q Query) ([]Sample, error) {
	return []Sample{{
		Provider: "self",
		Network:  "control",
		Healthy:  true,
		ICMP:     "skipped",
		Error:    "self vantage has no China perspective; use globalping",
	}}, nil
}
