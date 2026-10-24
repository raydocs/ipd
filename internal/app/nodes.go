package app

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"ipd/internal/nodes"
)

// ErrNodeMeasurementUnavailable lets an injected checker report missing probing
// capability (for example, no per-node endpoint), rather than a dead node.
var ErrNodeMeasurementUnavailable = errors.New("node measurement unavailable")

// DefaultNodeCheck is an injection point, not an out-of-the-box measurement
// implementation. A replacement must perform real per-node checks itself: Nodes
// does not start mihomo and passes an empty SOCKS address to the checker.
var DefaultNodeCheck nodes.Checker = unavailableNodeChecker{}

type unavailableNodeChecker struct{}

func (unavailableNodeChecker) Check(context.Context, string, string) (string, string, string, string, error) {
	return "", "", "", "", ErrNodeMeasurementUnavailable
}

type nodesCheckerFunc func(ctx context.Context, name, socks string) (string, string, string, string, error)

func (f nodesCheckerFunc) Check(ctx context.Context, name, socks string) (string, string, string, string, error) {
	return f(ctx, name, socks)
}

// NodeRunner is retained for source compatibility. Nodes does not wire a runner
// or create per-node SOCKS endpoints.
type NodeRunner = nodes.Runner

// SetNodeChecker injects a checker that owns the actual per-node measurement.
func (s *Service) SetNodeChecker(c nodes.Checker) { s.nodeChecker = c }

// Nodes parses a subscription and publishes measurements only when an injected
// checker completes the batch. The default is parse-only and abstains.
func (s *Service) Nodes(ctx context.Context, source string, checker nodes.Checker) (Report, error) {
	text, err := readSource(ctx, source, s.Cfg.Proxy)
	if err != nil {
		return Report{}, errors.New("could not read node subscription")
	}
	f, err := nodes.Parse(text)
	if err != nil {
		return Report{}, errors.New("could not parse node subscription")
	}
	if checker == nil {
		checker = s.nodeChecker
	}
	if checker == nil {
		checker = DefaultNodeCheck
	}
	count := len(f.Proxies)
	if err := ctx.Err(); err != nil {
		return s.nodesUnavailable(count, 0, nodeMeasurementIssue(err, "")), nil
	}
	if _, unavailable := checker.(unavailableNodeChecker); checker == nil || unavailable {
		return s.nodesUnavailable(count, 0, "not_configured"), nil
	}

	// nodes.Run intentionally collapses checker errors into "unreachable". Keep
	// the evidence boundary here, before it loses cancellation/capability errors.
	// If any result is inconclusive, withhold the whole batch's verdicts/export;
	// this also handles duplicate proxy names without guessing error attribution.
	var mu sync.Mutex
	measured := 0
	issue := ""
	guarded := nodesCheckerFunc(func(ctx context.Context, name, socks string) (string, string, string, string, error) {
		var egress, grade, ai, tt string
		err := ctx.Err()
		if err == nil {
			egress, grade, ai, tt, err = checker.Check(ctx, name, socks)
		}
		reason := nodeMeasurementIssue(err, egress)
		mu.Lock()
		if reason != "" {
			// Choose a stable reason when concurrent checks fail differently.
			if issue == "" || reason < issue {
				issue = reason
			}
		} else {
			measured++
		}
		mu.Unlock()
		return egress, grade, ai, tt, err
	})
	outcomes, renamed, err := nodes.Run(ctx, f, guarded, nil, nil, 8)
	if ctx.Err() != nil {
		issue = nodeMeasurementIssue(ctx.Err(), "")
	}
	if issue != "" {
		return s.nodesUnavailable(count, measured, issue), nil
	}
	if err != nil {
		// Parser/renamer errors can contain subscription names or values.
		return Report{}, errors.New("could not export measured node configuration")
	}
	unreachable := 0
	for _, o := range outcomes {
		if !o.Reachable {
			unreachable++
		}
	}
	v := "ok"
	if unreachable == len(outcomes) && len(outcomes) > 0 {
		v = "blocked"
	} else if unreachable > 0 {
		v = "ok_with_caveats"
	}
	return Report{
		Verdict: v,
		Summary: fmt.Sprintf("%d nodes, %d unreachable", len(outcomes), unreachable),
		Data: map[string]any{
			"nodes": outcomes, "renamed_yaml": renamed, "count": count,
			"measurement_status": "completed", "measured_count": measured,
		},
		Sources:  []Source{{ID: "local"}},
		CachedAt: s.now(),
	}, nil
}

// An ordinary checker error is a completed negative probe. Missing capability,
// interruption, and an empty success response are not reachability evidence.
func nodeMeasurementIssue(err error, egress string) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, ErrNodeMeasurementUnavailable):
		return "checker_unavailable"
	}
	var timeout interface{ Timeout() bool }
	if errors.As(err, &timeout) && timeout.Timeout() {
		return "timeout"
	}
	if err == nil && egress == "" {
		return "no_observation"
	}
	return ""
}

func (s *Service) nodesUnavailable(count, measured int, reason string) Report {
	return Report{
		Verdict: "abstain",
		Summary: fmt.Sprintf("%d nodes parsed; measurement unavailable (%s); no node verdicts exported", count, reason),
		Data: map[string]any{
			"count": count, "measured_count": measured,
			"measurement_status": "unavailable", "measurement_reason": reason,
		},
		Sources:  []Source{{ID: "local"}},
		CachedAt: s.now(),
	}
}
