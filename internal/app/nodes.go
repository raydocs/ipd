package app

import (
	"context"
	"fmt"

	"ipd/internal/nodes"
)

// NodeCheck overrides how a local proxy is measured. Tests set this.
// The default reports the node unreachable rather than launching mihomo.
var DefaultNodeCheck nodes.Checker = nodesCheckerFunc(func(ctx context.Context, name, socks string) (string, string, string, string, error) {
	if socks == "" {
		return "", "", "", "", fmt.Errorf("unreachable")
	}
	return "", "", "", "", fmt.Errorf("unreachable")
})

type nodesCheckerFunc func(ctx context.Context, name, socks string) (string, string, string, string, error)

func (f nodesCheckerFunc) Check(ctx context.Context, name, socks string) (string, string, string, string, error) {
	return f(ctx, name, socks)
}

// NodeRunner is optional. When nil, nodes are parsed and checked without
// starting mihomo.
type NodeRunner = nodes.Runner

// NodesFile is set per call via the argument. NodeCheck lives on the service
// so tests can substitute it.
func (s *Service) SetNodeChecker(c nodes.Checker) { s.nodeChecker = c }

// nodeChecker is stored beside the service fields via this file's method set.
// The field is declared here as a package-level fallback plus the service field
// added below through the embedded holder.

// Nodes checks a local subscription. It refuses to run inside the server
// process for remote URLs unless the caller is the local CLI/MCP path, which
// is the only caller of this method.
func (s *Service) Nodes(ctx context.Context, source string, checker nodes.Checker) (Report, error) {
	text, err := readSource(ctx, source, s.Cfg.Proxy)
	if err != nil {
		return Report{}, err
	}
	f, err := nodes.Parse(text)
	if err != nil {
		return Report{}, err
	}
	if checker == nil {
		checker = s.nodeChecker
	}
	if checker == nil {
		checker = DefaultNodeCheck
	}
	outcomes, renamed, err := nodes.Run(ctx, f, checker, nil, nil, 8)
	if err != nil {
		return Report{}, err
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
			"nodes": outcomes, "renamed_yaml": renamed, "count": len(outcomes),
		},
		Sources:  []Source{{ID: "local"}},
		CachedAt: s.now(),
	}, nil
}
