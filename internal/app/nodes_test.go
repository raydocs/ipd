package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"ipd/internal/config"
	"ipd/internal/nodes"
)

const nodeSubscription = `proxies:
- {name: first, type: ss, server: 192.0.2.1, port: 443, password: fixture-password}
- {name: second, type: ss, server: 192.0.2.2, port: 443, password: fixture-password}
`

func nodeService() *Service { return &Service{Cfg: &config.Config{}} }

func assertNodesUnavailable(t *testing.T, rep Report, count int) {
	t.Helper()
	data := rep.Data.(map[string]any)
	if rep.Verdict != "abstain" || data["measurement_status"] != "unavailable" || data["count"] != count {
		t.Fatalf("expected honest unmeasured report, got %+v", rep)
	}
	for _, key := range []string{"nodes", "renamed_yaml"} {
		if _, ok := data[key]; ok {
			t.Errorf("unavailable report must omit %s", key)
		}
	}
	blob, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"fixture-password", "192.0.2.", "unreachable", "❌", "Claude", "GPT"} {
		if strings.Contains(string(blob), forbidden) {
			t.Errorf("unavailable report leaked or fabricated %q", forbidden)
		}
	}
}

func TestNodesDefaultUnavailable(t *testing.T) {
	rep, err := nodeService().Nodes(context.Background(), nodeSubscription, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertNodesUnavailable(t, rep, 2)
}

func TestNodesNilDefaultUnavailable(t *testing.T) {
	previous := DefaultNodeCheck
	DefaultNodeCheck = nil
	t.Cleanup(func() { DefaultNodeCheck = previous })
	rep, err := nodeService().Nodes(context.Background(), nodeSubscription, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertNodesUnavailable(t, rep, 2)
}

func TestNodesInjectedMeasurement(t *testing.T) {
	for _, mode := range []string{"success", "partial", "failure"} {
		for _, injection := range []string{"argument", "service", "default"} {
			t.Run(mode+"/"+injection, func(t *testing.T) {
				var calls atomic.Int32
				checker := nodesCheckerFunc(func(ctx context.Context, name, socks string) (string, string, string, string, error) {
					calls.Add(1)
					if socks != "" {
						t.Errorf("unexpected endpoint %q", socks)
					}
					if mode == "failure" || (mode == "partial" && name == "second") {
						return "", "", "", "", errors.New("probe refused: fixture-password")
					}
					return "198.51.100.1", "A", "yes", "US", nil
				})
				s := nodeService()
				var argument nodes.Checker
				switch injection {
				case "argument":
					argument = checker
				case "service":
					s.SetNodeChecker(checker)
				case "default":
					previous := DefaultNodeCheck
					DefaultNodeCheck = checker
					t.Cleanup(func() { DefaultNodeCheck = previous })
				}
				rep, err := s.Nodes(context.Background(), nodeSubscription, argument)
				if err != nil {
					t.Fatal(err)
				}
				want := map[string]string{"success": "ok", "partial": "ok_with_caveats", "failure": "blocked"}[mode]
				data := rep.Data.(map[string]any)
				if calls.Load() != 2 || rep.Verdict != want || data["measurement_status"] != "completed" || data["count"] != 2 || data["measured_count"] != 2 {
					t.Fatalf("calls=%d, report=%+v", calls.Load(), rep)
				}
				out := data["nodes"].([]nodes.Outcome)
				if len(out) != 2 {
					t.Fatalf("expected two measured outcomes, got %d", len(out))
				}
				for _, o := range out {
					wantReachable := mode == "success" || (mode == "partial" && o.Name == "first")
					if o.Reachable != wantReachable || (o.Reachable && (o.EgressIP != "198.51.100.1" || o.AI != "yes")) {
						t.Fatalf("incorrect measured outcome: %+v", o)
					}
					if !o.Reachable && (o.Error != "unreachable" || o.AI != "") {
						t.Fatalf("incorrect negative probe: %+v", o)
					}
				}
				if data["renamed_yaml"] == "" || strings.Contains(rep.Summary, "fixture-password") {
					t.Fatal("missing measured export or unsafe summary")
				}
			})
		}
	}
}

func TestNodesCanceledBeforeMeasurement(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var calls atomic.Int32
	rep, err := nodeService().Nodes(ctx, nodeSubscription, nodesCheckerFunc(func(context.Context, string, string) (string, string, string, string, error) {
		calls.Add(1)
		return "", "", "", "", context.Canceled
	}))
	if err != nil {
		t.Fatal(err)
	}
	assertNodesUnavailable(t, rep, 2)
	if calls.Load() != 0 {
		t.Fatal("checker executed after cancellation")
	}
}

func TestNodesSourceErrorsDoNotEchoCredentials(t *testing.T) {
	for _, source := range []string{
		"https://fixture-user:fixture-password@invalid.test/%zz?token=fixture-token",
		"ss://fixture-user:fixture-password@invalid.test:%zz#fixture-token",
		"proxies: [fixture-password",
	} {
		_, err := nodeService().Nodes(context.Background(), source, nil)
		if err == nil {
			t.Fatalf("expected invalid input error")
		}
		if strings.Contains(fmt.Sprint(err), "fixture-") {
			t.Fatalf("error echoed subscription credentials: %v", err)
		}
	}
}

// Timeout-capable errors must remain inconclusive even if they do not wrap a
// context error (as with network timeouts).
type nodeTimeoutError struct{}

func (nodeTimeoutError) Error() string { return "fixture-password: timed out" }
func (nodeTimeoutError) Timeout() bool { return true }

func TestNodesInconclusiveMeasurement(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		reason string
	}{
		{"capability", fmt.Errorf("fixture-password: %w", ErrNodeMeasurementUnavailable), "checker_unavailable"},
		{"canceled", fmt.Errorf("fixture-password: %w", context.Canceled), "canceled"},
		{"deadline", fmt.Errorf("fixture-password: %w", context.DeadlineExceeded), "timeout"},
		{"network_timeout", nodeTimeoutError{}, "timeout"},
		{"empty_observation", nil, "no_observation"},
	} {
		for _, mixed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/mixed=%t", tc.name, mixed), func(t *testing.T) {
				var calls atomic.Int32
				rep, err := nodeService().Nodes(context.Background(), nodeSubscription, nodesCheckerFunc(func(ctx context.Context, name, socks string) (string, string, string, string, error) {
					calls.Add(1)
					if mixed && name == "first" {
						return "198.51.100.1", "A", "yes", "US", nil
					}
					// Even stray grades on an inconclusive result must not escape.
					return "", "A", "yes", "US", tc.err
				}))
				if err != nil {
					t.Fatal(err)
				}
				assertNodesUnavailable(t, rep, 2)
				wantMeasured := 0
				if mixed {
					wantMeasured = 1
				}
				data := rep.Data.(map[string]any)
				if calls.Load() != 2 || data["measured_count"] != wantMeasured || data["measurement_reason"] != tc.reason {
					t.Fatalf("calls=%d, data=%+v", calls.Load(), data)
				}
			})
		}
	}
}

func TestNodesContextCanceledDuringMeasurement(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	rep, err := nodeService().Nodes(ctx, nodeSubscription, nodesCheckerFunc(func(context.Context, string, string) (string, string, string, string, error) {
		calls.Add(1)
		cancel()
		return "198.51.100.1", "A", "yes", "US", nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	assertNodesUnavailable(t, rep, 2)
	if calls.Load() == 0 || rep.Data.(map[string]any)["measurement_reason"] != "canceled" {
		t.Fatalf("calls=%d, data=%+v", calls.Load(), rep.Data)
	}
}

func TestNodesCheckerPrecedence(t *testing.T) {
	s := nodeService()
	unexpected := nodesCheckerFunc(func(context.Context, string, string) (string, string, string, string, error) {
		t.Error("lower-priority checker executed")
		return "", "", "", "", ErrNodeMeasurementUnavailable
	})
	s.SetNodeChecker(unexpected)
	previous := DefaultNodeCheck
	DefaultNodeCheck = unexpected
	t.Cleanup(func() { DefaultNodeCheck = previous })
	var calls atomic.Int32
	_, err := s.Nodes(context.Background(), nodeSubscription, nodesCheckerFunc(func(context.Context, string, string) (string, string, string, string, error) {
		calls.Add(1)
		return "198.51.100.1", "A", "yes", "US", nil
	}))
	if err != nil || calls.Load() != 2 {
		t.Fatalf("calls=%d, err=%v", calls.Load(), err)
	}
}

func TestNodesDefaultCheckerSignalsUnavailable(t *testing.T) {
	_, _, _, _, err := DefaultNodeCheck.Check(context.Background(), "first", "")
	if !errors.Is(err, ErrNodeMeasurementUnavailable) {
		t.Fatalf("default checker must signal missing capability, got %v", err)
	}
}
