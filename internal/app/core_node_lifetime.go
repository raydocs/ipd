package app

import (
	"context"

	"ipd/internal/nodes"
)

type coreGate func(context.Context) error

func coreRunGate(handle *nodes.RunHandle, name string, endpoint nodes.Endpoint) coreGate {
	return func(ctx context.Context) error { return handle.Check(ctx, name, endpoint) }
}

// Done is logical revocation, not teardown completion. Request contexts and the
// client's active-connection registry are canceled by this same batch context.
func watchCoreRun(ctx context.Context, handle *nodes.RunHandle, cancel context.CancelFunc) func() {
	stop, finished := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(finished)
		select {
		case <-stop:
		case <-ctx.Done():
		case <-handle.Done():
			cancel()
		}
	}()
	return func() { close(stop); <-finished }
}

// Fresh all-node sweep followed by state gates. This is not an atomic kernel
// snapshot or proof against an unobserved close/rebind after a successful check.
func (s *Service) publishCoreNodes(ctx context.Context, handle *nodes.RunHandle, rows []CoreNodeObservation) Report {
	reason := ""
	if err := handle.CheckAll(ctx); err != nil {
		reason = coreNodeReason(err)
	}
	if err := handle.Err(); err != nil {
		reason = coreNodeReason(err)
	}
	if err := ctx.Err(); err != nil && reason == "" {
		reason = coreNodeReason(err)
	}
	for _, row := range rows {
		if row.Status != "observed" && reason == "" {
			reason = "batch_incomplete"
		}
	}
	if reason != "" {
		return s.coreNodeReport(rows, "unavailable", reason)
	}
	return s.coreNodeReport(rows, "completed", "")
}
