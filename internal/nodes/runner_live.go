package nodes

import (
	"context"
	"errors"
	"time"
)

// Fixed upper bounds, not a promise of atomicity or hard real-time scheduling.
const (
	ownerQueryBudget     = 500 * time.Millisecond
	ownerSweepBudget     = 5 * time.Second
	ownerMonitorInterval = 100 * time.Millisecond
)

type ownerQuery func(context.Context, int, int) (bool, error)
type ownedEndpoint struct {
	name     string
	endpoint Endpoint
	child    coreProcess
	port     int
}

// RunHandle is an opaque capability for one successful Start. Do not copy a
// handle's endpoint URLs into public output. A handle never follows a restart.
// Checks observe kernel ownership, not end-to-end receiver authentication.
type RunHandle struct{ run *execRun }

// Done closes on logical revocation, BEFORE slow queries/reaping/cleanup finish.
func (h *RunHandle) Done() <-chan struct{} { return h.run.invalid }

// Err preserves the initial reason, later joining cleanup errors. Explicit Stop
// is ErrRunnerStopped (also context.Canceled); it is not a measurement failure.
func (h *RunHandle) Err() error { return h.run.terminalError() }

// Check verifies the exact name/endpoint/run binding and fresh kernel ownership.
// Cancellation of a check revokes the WHOLE run, not only this call. Supply a
// node context here to apply its deadline as well as the run's batch deadline.
func (h *RunHandle) Check(ctx context.Context, name string, expected Endpoint) error {
	return h.run.checkOwnership(ctx, name, &expected)
}

// CheckAll sweeps the fixed ordered nodes and accepts only through the same
// generation/lifetime gate after the last query. It is not an atomic OS snapshot.
func (h *RunHandle) CheckAll(ctx context.Context) error {
	return h.run.checkOwnership(ctx, "", nil)
}

// queryListener bounds even an OS query that fails to honor cancellation (e.g.
// a blocked proc read). No state lock spans this goroutine or its wait. The
// buffered result cannot resurrect a revoked run; monitor stops on first error.
func (r *execRun) queryListener(ctx context.Context, pid, port int) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, ownerQueryBudget)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	select {
	case <-r.invalid:
		return false, r.failure()
	default:
	}
	query := r.query
	if query == nil {
		query = runnerOwnsListener
	}
	type result struct {
		owned bool
		err   error
	}
	results := make(chan result, 1)
	go func() { owned, err := query(ctx, pid, port); results <- result{owned, err} }()
	select {
	case <-r.invalid:
		return false, r.failure()
	case <-ctx.Done():
		return false, ctx.Err()
	case got := <-results:
		if err := ctx.Err(); err != nil {
			return false, err
		}
		// Never expose raw kernel/tool errors or caller-provided fixture data.
		if got.err != nil {
			for _, cause := range []error{context.Canceled, context.DeadlineExceeded, ErrRunnerExit, ErrRunnerUnsupported} {
				if errors.Is(got.err, cause) {
					return false, errors.Join(ErrRunnerOwnership, cause)
				}
			}
			return false, ErrRunnerOwnership
		}
		return got.owned, nil
	}
}

func (r *execRun) checkOwnership(ctx context.Context, name string, expected *Endpoint) error {
	r.mu.Lock()
	err := r.validityLocked()
	generation := r.generation
	owners := r.owners // Immutable after publication, not exposed to callers.
	if err == nil && r.starting {
		err = ErrRunnerOwnership
	}
	if err == nil && expected != nil {
		owners = nil
		for _, owner := range r.owners {
			if owner.name == name && owner.endpoint == *expected {
				owners = []ownedEndpoint{owner}
				break
			}
		}
	}
	if err == nil && len(owners) == 0 {
		err = ErrRunnerOwnership
	}
	r.mu.Unlock()
	if err != nil {
		r.invalidate(err)
		return r.failure()
	}
	// WithDeadline respects the earlier caller (node) deadline automatically.
	deadline := time.Now().Add(ownerSweepBudget)
	if d, ok := r.ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	checkCtx, cancel := context.WithDeadline(ctx, deadline)
	stop := context.AfterFunc(r.ctx, cancel)
	defer func() { stop(); cancel() }()
	for _, owner := range owners {
		if err = r.requireOwner(checkCtx, owner.child, owner.port); err != nil {
			r.invalidate(err)
			return r.failure()
		}
		if err = r.failure(); err != nil {
			return err
		}
	}
	// This is a state-generation gate, NOT an assertion that an earlier socket
	// cannot change during a later query. Observed concurrent failure wins.
	r.mu.Lock()
	err = r.validityLocked()
	if err == nil {
		err = checkCtx.Err()
	}
	if err == nil && r.generation != generation {
		err = ErrRunnerOwnership
	}
	first := r.invalidateLocked(err)
	r.mu.Unlock()
	if first {
		r.cancel()
	}
	return err
}

func (r *execRun) monitorOwnership() {
	tick := time.NewTicker(ownerMonitorInterval)
	defer tick.Stop()
	for {
		select {
		case <-r.invalid:
			return
		case <-tick.C:
			if r.checkOwnership(r.ctx, "", nil) != nil {
				return
			}
		}
	}
}
