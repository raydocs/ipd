package nodes

import (
	"context"
	"errors"
	"maps"
)

// All publication and invalidation transitions share r.mu. Never hold it across
// process/kernel/filesystem operations: revocation must not await teardown.
func (r *execRun) invalidateLocked(cause error) bool {
	if cause == nil || r.cause != nil {
		return false
	}
	if err := r.ctx.Err(); err != nil && !errors.Is(cause, err) {
		cause = errors.Join(cause, err)
	}
	r.generation++
	r.cause = cause
	r.err = cause
	r.endpoints = nil
	close(r.invalid)
	return true
}
func (r *execRun) invalidate(cause error) {
	r.mu.Lock()
	first := r.invalidateLocked(cause)
	r.mu.Unlock()
	if first {
		r.cancel()
	}
}

// The callbacks make revocation prompt; these synchronous checks also prevent
// readers/publication from depending on the scheduling of a context callback.
func (r *execRun) validityLocked() error {
	if r.cause != nil {
		return r.cause
	}
	if err := r.ctx.Err(); err != nil {
		r.invalidateLocked(err)
	} else if r.starting && r.startup != nil && r.startup.Err() != nil {
		r.invalidateLocked(readinessError(r.ctx))
	}
	return r.cause
}
func (r *execRun) watchStartup(ctx context.Context) func() bool {
	r.mu.Lock()
	r.startup = ctx
	r.mu.Unlock()
	return context.AfterFunc(ctx, func() {
		r.mu.Lock()
		first := false
		if r.starting {
			first = r.invalidateLocked(readinessError(r.ctx))
		}
		r.mu.Unlock()
		if first {
			r.cancel()
		}
	})
}

func (r *execRun) publish(endpoints map[string]Endpoint) error {
	r.mu.Lock()
	err := r.validityLocked()
	if err == nil {
		r.endpoints = endpoints
		// One buffered notice, not a snapshot/capability that can outlive the batch.
		// The receiver must still accept success through this same state gate.
		r.ready <- startResult{}
	}
	r.mu.Unlock()
	if err != nil {
		r.cancel()
	}
	return err
}
func (r *execRun) acceptReady() (map[string]string, error) {
	r.mu.Lock()
	err := r.validityLocked()
	var socks map[string]string
	if err == nil {
		r.starting = false // Startup deadline no longer applies after accepting success.
		socks = make(map[string]string, len(r.endpoints))
		for name, endpoint := range r.endpoints {
			socks[name] = endpoint.SOCKS
		}
	}
	r.mu.Unlock()
	if err != nil {
		r.cancel()
	}
	return socks, err
}
func (r *execRun) liveEndpoints() map[string]Endpoint {
	r.mu.Lock()
	err := r.validityLocked()
	endpoints := maps.Clone(r.endpoints)
	r.mu.Unlock()
	if err != nil {
		r.cancel()
		return nil
	}
	return endpoints
}
func (r *execRun) failure() error {
	r.mu.Lock()
	err := r.validityLocked()
	r.mu.Unlock()
	if err != nil {
		r.cancel()
	}
	return err
}
func (r *execRun) terminalError() error {
	r.mu.Lock()
	cause := r.validityLocked()
	err := r.err
	r.mu.Unlock()
	if cause != nil {
		r.cancel()
	}
	return err
}

// Closing the child's done signal and revoking the batch are one transition.
// A queued success or an in-progress owner sweep cannot overwrite this state.
func (r *execRun) childExited(child coreProcess) {
	r.mu.Lock()
	close(child.done)
	first := r.invalidateLocked(ErrRunnerExit)
	r.mu.Unlock()
	if first {
		r.cancel()
	}
}
func (r *execRun) finish(err error) {
	r.invalidate(err)
	r.mu.Lock()
	if !errors.Is(err, r.cause) {
		err = errors.Join(r.cause, err)
	}
	r.err = err
	r.endpoints = nil
	r.mu.Unlock()
	if err != nil {
		select {
		case r.ready <- startResult{err: err}:
		default:
		}
	}
	close(r.done)
}

// A pending lifetime cancellation/deadline must not be relabeled as a normal
// Stop merely because its AfterFunc has not been scheduled yet.
func (r *execRun) stop() {
	r.mu.Lock()
	if r.validityLocked() == nil {
		r.invalidateLocked(errors.Join(ErrRunnerStopped, context.Canceled))
	}
	r.mu.Unlock()
	r.cancel()
}
