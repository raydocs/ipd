package probe

import (
	"errors"
	"sync"
	"time"
)

// ErrQuota is returned when a Globalping measurement would exceed the hourly
// allowance (250 anonymous, 500 with a token). Callers should report
// insufficient_sample instead of issuing the request.
var ErrQuota = errors.New("globalping: hourly quota exhausted")

// Health tracks whether a vantage probe itself is answering. A probe that
// fails its own check three times, with more failures than successes, is
// dropped from later verdicts. A target timeout is not a probe failure.
type Health struct {
	mu sync.Mutex
	n  map[string][2]int
}

// DefaultHealth is the process-wide probe health table.
var DefaultHealth Health

// Observe records one anchor result for id (typically "asn/city").
func (h *Health) Observe(id string, ok bool) {
	if h == nil || id == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.n == nil {
		h.n = map[string][2]int{}
	}
	cur := h.n[id]
	if ok {
		cur[0]++
	} else {
		cur[1]++
	}
	h.n[id] = cur
}

// Healthy reports whether id may vote. Unknown probes are healthy.
func (h *Health) Healthy(id string) bool {
	if h == nil || id == "" {
		return true
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	cur := h.n[id]
	if cur[0]+cur[1] < 3 {
		return true
	}
	return cur[1] < 3 || cur[0] >= cur[1]
}

type hourBudget struct {
	mu    sync.Mutex
	start time.Time
	used  int
}

func (b *hourBudget) take(limit int, now time.Time) error {
	if limit <= 0 {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.start.IsZero() || now.Sub(b.start) >= time.Hour {
		b.start = now
		b.used = 0
	}
	if b.used >= limit {
		return ErrQuota
	}
	b.used++
	return nil
}

// gpBudget counts measurement creates. Anonymous Globalping allows 250/hour;
// a token raises that to 500. Each create is also spaced by MinInterval.
var gpBudget hourBudget

func (g Globalping) reserve(now time.Time) error {
	limit := 250
	if g.Token != "" {
		limit = 500
	}
	return gpBudget.take(limit, now)
}
