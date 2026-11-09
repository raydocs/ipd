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

// Anchor history is process-local and bounded, not a calibrated probability.
const (
	anchorTTL       = 24 * time.Hour
	maxAnchorEvents = 32
	maxAnchorProbes = 1024
)

type anchorEvent struct {
	id string
	at time.Time
	ok bool
}

// AnchorHistory exposes the finite observation window. Weight is an observed
// anchor success fraction, nil until three observations exist (unknown).
type AnchorHistory struct {
	Known        bool       `json:"known"`
	Samples      int        `json:"samples"`
	Failures     int        `json:"failures"`
	Weight       *float64   `json:"weight"`
	LastObserved *time.Time `json:"last_observed,omitempty"`
}

// Health accepts only independent anchor observations, never target results.
// Keys identify provider vantage buckets (Globalping uses ASN/city, not a
// guaranteed physical probe). Zero value is ready for use; do not copy it.
type Health struct {
	mu  sync.Mutex
	n   map[string][]anchorEvent
	now func() time.Time // deterministic clock in package tests; fixed before use
}

var DefaultHealth Health

func (h *Health) clock() time.Time {
	if h.now != nil {
		return h.now()
	}
	return time.Now()
}

// Observe is the legacy anchor-only entry point without replay protection.
// Prefer ObserveAnchor with a stable measurement/event ID for retried results.
func (h *Health) Observe(id string, ok bool) { h.observe(id, "", ok) }

// ObserveAnchor records an independent anchor once per retained event ID and
// vantage bucket. Empty identities are rejected. Evicted/expired events cannot
// be deduplicated: this is bounded recent history, not a durable event ledger.
func (h *Health) ObserveAnchor(id, eventID string, ok bool) bool {
	if eventID == "" {
		return false
	}
	return h.observe(id, eventID, ok)
}

func (h *Health) prune(now time.Time) {
	for id, events := range h.n {
		kept := events[:0]
		for _, e := range events {
			if !e.at.After(now) && now.Sub(e.at) < anchorTTL {
				kept = append(kept, e)
			}
		}
		if len(kept) == 0 {
			delete(h.n, id)
		} else {
			h.n[id] = kept
		}
	}
}

func (h *Health) observe(id, eventID string, ok bool) bool {
	if h == nil || id == "" {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.clock()
	h.prune(now)
	if h.n == nil {
		h.n = map[string][]anchorEvent{}
	}
	events := h.n[id]
	for _, e := range events {
		if eventID != "" && e.id == eventID {
			return false
		}
	}
	if len(events) == 0 && len(h.n) >= maxAnchorProbes {
		// Oldest bucket first, with deterministic tie breaking.
		oldest := ""
		for key, es := range h.n {
			if oldest == "" || es[len(es)-1].at.Before(h.n[oldest][len(h.n[oldest])-1].at) ||
				(es[len(es)-1].at.Equal(h.n[oldest][len(h.n[oldest])-1].at) && key < oldest) {
				oldest = key
			}
		}
		delete(h.n, oldest)
	}
	if len(events) >= maxAnchorEvents {
		events = events[1:]
	}
	h.n[id] = append(events, anchorEvent{id: eventID, at: now, ok: ok})
	return true
}

// Snapshot returns a detached value; expiry restores explicit unknown history.
func (h *Health) Snapshot(id string) AnchorHistory {
	var out AnchorHistory
	if h == nil || id == "" {
		return out
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.prune(h.clock())
	events := h.n[id]
	out.Samples = len(events)
	for _, e := range events {
		if !e.ok {
			out.Failures++
		}
	}
	if len(events) > 0 {
		at := events[len(events)-1].at
		out.LastObserved = &at
	}
	if len(events) >= 3 {
		out.Known = true
		weight := float64(len(events)-out.Failures) / float64(len(events))
		out.Weight = &weight
	}
	return out
}

// Healthy preserves the original binary anchor gate within the recent window.
// Unknown history may vote, but is not evidence of reliability.
func (h *Health) Healthy(id string) bool {
	s := h.Snapshot(id)
	return s.Failures < 3 || s.Samples-s.Failures >= s.Failures
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
