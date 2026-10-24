// Package app is the use-case layer shared by HTTP, the CLI, and MCP.
package app

import (
	"time"

	"ipd/internal/lookup"
)

// Source is one attribution row on a response.
type Source struct {
	ID          string `json:"id"`
	Attribution string `json:"attribution,omitempty"`
	License     string `json:"license,omitempty"`
	Raw         any    `json:"raw,omitempty"`
}

// Report is the envelope every surface renders.
type Report struct {
	Verdict            string    `json:"verdict"`
	Summary            string    `json:"summary_md"`
	Data               any       `json:"data"`
	Sources            []Source  `json:"sources"`
	CachedAt           time.Time `json:"cached_at"`
	Attribution        []string  `json:"attribution"`
	SnapshotAt         time.Time `json:"snapshot_at"`
	SnapshotAgeSeconds int64     `json:"snapshot_age_seconds"`
}

// WithSnapshot copies the prefix-snapshot clock onto a response.
func (s *Service) WithSnapshot(r Report) Report {
	if s == nil || s.Look == nil {
		return r
	}
	at, age := s.Look.SnapshotAge(s.now())
	r.SnapshotAt = at
	r.SnapshotAgeSeconds = age
	return r
}

func conflictsOrEmpty(p lookup.Profile) []lookup.Conflict {
	if len(p.Conflicts) == 0 {
		return []lookup.Conflict{}
	}
	return p.Conflicts
}

func (r Report) CachedAtRFC() string {
	if r.CachedAt.IsZero() {
		return time.Now().UTC().Format(time.RFC3339)
	}
	return r.CachedAt.UTC().Format(time.RFC3339)
}

// ExitCode is 0 ok, 10 risky, 20 blocked.
func ExitCode(verdict string) int {
	switch verdict {
	case "ok", "safe", "native", "yes", "reserved":
		return 0
	case "ok_with_caveats", "risky", "abstain", "partial", "broadcast", "originals_only", "web_only", "app_only", "congested", "carrier_partial", "insufficient_sample", "cannot determine":
		return 10
	default:
		return 20
	}
}

func sourcesFrom(p lookup.Profile) []Source {
	out := make([]Source, 0, len(p.Hits))
	seen := map[string]bool{}
	for _, h := range p.Hits {
		if seen[h.Source] {
			continue
		}
		seen[h.Source] = true
		out = append(out, Source{ID: h.Source, Raw: map[string]any{
			"cc": h.Rec.CC, "asn": h.Rec.ASN, "as_type": h.Rec.ASType, "org": h.Rec.Org, "prefix": h.Rec.Prefix,
		}})
	}
	if out == nil {
		out = []Source{}
	}
	return out
}
