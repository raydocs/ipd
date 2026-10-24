package lookup

import (
	"net/netip"
	"testing"
	"time"
)

func assertSnapshotClock(t *testing.T, e *Engine, now, want time.Time, age int64) {
	t.Helper()
	if at, seconds := e.SnapshotAge(now); !at.Equal(want) || seconds != age {
		t.Fatalf("SnapshotAge = %s, %d; want %s, %d", at, seconds, want, age)
	}
}

func TestFreshnessOldestSourceReplacement(t *testing.T) {
	for _, mode := range []string{"merge", "install", "reload"} {
		t.Run(mode, func(t *testing.T) {
			e := replacementEngine(t)
			bgp, dbip := replacementMeta("bgp", 1), replacementMeta("dbip_lite", 2)
			e.Reload([]SourceMeta{bgp, dbip}, append(replacementRows("bgp", 1), replacementRows("dbip_lite", 2)...))
			now := replacementAt.Add(10 * time.Hour)
			assertSnapshotClock(t, e, now, bgp.UpdatedAt, 9*3600)
			bgp = replacementMeta("bgp", 3)
			switch mode {
			case "merge":
				e.MergeSource(bgp, replacementRows("bgp", 3))
			case "install":
				installReplacement(t, e, bgp, replacementRows("bgp", 3))
			case "reload":
				e.Reload([]SourceMeta{bgp, dbip}, append(replacementRows("bgp", 3), replacementRows("dbip_lite", 2)...))
			}
			assertSnapshotClock(t, e, now, dbip.UpdatedAt, 8*3600)
			// Non-clock sources do not make the prefix table look older or newer.
			e.MergeSource(replacementMeta("cloud_ranges", -100), replacementRows("cloud_ranges", 4))
			assertSnapshotClock(t, e, now, dbip.UpdatedAt, 8*3600)
			assertSnapshotClock(t, e, replacementAt, dbip.UpdatedAt, 0)
		})
	}
}

func TestFreshnessUnknownReplacement(t *testing.T) {
	for _, mode := range []string{"merge", "install", "reload"} {
		t.Run(mode, func(t *testing.T) {
			e := replacementEngine(t)
			bgp, dbip := replacementMeta("bgp", 1), replacementMeta("dbip_lite", 2)
			e.Reload([]SourceMeta{bgp, dbip}, append(replacementRows("bgp", 1), replacementRows("dbip_lite", 2)...))
			bgp.UpdatedAt = time.Time{}
			switch mode {
			case "merge":
				e.MergeSource(bgp, replacementRows("bgp", 3))
			case "install":
				installReplacement(t, e, bgp, replacementRows("bgp", 3))
			case "reload":
				e.Reload([]SourceMeta{bgp, dbip}, append(replacementRows("bgp", 3), replacementRows("dbip_lite", 2)...))
			}
			for _, m := range e.Sources(replacementAt.Add(100 * time.Hour)) {
				if m.ID == "bgp" && (!m.UpdatedAt.IsZero() || m.Stale) {
					t.Fatalf("unknown source time was fabricated or treated as known stale: %+v", m)
				}
			}
			assertSnapshotClock(t, e, replacementAt.Add(100*time.Hour), time.Time{}, 0)
			// Unknown is not sticky: an authoritative replacement can restore it,
			// including an older source time (never the local replacement time).
			e.MergeSource(replacementMeta("bgp", -1), replacementRows("bgp", 4))
			assertSnapshotClock(t, e, replacementAt, replacementAt.Add(-time.Hour), 3600)
		})
	}
}

func TestFreshnessStaleAndUnknown(t *testing.T) {
	e := replacementEngine(t)
	m := replacementMeta("bgp", 1)
	e.MergeSource(m, replacementRows("bgp", 1))
	for _, tc := range []struct {
		elapsed time.Duration
		stale   bool
	}{{-time.Hour, false}, {48 * time.Hour, false}, {48*time.Hour + time.Second, true}} {
		now := m.UpdatedAt.Add(tc.elapsed)
		if got := e.Sources(now)[0].Stale; got != tc.stale {
			t.Fatalf("stale at %s = %v", tc.elapsed, got)
		}
	}
	for _, freq := range []string{"hour", "day", "week", "month", "unknown"} {
		m.Frequency = freq
		m.UpdatedAt = time.Time{}
		if Stale(m, replacementAt) {
			t.Fatalf("unknown timestamp cannot prove staleness: %s", freq)
		}
	}
	m = replacementMeta("bgp", 1)
	m.Enabled = false
	if Stale(m, replacementAt.Add(1000*time.Hour)) {
		t.Fatal("disabled source marked stale")
	}
}

func TestFreshnessOnlyLoadedSources(t *testing.T) {
	e := replacementEngine(t)
	// A metadata-only placeholder is not a prefix snapshot clock.
	e.Reload([]SourceMeta{replacementMeta("bgp", -100), replacementMeta("cloud_ranges", 2)}, replacementRows("cloud_ranges", 2))
	assertSnapshotClock(t, e, replacementAt.Add(3*time.Hour), replacementMeta("cloud_ranges", 2).UpdatedAt, 3600)
	// A queryable source without metadata is not known enabled, so it does
	// not participate in the clock of an explicitly enabled source.
	e.Reload([]SourceMeta{replacementMeta("dbip_lite", 2)}, append(replacementRows("bgp", 1), replacementRows("dbip_lite", 2)...))
	assertSnapshotClock(t, e, replacementAt.Add(3*time.Hour), replacementMeta("dbip_lite", 2).UpdatedAt, 3600)
	// Reload also removes old clock sources rather than retaining their time.
	e.Reload([]SourceMeta{replacementMeta("cloud_ranges", 3)}, replacementRows("cloud_ranges", 3))
	assertSnapshotClock(t, e, replacementAt.Add(4*time.Hour), replacementMeta("cloud_ranges", 3).UpdatedAt, 3600)
}

func TestFreshnessFallbackUnknown(t *testing.T) {
	e := replacementEngine(t)
	known := replacementMeta("cloud_ranges", 1)
	e.MergeSource(known, replacementRows("cloud_ranges", 1))
	assertSnapshotClock(t, e, replacementAt.Add(2*time.Hour), known.UpdatedAt, 3600)
	unknown := replacementMeta("geofeed", 2)
	unknown.UpdatedAt = time.Time{}
	installReplacement(t, e, unknown, replacementRows("geofeed", 2))
	assertSnapshotClock(t, e, replacementAt.Add(2*time.Hour), time.Time{}, 0)
	// Primary clocks remain authoritative when another loaded source is unknown.
	e.MergeSource(replacementMeta("bgp", 3), replacementRows("bgp", 3))
	assertSnapshotClock(t, e, replacementAt.Add(4*time.Hour), replacementMeta("bgp", 3).UpdatedAt, 3600)
}

func TestFreshnessReloadEnabledClock(t *testing.T) {
	known := replacementAt.Add(time.Hour)
	older := replacementAt.Add(-time.Hour)
	unknown := time.Time{}
	meta := func(id string, enabled bool, at time.Time) SourceMeta {
		m := replacementMeta(id, 1)
		m.Enabled, m.UpdatedAt = enabled, at
		return m
	}
	for _, tc := range []struct {
		name string
		meta []SourceMeta
		ids  []string
		want time.Time
	}{
		{"primary_disabled_old", []SourceMeta{meta("bgp", false, older), meta("dbip_lite", true, known)}, []string{"bgp", "dbip_lite"}, known},
		{"primary_disabled_unknown", []SourceMeta{meta("bgp", true, known), meta("dbip_lite", false, unknown)}, []string{"bgp", "dbip_lite"}, known},
		{"disabled_primary_uses_fallback", []SourceMeta{meta("bgp", false, older), meta("dbip_lite", false, unknown), meta("cloud_ranges", true, known)}, []string{"bgp", "dbip_lite", "cloud_ranges"}, known},
		{"fallback_disabled_old", []SourceMeta{meta("cloud_ranges", true, known), meta("geofeed", false, older), meta("peeringdb", true, known.Add(time.Hour))}, []string{"cloud_ranges", "geofeed", "peeringdb"}, known},
		{"fallback_disabled_unknown", []SourceMeta{meta("geofeed", false, unknown), meta("cloud_ranges", true, known)}, []string{"geofeed", "cloud_ranges"}, known},
		{"primary_enabled_unknown", []SourceMeta{meta("bgp", true, unknown), meta("dbip_lite", false, older), meta("cloud_ranges", true, known)}, []string{"bgp", "dbip_lite", "cloud_ranges"}, unknown},
		{"fallback_enabled_unknown", []SourceMeta{meta("cloud_ranges", true, unknown), meta("geofeed", false, older)}, []string{"cloud_ranges", "geofeed"}, unknown},
		{"no_enabled_primary", []SourceMeta{meta("bgp", false, older), meta("dbip_lite", false, known)}, []string{"bgp", "dbip_lite"}, unknown},
		{"no_enabled_fallback", []SourceMeta{meta("geofeed", false, known), meta("cloud_ranges", false, older)}, []string{"geofeed", "cloud_ranges"}, unknown},
		{"enabled_but_not_loaded", []SourceMeta{meta("bgp", true, known), meta("cloud_ranges", false, older)}, []string{"cloud_ranges"}, unknown},
		{"missing_primary_metadata", []SourceMeta{meta("cloud_ranges", true, known)}, []string{"bgp", "cloud_ranges"}, known},
		{"missing_fallback_metadata", []SourceMeta{meta("cloud_ranges", true, known)}, []string{"geofeed", "cloud_ranges"}, known},
		{"no_enabled_metadata", nil, []string{"bgp", "cloud_ranges"}, unknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := replacementEngine(t)
			var rows []SourceRow
			for i, id := range tc.ids {
				rows = append(rows, replacementRows(id, i+1)...)
			}
			e.Reload(tc.meta, rows)
			// Enabled gates the clock, not query participation: even disabled or
			// metadata-less rows must remain loaded and visible to callers.
			p := e.Lookup(netip.MustParseAddr("9.9.9.9"))
			if len(p.Hits) != len(rows) {
				t.Fatalf("clock filtering changed query data: %+v", p.Hits)
			}
			for _, row := range rows {
				if rec, ok := e.Covering(row.Source, netip.MustParsePrefix(row.Rec.Prefix)); !ok || rec.ASN != row.Rec.ASN {
					t.Fatalf("source %s no longer queryable: %+v, %v", row.Source, rec, ok)
				}
			}
			if got := e.Sources(known); len(got) != len(tc.meta) {
				t.Fatalf("metadata changed during clock selection: %+v", got)
			}
			now := known.Add(time.Hour)
			var age int64
			if !tc.want.IsZero() {
				age = int64(now.Sub(tc.want) / time.Second)
			}
			assertSnapshotClock(t, e, now, tc.want, age)
			for _, got := range e.Sources(now) {
				for _, want := range tc.meta {
					if got.ID == want.ID && (got.Enabled != want.Enabled || !got.UpdatedAt.Equal(want.UpdatedAt)) {
						t.Fatalf("clock selection changed metadata: got %+v, want %+v", got, want)
					}
				}
			}
		})
	}
}
