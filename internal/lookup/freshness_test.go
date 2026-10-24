package lookup

import (
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
	// A queryable primary source without metadata must not inherit another
	// source's timestamp.
	e.Reload([]SourceMeta{replacementMeta("dbip_lite", 2)}, append(replacementRows("bgp", 1), replacementRows("dbip_lite", 2)...))
	assertSnapshotClock(t, e, replacementAt, time.Time{}, 0)
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
