//go:build pr8_integration

package ingest

import (
	"path/filepath"
	"testing"
	"time"

	"ipd/internal/lookup"
)

// Requires the separately owned PR8 c9fcb30 lookup changes. The standalone
// baseline MergeSource fills unknown timestamps; that behavior is not fixed here.
func TestApplySnapshotPR8SourceTimes(t *testing.T) {
	for _, id := range []string{"r7_fixture", "bgp"} {
		t.Run(id, func(t *testing.T) {
			u, _ := feedTestUpdater(t)
			known := feedTestMeta(id).UpdatedAt
			// Cover both losing a previously known timestamp and a later known refresh.
			for _, at := range []time.Time{known, {}, known.Add(time.Hour)} {
				m := feedTestMeta(id)
				m.UpdatedAt = at
				if fr := u.apply(id, m, feedTestRows("fixture"), "", "", nil); fr.Err != "" || fr.Rows != 1 {
					t.Fatal(fr)
				}
				disk, err := readFeedSnapshot(filepath.Join(u.cfg.DataDir, "feeds", id+feedSnapshotSuffix), id)
				if err != nil {
					t.Fatal(err)
				}
				if !disk.Meta.UpdatedAt.Equal(at) {
					t.Errorf("disk source time %s, want %s", disk.Meta.UpdatedAt, at)
				}
				restarted := lookup.New()
				if err := Load(restarted, u.cfg); err != nil {
					t.Fatal(err)
				}
				for _, entry := range []struct {
					name string
					eng  *lookup.Engine
				}{{"live", u.eng}, {"reload", restarted}} {
					got := feedSource(t, entry.eng, id)
					if !got.UpdatedAt.Equal(at) {
						t.Errorf("%s source time %s, want %s", entry.name, got.UpdatedAt, at)
					}
					if got.Rows != 1 || !got.Enabled {
						t.Fatal(entry.name, got)
					}
					requireFeedRec(t, entry.eng, id, lookup.Rec{Prefix: "192.0.2.0/24", Org: "fixture"})
					if id == "bgp" && at.IsZero() {
						if clock, age := entry.eng.SnapshotAge(known.Add(24 * time.Hour)); !clock.IsZero() || age != 0 {
							t.Errorf("%s invented freshness: clock %s age %d", entry.name, clock, age)
						}
					}
				}
			}
		})
	}
}
