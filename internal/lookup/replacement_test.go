package lookup

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

var replacementAt = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

func replacementMeta(id string, generation int) SourceMeta {
	return SourceMeta{ID: id, Version: fmt.Sprint(generation), UpdatedAt: replacementAt.Add(time.Duration(generation) * time.Hour), Frequency: "day", Enabled: true}
}

func replacementRows(id string, generation int) []SourceRow {
	return []SourceRow{{Source: id, Rec: Rec{Prefix: "9.9.9.0/24", ASN: 65000 + generation, Org: fmt.Sprint(generation), CC: "US", ASType: "hosting"}}}
}

func replacementEngine(t *testing.T) *Engine {
	t.Helper()
	e := &Engine{}
	t.Cleanup(func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		for _, mt := range e.mapped {
			if err := mt.Close(); err != nil {
				t.Error(err)
			}
		}
	})
	return e
}

func replacementFile(t *testing.T, meta SourceMeta, rows []SourceRow) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "source.ipds")
	b := NewSnapshotBuilder(meta)
	for _, row := range rows {
		b.Add(row.Rec)
	}
	if err := b.CommitFile(path); err != nil {
		t.Fatal(err)
	}
	return path
}

func installReplacement(t *testing.T, e *Engine, meta SourceMeta, rows []SourceRow) {
	t.Helper()
	if n, err := e.InstallSnapshot(replacementFile(t, meta, rows)); err != nil || n != len(rows) {
		t.Fatalf("InstallSnapshot = %d, %v", n, err)
	}
}

func assertReplacement(t *testing.T, e *Engine, id string, generation int, mapped bool) {
	t.Helper()
	want := replacementRows(id, generation)[0].Rec
	ip := netip.MustParseAddr("9.9.9.9")
	p := e.Lookup(ip)
	if len(p.Hits) != 1 || p.Hits[0].Source != id || p.ASN != want.ASN || p.Org != want.Org {
		t.Fatalf("lookup generation %d: %+v", generation, p)
	}
	if rec, ok := e.Covering(id, netip.MustParsePrefix(want.Prefix)); !ok || rec.ASN != want.ASN {
		t.Fatalf("covering generation %d: %+v, %v", generation, rec, ok)
	}
	if info := e.ASNInfo(want.ASN); len(info.PrefixesV4) != 1 || info.Org != want.Org {
		t.Fatalf("ASN generation %d: %+v", generation, info)
	}
	if comp := e.Composition(want.Prefix); comp.Composition["hosting"] != 1 {
		t.Fatalf("composition generation %d: %+v", generation, comp)
	}
	meta := replacementMeta(id, generation)
	sources := e.Sources(meta.UpdatedAt)
	if len(sources) != 1 || sources[0].Version != meta.Version || !sources[0].UpdatedAt.Equal(meta.UpdatedAt) || sources[0].Rows != 1 {
		t.Fatalf("sources generation %d: %+v", generation, sources)
	}
	if at, age := e.SnapshotAge(meta.UpdatedAt.Add(time.Hour)); !at.Equal(meta.UpdatedAt) || age != 3600 {
		t.Fatalf("clock generation %d: %s, %d", generation, at, age)
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if mapped {
		if e.tables[id] != nil || e.mapped[id] == nil {
			t.Fatal("mapped source must have exactly one backing table")
		}
	} else if e.tables[id] == nil || e.mapped[id] != nil {
		t.Fatal("memory source must have exactly one backing table")
	}
}

func assertReleased(t *testing.T, mt *mappedTable) {
	t.Helper()
	if mt.data != nil || mt.f != nil {
		t.Fatal("retired snapshot was not unmapped and closed")
	}
}

func TestReplacementMemoryMappedMemory(t *testing.T) {
	for _, id := range []string{"bgp", "dbip_lite"} {
		t.Run(id, func(t *testing.T) {
			e := replacementEngine(t)
			for _, generation := range []int{1, 2} {
				e.MergeSource(replacementMeta(id, generation), replacementRows(id, generation))
				assertReplacement(t, e, id, generation, false)
			}
			installReplacement(t, e, replacementMeta(id, 3), replacementRows(id, 3))
			assertReplacement(t, e, id, 3, true)
			old := e.mapped[id]
			installReplacement(t, e, replacementMeta(id, 4), replacementRows(id, 4))
			assertReplacement(t, e, id, 4, true)
			assertReleased(t, old)
			old = e.mapped[id]
			e.MergeSource(replacementMeta(id, 5), replacementRows(id, 5))
			assertReplacement(t, e, id, 5, false)
			assertReleased(t, old)
		})
	}
}

func TestReplacementMappedReload(t *testing.T) {
	e := replacementEngine(t)
	installReplacement(t, e, replacementMeta("bgp", 1), replacementRows("bgp", 1))
	installReplacement(t, e, replacementMeta("dbip_lite", 2), replacementRows("dbip_lite", 2))
	oldBGP, oldDBIP := e.mapped["bgp"], e.mapped["dbip_lite"]
	e.Reload([]SourceMeta{replacementMeta("bgp", 3)}, replacementRows("bgp", 3))
	assertReplacement(t, e, "bgp", 3, false)
	if _, ok := e.Covering("dbip_lite", netip.MustParsePrefix("9.9.9.0/24")); ok {
		t.Fatal("Reload retained a removed mapped source")
	}
	assertReleased(t, oldBGP)
	assertReleased(t, oldDBIP)
}

func TestReplacementFailureKeepsLastGood(t *testing.T) {
	for _, mapped := range []bool{false, true} {
		t.Run(fmt.Sprint(mapped), func(t *testing.T) {
			e := replacementEngine(t)
			if mapped {
				installReplacement(t, e, replacementMeta("bgp", 1), replacementRows("bgp", 1))
			} else {
				e.MergeSource(replacementMeta("bgp", 1), replacementRows("bgp", 1))
			}
			for _, rows := range [][]SourceRow{nil, {{Source: "bgp", Rec: Rec{Prefix: "invalid"}}}} {
				if n := e.MergeSource(replacementMeta("bgp", 2), rows); n != 0 {
					t.Fatalf("invalid merge accepted %d rows", n)
				}
				assertReplacement(t, e, "bgp", 1, mapped)
				e.Reload([]SourceMeta{replacementMeta("bgp", 2)}, rows)
				assertReplacement(t, e, "bgp", 1, mapped)
			}
			good := replacementFile(t, replacementMeta("bgp", 2), replacementRows("bgp", 2))
			raw, err := os.ReadFile(good)
			if err != nil {
				t.Fatal(err)
			}
			empty := append([]byte(nil), raw...)
			binary.LittleEndian.PutUint32(empty[16:20], 0)
			for name, data := range map[string][]byte{"corrupt": []byte("not a snapshot"), "truncated": raw[:len(raw)-1], "empty": empty} {
				path := filepath.Join(t.TempDir(), name)
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
				if _, err := e.InstallSnapshot(path); err == nil {
					t.Fatalf("%s replacement succeeded", name)
				}
				assertReplacement(t, e, "bgp", 1, mapped)
			}
			for _, path := range []string{filepath.Join(t.TempDir(), "missing"), replacementFile(t, replacementMeta("", 2), replacementRows("", 2))} {
				if _, err := e.InstallSnapshot(path); err == nil {
					t.Fatal("invalid replacement succeeded")
				}
				assertReplacement(t, e, "bgp", 1, mapped)
			}
		})
	}
}

// Pin a reader through retirement. No sleeps, random timings or network feeds:
// the writer starts while the reader owns the same lock Lookup uses.
func TestReplacementWaitsForMappedReader(t *testing.T) {
	for _, mode := range []string{"merge", "reload", "install"} {
		t.Run(mode, func(t *testing.T) {
			e := replacementEngine(t)
			installReplacement(t, e, replacementMeta("bgp", 1), replacementRows("bgp", 1))
			path := replacementFile(t, replacementMeta("bgp", 2), replacementRows("bgp", 2))
			e.mu.RLock()
			old := e.mapped["bgp"]
			started, done := make(chan struct{}), make(chan error, 1)
			go func() {
				close(started)
				var err error
				switch mode {
				case "merge":
					e.MergeSource(replacementMeta("bgp", 2), replacementRows("bgp", 2))
				case "reload":
					e.Reload([]SourceMeta{replacementMeta("bgp", 2)}, replacementRows("bgp", 2))
				case "install":
					_, err = e.InstallSnapshot(path)
				}
				done <- err
			}()
			<-started
			rec, ok := old.lookup(netip.MustParseAddr("9.9.9.9"))
			at := e.prefixAtLocked()
			meta := e.meta[e.byID["bgp"]]
			select {
			case <-done:
				e.mu.RUnlock()
				t.Fatal("replacement completed while old mapping was in use")
			default:
			}
			e.mu.RUnlock()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if !ok || rec.ASN != 65001 || !at.Equal(replacementMeta("bgp", 1).UpdatedAt) || meta.Version != "1" {
				t.Fatalf("pinned reader saw mixed generation: %+v, %s, %+v", rec, at, meta)
			}
			assertReleased(t, old)
			// Decoded strings must remain valid after unmapping.
			if rec.Org != "1" {
				t.Fatalf("retained record changed after unmapping: %+v", rec)
			}
			assertReplacement(t, e, "bgp", 2, mode == "install")
		})
	}
}

func TestReplacementConcurrentLookup(t *testing.T) {
	e := replacementEngine(t)
	e.MergeSource(replacementMeta("bgp", 1), replacementRows("bgp", 1))
	const rounds = 60
	paths := make([]string, rounds)
	for i := range paths {
		if i%3 == 0 {
			paths[i] = replacementFile(t, replacementMeta("bgp", i+2), replacementRows("bgp", i+2))
		}
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range rounds * 4 {
				p := e.Lookup(netip.MustParseAddr("9.9.9.9"))
				if len(p.Hits) != 1 || p.Org != fmt.Sprint(p.ASN-65000) {
					t.Errorf("mixed lookup: %+v", p)
					return
				}
				// Observe data and metadata in one read-side critical section;
				// separate public calls are not a multi-call transaction.
				e.mu.RLock()
				m := e.meta[e.byID["bgp"]]
				var rec Rec
				var ok bool
				if mt := e.mapped["bgp"]; mt != nil {
					rec, ok = mt.lookup(netip.MustParseAddr("9.9.9.9"))
				} else {
					rec, ok = e.tables["bgp"].Lookup(netip.MustParseAddr("9.9.9.9"))
				}
				at := e.prefixAtLocked()
				both := e.mapped["bgp"] != nil && e.tables["bgp"] != nil
				e.mu.RUnlock()
				if !ok || both || rec.Org != m.Version || !at.Equal(m.UpdatedAt) {
					t.Errorf("mixed publication: rec=%+v meta=%+v at=%s both=%v", rec, m, at, both)
					return
				}
				e.Covering("bgp", netip.MustParsePrefix("9.9.9.0/24"))
				e.Composition("9.9.9.0/24")
				e.ASNInfo(p.ASN)
				e.Sources(replacementAt)
				e.SnapshotAge(replacementAt)
			}
		}()
	}
	// Exercise all three same-source writers concurrently. Their scheduling is
	// intentionally unconstrained; every visible generation must be coherent.
	for mode := range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := mode; i < rounds; i += 3 {
				meta, rows := replacementMeta("bgp", i+2), replacementRows("bgp", i+2)
				switch mode {
				case 0:
					if _, err := e.InstallSnapshot(paths[i]); err != nil {
						t.Error(err)
					}
				case 1:
					e.MergeSource(meta, rows)
				case 2:
					e.Reload([]SourceMeta{meta}, rows)
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	// Establish a deterministic final generation after all writers complete.
	e.MergeSource(replacementMeta("bgp", rounds+2), replacementRows("bgp", rounds+2))
	assertReplacement(t, e, "bgp", rounds+2, false)
}
