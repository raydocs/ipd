package app

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	"ipd/internal/config"
	"ipd/internal/store"
)

func correctionSvc(t *testing.T) (*Service, time.Time) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s := New(&config.Config{Offline: true, DataDir: t.TempDir(), HistoryRetention: 90 * 24 * time.Hour}, db)
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return now }
	return s, now
}
func correctionAdd(t *testing.T, s *Service, ip, typ string, at time.Time) {
	t.Helper()
	if _, err := s.DB.DB.Exec(`INSERT INTO history(ip,prefix,ts,asn,cc,type,flags) VALUES(?,?,?,0,'',?,'')`, ip, "", at.Unix(), typ); err != nil {
		t.Fatal(err)
	}
}
func TestHistoryCorrectionLegacyAliasRoundTrip(t *testing.T) {
	s, now := correctionSvc(t)
	const ip = "2001:0DB8:0000:0000:0000:0000:0000:0001"
	correctionAdd(t, s, ip, "hosting", now.Add(-2*time.Hour))
	correctionAdd(t, s, ip, "unknown", now.Add(-time.Hour))
	rep, err := s.History(ip, 1)
	if err != nil {
		t.Fatal(err)
	}
	data := rep.Data.(map[string]any)
	snaps := data["snapshots"].([]store.Observation)
	ev := data["events"].([]store.Event)
	if len(snaps) != 2 || len(ev) != 1 {
		t.Fatalf("unchanged caller IP spelling lost retained legacy data: snapshots=%d events=%d verdict=%s neighbors=%+v", len(snaps), len(ev), rep.Verdict, data["neighbors"])
	}
}
func TestHistoryCorrectionCanonicalNeighborIdentity(t *testing.T) {
	for _, tc := range []struct{ old, canonical string }{
		{"2001:0db8:0:0:0:0:0:1", "2001:db8::1"},
		{"::ffff:192.0.2.1", "192.0.2.1"},
	} {
		t.Run(tc.canonical, func(t *testing.T) {
			s, now := correctionSvc(t)
			correctionAdd(t, s, tc.old, "hosting", now.Add(-2*time.Hour))
			correctionAdd(t, s, tc.canonical, "unknown", now.Add(-time.Hour))
			rep, err := s.History(tc.canonical, 1)
			if err != nil {
				t.Fatal(err)
			}
			n := rep.Data.(map[string]any)["neighbors"].(store.LocalNeighbors)
			if n.ObservedAddresses != 1 || n.Types["unknown"] != 1 || n.Types["hosting"] != 0 {
				t.Fatalf("one canonical address counted multiple times / stale type survived: %+v", n)
			}
		})
	}
}
func TestHistoryCorrectionCoherentConcurrentHistory(t *testing.T) {
	s, now := correctionSvc(t)
	const ip = "192.0.2.1"
	correctionAdd(t, s, ip, "unknown", now.Add(-time.Hour))
	stop := make(chan struct{})
	errs := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			select {
			case <-stop:
				return
			default:
			}
			typ := "hosting"
			if i%2 == 1 {
				typ = "unknown"
			}
			if _, err := s.DB.AddHistory(ip, "", "", typ, "", 0, now); err != nil {
				errs <- err
				return
			}
		}
	}()
	defer func() {
		close(stop)
		wg.Wait()
		select {
		case err := <-errs:
			t.Error(err)
		default:
		}
	}()
	for i := 0; i < 100; i++ {
		rep, err := s.History(ip, 1)
		if err != nil {
			t.Fatal(err)
		}
		data := rep.Data.(map[string]any)
		snaps := data["snapshots"].([]store.Observation)
		ev := data["events"].([]store.Event)
		want := 0
		for j := 1; j < len(snaps); j++ {
			if snaps[j].Type != snaps[j-1].Type {
				want++
			}
		}
		if len(ev) != want {
			t.Fatalf("same response combines different database states on read %d: snapshots=%d imply %d type changes, events=%d", i, len(snaps), want, len(ev))
		}
	}
}
