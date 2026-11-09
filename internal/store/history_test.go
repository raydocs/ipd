package store

import (
	"database/sql"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func historyStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestHistoryRetentionBoundary(t *testing.T) {
	s := historyStore(t)
	now := time.Unix(1800000000, 0)
	for _, offset := range []time.Duration{-25 * time.Hour, -24 * time.Hour, -time.Hour, time.Hour} {
		if _, err := s.AddHistory("192.0.2.1", "192.0.2.0/24", "", "unknown", "vpn", 0, now.Add(offset)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.PurgeHistory(now, 0); err == nil {
		t.Fatal("zero retention accepted")
	}
	if _, err := s.PurgeHistory(now, -time.Hour); err == nil {
		t.Fatal("negative retention accepted")
	}
	n, err := s.PurgeHistory(now, 24*time.Hour)
	if err != nil || n != 1 {
		t.Fatalf("purged %d: %v", n, err)
	}
	obs, err := s.Observations("192.0.2.1", now.Add(-24*time.Hour), now)
	if err != nil || len(obs) != 2 || obs[0].Provenance != nil || obs[0].Flags != "vpn" {
		t.Fatalf("%+v %v", obs, err)
	}
	// Future evidence must not create a current change.
	if _, err := s.AddHistory("192.0.2.1", "", "US", "hosting", "", 64500, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	ev, err := s.HistoryUntil("192.0.2.1", now.Add(-24*time.Hour), now)
	if err != nil || len(ev) != 0 {
		t.Fatalf("events %v %v", ev, err)
	}
}

func TestHistoryMigrationAndProvenance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE history(id INTEGER PRIMARY KEY,ip TEXT,prefix TEXT,ts INTEGER,asn INTEGER,cc TEXT,type TEXT,flags TEXT);
 INSERT INTO history VALUES(1,'192.0.2.1','192.0.2.0/24',100,0,'','unknown','');`)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.migrate(); err != nil {
		t.Fatal(err)
	}
	raw := json.RawMessage(`[{"id":"fixture","version":"v1"}]`)
	if _, err := s.AddHistoryWithProvenance("192.0.2.1", "", "", "unknown", "", 0, time.Unix(101, 0), raw); err != nil {
		t.Fatal(err)
	}
	rows, err := s.Observations("192.0.2.1", time.Unix(0, 0), time.Unix(102, 0))
	if err != nil || len(rows) != 2 || rows[0].Provenance != nil || string(rows[1].Provenance) != string(raw) {
		t.Fatalf("%+v %v", rows, err)
	}
	if _, err := s.AddHistoryWithProvenance("192.0.2.1", "", "", "", "", 0, time.Now(), json.RawMessage("{")); err == nil {
		t.Fatal("invalid JSON accepted")
	}
}

func TestLocalNeighborsLatestIPv6AndConcurrent(t *testing.T) {
	s := historyStore(t)
	now := time.Unix(1800000000, 0)
	for _, row := range []struct{ ip, typ string }{
		{"2001:db8::1", "hosting"}, {"2001:db8::1", "unknown"},
		{"2001:db8::2", ""}, {"2001:db8:0:1::1", "hosting"},
	} {
		if _, err := s.AddHistory(row.ip, "::/0", "", row.typ, "", 0, now); err != nil {
			t.Fatal(err)
		}
	}
	p := netip.MustParsePrefix("2001:db8::/64")
	n, err := s.LocalNeighbors(p, now.Add(-time.Hour), now)
	if err != nil || n.ObservedAddresses != 2 || n.Types["unknown"] != 2 || n.Types["hosting"] != 0 {
		t.Fatalf("%+v %v", n, err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.PurgeHistory(now, 24*time.Hour); err != nil {
				t.Error(err)
			}
			if _, err := s.LocalNeighbors(p, now.Add(-time.Hour), now); err != nil {
				t.Error(err)
			}
			if _, err := s.AddHistory("2001:db8::3", "", "", "unknown", "", 0, now); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}
