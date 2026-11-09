package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestHistoryCorrectionScanErrorClosesRows(t *testing.T) {
	s := historyStore(t)
	if _, err := s.DB.Exec(`INSERT INTO history(ip,prefix,ts,asn,cc,type,flags) VALUES('192.0.2.1',NULL,100,NULL,'','unknown','')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Observations("192.0.2.1", time.Unix(0, 0), time.Unix(200, 0)); err == nil {
		t.Fatal("expected scan failure")
	}
	if _, err := s.HistoryUntil("192.0.2.1", time.Unix(0, 0), time.Unix(200, 0)); err == nil {
		t.Fatal("expected history scan failure")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var n int
	if err := s.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM history").Scan(&n); err != nil {
		t.Fatal(err)
	}
}
func TestHistoryCorrectionConcurrentMigration(t *testing.T) {
	for attempt := 0; attempt < 20; attempt++ {
		path := filepath.Join(t.TempDir(), "legacy.db")
		seed, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := seed.Exec(schema); err != nil {
			seed.Close()
			t.Fatal(err)
		}
		if _, err := seed.Exec(`INSERT INTO history(ip,prefix,ts,asn,cc,type,flags) VALUES('192.0.2.1','',100,0,'','unknown','')`); err != nil {
			seed.Close()
			t.Fatal(err)
		}
		seed.Close()
		start := make(chan struct{})
		errs := make(chan error, 8)
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				s, err := Open(path)
				if err == nil {
					obs, readErr := s.Observations("192.0.2.1", time.Unix(0, 0), time.Unix(200, 0))
					if readErr != nil {
						err = readErr
					} else if len(obs) != 1 || obs[0].Provenance != nil {
						err = fmt.Errorf("migration changed old evidence: %+v", obs)
					}
					s.Close()
				}
				errs <- err
			}()
		}
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("concurrent legacy Open attempt %d: %v", attempt, err)
			}
		}
	}
}

func TestHistoryCanonicalLegacyPublicPaths(t *testing.T) {
	for _, tc := range []struct{ legacy, canonical, bucket string }{
		{"2001:0DB8:0000:0000:0000:0000:0000:0001", "2001:db8::1", "2001:db8::/64"},
		{"::ffff:192.0.2.1", "192.0.2.1", "192.0.2.0/24"},
	} {
		t.Run(tc.canonical, func(t *testing.T) {
			s := historyStore(t)
			// Seed old keys directly: new public writes must no longer create aliases.
			for _, row := range []struct {
				ip  string
				ts  int
				typ string
			}{
				{tc.legacy, 100, "hosting"}, {tc.canonical, 101, "hosting"},
				{tc.legacy, 101, "unknown"}, {tc.canonical, 99, "hosting"},
			} {
				if _, err := s.DB.Exec(`INSERT INTO history(ip,prefix,ts,asn,cc,type,flags,provenance) VALUES(?,'fixture',?,0,'',?,'',NULL)`, row.ip, row.ts, row.typ); err != nil {
					t.Fatal(err)
				}
			}
			for _, key := range []string{tc.legacy, tc.canonical} {
				obs, err := s.Observations(key, time.Unix(0, 0), time.Unix(101, 0))
				if err != nil || len(obs) != 4 || obs[0].TS.Unix() != 99 || obs[3].Type != "unknown" || obs[3].Prefix != "fixture" || obs[3].Provenance != nil {
					t.Fatalf("observations %s: %+v %v", key, obs, err)
				}
				ev, err := s.HistoryUntil(key, time.Unix(0, 0), time.Unix(101, 0))
				if err != nil || len(ev) != 1 || ev[0].To != "unknown" || ev[0].TS.Unix() != 101 {
					t.Fatalf("events %s: %+v %v", key, ev, err)
				}
				all, err := s.History(key, time.Unix(0, 0))
				if err != nil || len(all) != 1 {
					t.Fatalf("history: %+v %v", all, err)
				}
			}
			n, err := s.LocalNeighbors(netip.MustParsePrefix(tc.bucket), time.Unix(0, 0), time.Unix(101, 0))
			if err != nil || n.ObservedAddresses != 1 || n.Types["unknown"] != 1 || n.Types["hosting"] != 0 {
				t.Fatalf("neighbors: %+v %v", n, err)
			}
			raw := json.RawMessage(`[{"id":"fixture"}]`)
			changed, err := s.AddHistoryWithProvenance(tc.legacy, "", "", "hosting", "", 0, time.Unix(102, 0), raw)
			if err != nil || !changed {
				t.Fatalf("write must compare legacy latest: %v %v", changed, err)
			}
			var stored string
			if err := s.DB.QueryRow("SELECT ip FROM history ORDER BY id DESC LIMIT 1").Scan(&stored); err != nil || stored != tc.canonical {
				t.Fatalf("new key %s: %v", stored, err)
			}
			obs, err := s.Observations(tc.legacy, time.Unix(102, 0), time.Unix(102, 0))
			if err != nil || len(obs) != 1 || string(obs[0].Provenance) != string(raw) {
				t.Fatalf("provenance: %+v %v", obs, err)
			}
			changed, err = s.AddHistory(tc.legacy, "", "", "hosting", "", 0, time.Unix(103, 0))
			if err != nil || changed {
				t.Fatalf("AddHistory canonical latest comparison: %v %v", changed, err)
			}
			if err := s.DB.QueryRow("SELECT ip FROM history ORDER BY id DESC LIMIT 1").Scan(&stored); err != nil || stored != tc.canonical {
				t.Fatalf("AddHistory new key %s: %v", stored, err)
			}
			var legacy int
			if err := s.DB.QueryRow("SELECT COUNT(*) FROM history WHERE ip=?", tc.legacy).Scan(&legacy); err != nil || legacy != 2 {
				t.Fatalf("legacy rows rewritten: %d %v", legacy, err)
			}
		})
	}
	s := historyStore(t)
	for _, key := range []string{"fe80::1%fixture", "not-an-address"} {
		if _, err := s.AddHistory(key, "", "", "", "", 0, time.Now()); err == nil {
			t.Fatal("invalid/zone write accepted")
		}
		if _, err := s.Observations(key, time.Time{}, time.Now()); err == nil {
			t.Fatal("invalid/zone read accepted")
		}
		if _, err := s.HistoryUntil(key, time.Time{}, time.Now()); err == nil {
			t.Fatal("invalid/zone events accepted")
		}
	}
}

func TestHistoryMigrationPropagatesFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("CREATE TABLE history(wrong TEXT)"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if s, err := Open(path); err == nil {
		s.Close()
		t.Fatal("unrelated schema failure swallowed")
	}
}
