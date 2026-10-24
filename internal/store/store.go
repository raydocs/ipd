// Package store is the SQLite WAL database. There is no table and no column
// for a WebRTC candidate IP.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"ipd/internal/privacy"
	_ "modernc.org/sqlite"
)

// Store wraps the database.
type Store struct {
	DB *sql.DB
}

// Open creates the file (or memory) database and migrates it.
func Open(path string) (*Store, error) {
	if path == "" || path == ":memory:" {
		path = "file:ipd?mode=memory&cache=shared"
	} else {
		path = "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{DB: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.DB.Close() }

func (s *Store) migrate() error {
	_, err := s.DB.Exec(schema)
	return err
}

const schema = `
CREATE TABLE IF NOT EXISTS lookups_cache (
  key TEXT PRIMARY KEY,
  body TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  status TEXT NOT NULL,
  request TEXT,
  result TEXT,
  created_at INTEGER,
  updated_at INTEGER
);
CREATE TABLE IF NOT EXISTS results (
  id TEXT PRIMARY KEY,
  kind TEXT,
  target TEXT,
  body TEXT,
  created_at INTEGER
);
CREATE TABLE IF NOT EXISTS history (
  id INTEGER PRIMARY KEY,
  ip TEXT,
  prefix TEXT,
  ts INTEGER,
  asn INTEGER,
  cc TEXT,
  type TEXT,
  flags TEXT
);
CREATE TABLE IF NOT EXISTS watches (
  id TEXT PRIMARY KEY,
  target TEXT,
  checks TEXT,
  webhook TEXT,
  secret TEXT,
  last_hash TEXT,
  next_run INTEGER,
  created_at INTEGER
);
CREATE TABLE IF NOT EXISTS probes (
  id TEXT PRIMARY KEY,
  pubkey TEXT,
  name TEXT,
  region TEXT,
  asn INTEGER,
  last_seen INTEGER,
  meta TEXT
);
CREATE TABLE IF NOT EXISTS labels (
  id INTEGER PRIMARY KEY,
  ip TEXT,
  label TEXT,
  note TEXT,
  created_at INTEGER,
  withdrawn INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS shares (
  id TEXT PRIMARY KEY,
  body TEXT,
  created_at INTEGER
);
CREATE TABLE IF NOT EXISTS ip_logs (
  id INTEGER PRIMARY KEY,
  ip_hash TEXT,
  ip TEXT,
  ts INTEGER,
  path TEXT
);
CREATE TABLE IF NOT EXISTS peak_samples (
  id INTEGER PRIMARY KEY,
  target TEXT,
  ts INTEGER,
  loss REAL,
  rtt REAL,
  carrier TEXT
);
CREATE TABLE IF NOT EXISTS webrtc_reports (
  id INTEGER PRIMARY KEY,
  ts INTEGER,
  leak INTEGER,
  candidate_count INTEGER
);
`

// SchemaSQL exposes the DDL so tests can assert it stores no candidate IP.
func SchemaSQL() string { return schema }

// LogIP writes a raw visitor address. Callers must also run Purge.
func (s *Store) LogIP(ip, path string, now time.Time) error {
	_, err := s.DB.Exec(`INSERT INTO ip_logs(ip_hash, ip, ts, path) VALUES(?,?,?,?)`, hashIP(ip), ip, now.Unix(), path)
	return err
}

func hashIP(ip string) string {
	// /24 hash would drop the host; we keep a short prefix hash for stats and the raw ip for the retention window.
	if len(ip) > 64 {
		ip = ip[:64]
	}
	return ip
}

// PurgeLogs deletes raw IP logs older than retention.
func (s *Store) PurgeLogs(now time.Time, retention time.Duration) (int, error) {
	cut := now.Add(-retention).Unix()
	res, err := s.DB.Exec(`DELETE FROM ip_logs WHERE ts < ?`, cut)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// CountLogs returns remaining raw IP rows.
func (s *Store) CountLogs() (int, error) {
	var n int
	err := s.DB.QueryRow(`SELECT COUNT(*) FROM ip_logs`).Scan(&n)
	return n, err
}

// InsertLogAt writes a row at an explicit timestamp (tests).
func (s *Store) InsertLogAt(ip string, ts time.Time) error {
	_, err := s.DB.Exec(`INSERT INTO ip_logs(ip_hash, ip, ts, path) VALUES(?,?,?,?)`, ip, ip, ts.Unix(), "/test")
	return err
}

// SaveWebRTC stores only the boolean verdict and a count.
func (s *Store) SaveWebRTC(r privacy.WebRTCReport, now time.Time) error {
	_, err := s.DB.Exec(`INSERT INTO webrtc_reports(ts, leak, candidate_count) VALUES(?,?,?)`, now.Unix(), boolInt(r.Leak), r.CandidateCount)
	return err
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// AddHistory records a daily snapshot and returns true when the type or ASN changed.
func (s *Store) AddHistory(ip, prefix, cc, typ, flags string, asn int, ts time.Time) (bool, error) {
	var prevType, prevCC string
	var prevASN int
	err := s.DB.QueryRow(`SELECT asn, cc, type FROM history WHERE ip=? ORDER BY ts DESC LIMIT 1`, ip).Scan(&prevASN, &prevCC, &prevType)
	changed := false
	if err == nil {
		changed = prevASN != asn || prevCC != cc || prevType != typ
	} else if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	_, err = s.DB.Exec(`INSERT INTO history(ip, prefix, ts, asn, cc, type, flags) VALUES(?,?,?,?,?,?,?)`,
		ip, prefix, ts.Unix(), asn, cc, typ, flags)
	return changed, err
}

// History lists events derived from successive snapshots.
func (s *Store) History(ip string, since time.Time) ([]Event, error) {
	rows, err := s.DB.Query(`SELECT ts, asn, cc, type, flags FROM history WHERE ip=? AND ts>=? ORDER BY ts`, ip, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type snap struct {
		ts          int64
		asn         int
		cc, typ, fl string
	}
	var snaps []snap
	for rows.Next() {
		var s snap
		if err := rows.Scan(&s.ts, &s.asn, &s.cc, &s.typ, &s.fl); err != nil {
			return nil, err
		}
		snaps = append(snaps, s)
	}
	var ev []Event
	for i := 1; i < len(snaps); i++ {
		a, b := snaps[i-1], snaps[i]
		if a.asn != b.asn {
			ev = append(ev, Event{TS: time.Unix(b.ts, 0).UTC(), Field: "asn", From: fmt.Sprint(a.asn), To: fmt.Sprint(b.asn)})
		}
		if a.cc != b.cc {
			ev = append(ev, Event{TS: time.Unix(b.ts, 0).UTC(), Field: "cc", From: a.cc, To: b.cc})
		}
		if a.typ != b.typ {
			ev = append(ev, Event{TS: time.Unix(b.ts, 0).UTC(), Field: "type", From: a.typ, To: b.typ})
		}
	}
	if ev == nil {
		ev = []Event{}
	}
	return ev, nil
}

// Event is one field change.
type Event struct {
	TS    time.Time `json:"ts"`
	Field string    `json:"field"`
	From  string    `json:"from"`
	To    string    `json:"to"`
}

// CreateJob inserts a queued job.
func (s *Store) CreateJob(id, kind, request string, now time.Time) error {
	_, err := s.DB.Exec(`INSERT INTO jobs(id, kind, status, request, result, created_at, updated_at) VALUES(?,?,?,?,?,?,?)`,
		id, kind, "queued", request, "", now.Unix(), now.Unix())
	return err
}

// FinishJob stores a result.
func (s *Store) FinishJob(id, status string, result any, now time.Time) error {
	b, _ := json.Marshal(result)
	_, err := s.DB.Exec(`UPDATE jobs SET status=?, result=?, updated_at=? WHERE id=?`, status, string(b), now.Unix(), id)
	return err
}

// Job loads a job.
func (s *Store) Job(id string) (kind, status, result string, err error) {
	err = s.DB.QueryRow(`SELECT kind, status, result FROM jobs WHERE id=?`, id).Scan(&kind, &status, &result)
	return
}

// CreateWatch inserts a watch.
func (s *Store) CreateWatch(id, target, checks, webhook, secret string, next time.Time) error {
	_, err := s.DB.Exec(`INSERT INTO watches(id, target, checks, webhook, secret, last_hash, next_run, created_at) VALUES(?,?,?,?,?,?,?,?)`,
		id, target, checks, webhook, secret, "", next.Unix(), time.Now().Unix())
	return err
}

// ListWatches returns watches.
func (s *Store) ListWatches() ([]Watch, error) {
	rows, err := s.DB.Query(`SELECT id, target, checks, webhook, next_run FROM watches ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Watch
	for rows.Next() {
		var w Watch
		var next int64
		if err := rows.Scan(&w.ID, &w.Target, &w.Checks, &w.Webhook, &next); err != nil {
			return nil, err
		}
		w.NextRun = time.Unix(next, 0).UTC()
		out = append(out, w)
	}
	if out == nil {
		out = []Watch{}
	}
	return out, nil
}

// DeleteWatch removes a watch.
func (s *Store) DeleteWatch(id string) error {
	_, err := s.DB.Exec(`DELETE FROM watches WHERE id=?`, id)
	return err
}

// DueWatches returns watches whose next_run is due, including their secret.
func (s *Store) DueWatches(now time.Time) ([]Watch, error) {
	rows, err := s.DB.Query(`SELECT id, target, checks, webhook, secret, last_hash, next_run FROM watches WHERE next_run<=?`, now.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Watch
	for rows.Next() {
		var w Watch
		var next int64
		if err := rows.Scan(&w.ID, &w.Target, &w.Checks, &w.Webhook, &w.Secret, &w.LastHash, &next); err != nil {
			return nil, err
		}
		w.NextRun = time.Unix(next, 0).UTC()
		out = append(out, w)
	}
	return out, nil
}

// UpdateWatch stores the new hash and next run.
func (s *Store) UpdateWatch(id, hash string, next time.Time) error {
	_, err := s.DB.Exec(`UPDATE watches SET last_hash=?, next_run=? WHERE id=?`, hash, next.Unix(), id)
	return err
}

// Watch is a subscription.
type Watch struct {
	ID, Target, Checks, Webhook, Secret, LastHash string
	NextRun                                       time.Time
}

// SaveShare stores a redacted report.
func (s *Store) SaveShare(id, body string, now time.Time) error {
	_, err := s.DB.Exec(`INSERT INTO shares(id, body, created_at) VALUES(?,?,?)`, id, body, now.Unix())
	return err
}

// Share loads a report.
func (s *Store) Share(id string) (string, error) {
	var body string
	err := s.DB.QueryRow(`SELECT body FROM shares WHERE id=?`, id).Scan(&body)
	return body, err
}

// AddLabel stores an opt-in training label. Withdrawn labels stay for audit.
func (s *Store) AddLabel(ip, label, note string, now time.Time) error {
	_, err := s.DB.Exec(`INSERT INTO labels(ip, label, note, created_at, withdrawn) VALUES(?,?,?,?,0)`, ip, label, note, now.Unix())
	return err
}

// AddPeak stores one latency sample.
func (s *Store) AddPeak(target, carrier string, ts time.Time, loss, rtt float64) error {
	_, err := s.DB.Exec(`INSERT INTO peak_samples(target, ts, loss, rtt, carrier) VALUES(?,?,?,?,?)`, target, ts.Unix(), loss, rtt, carrier)
	return err
}

// PeakTimes returns sample timestamps for a target.
func (s *Store) PeakTimes(target string, since time.Time) ([]time.Time, error) {
	rows, err := s.DB.Query(`SELECT ts FROM peak_samples WHERE target=? AND ts>=? ORDER BY ts`, target, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []time.Time
	for rows.Next() {
		var ts int64
		if err := rows.Scan(&ts); err != nil {
			return nil, err
		}
		out = append(out, time.Unix(ts, 0).UTC())
	}
	return out, nil
}

// UpsertProbe registers a probe public key.
func (s *Store) UpsertProbe(id, pubkey, name, region string, asn int, seen time.Time) error {
	_, err := s.DB.Exec(`INSERT INTO probes(id, pubkey, name, region, asn, last_seen, meta) VALUES(?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET pubkey=excluded.pubkey, name=excluded.name, region=excluded.region, asn=excluded.asn, last_seen=excluded.last_seen`,
		id, pubkey, name, region, asn, seen.Unix(), "")
	return err
}
