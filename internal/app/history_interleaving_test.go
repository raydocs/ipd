package app

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"strings"
	"sync"
	"testing"
	"time"

	"ipd/internal/store"
	"modernc.org/sqlite"
)

// Scheduling only: commit a write after the first actual row is stepped.
// This pins the SQLite read view without depending on a particular SELECT shape.
type historyInterleaveDriver struct{ afterFirstRow func() }

func (d *historyInterleaveDriver) Open(name string) (driver.Conn, error) {
	c, err := (&sqlite.Driver{}).Open(name)
	if err != nil {
		return nil, err
	}
	return &historyInterleaveConn{Conn: c, afterFirstRow: d.afterFirstRow}, nil
}

type historyInterleaveConnector struct {
	d    *historyInterleaveDriver
	name string
}

func (c historyInterleaveConnector) Connect(context.Context) (driver.Conn, error) {
	return c.d.Open(c.name)
}
func (c historyInterleaveConnector) Driver() driver.Driver { return c.d }

type historyInterleaveConn struct {
	driver.Conn
	afterFirstRow func()
}

func (c *historyInterleaveConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	rows, err := c.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
	if err == nil && strings.HasPrefix(q, "SELECT") && strings.Contains(q, "FROM history") {
		return &historyInterleaveRows{Rows: rows, afterFirstRow: c.afterFirstRow}, nil
	}
	return rows, err
}
func (c *historyInterleaveConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, q, args)
}

type historyInterleaveRows struct {
	driver.Rows
	afterFirstRow func()
}

func (r *historyInterleaveRows) Next(dest []driver.Value) error {
	err := r.Rows.Next(dest)
	if err == nil {
		r.afterFirstRow()
	}
	return err
}
func TestHistorySnapshotReadInterleaving(t *testing.T) {
	s, now := correctionSvc(t)
	const ip = "192.0.2.1"
	correctionAdd(t, s, ip, "hosting", now.Add(-time.Hour))
	writer := s.DB
	var seq int
	var name, path string
	if err := writer.DB.QueryRow("PRAGMA database_list").Scan(&seq, &name, &path); err != nil {
		t.Fatal(err)
	}
	begin := make(chan struct{})
	written := make(chan error, 1)
	go func() {
		<-begin
		_, err := writer.AddHistory(ip, "", "", "unknown", "", 0, now)
		written <- err
	}()
	var once sync.Once
	stepped := false
	d := &historyInterleaveDriver{afterFirstRow: func() {
		once.Do(func() {
			stepped = true
			close(begin)
			if err := <-written; err != nil {
				t.Fatal(err)
			}
		})
	}}
	readDB := sql.OpenDB(historyInterleaveConnector{d: d, name: "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"})
	readDB.SetMaxOpenConns(1)
	defer readDB.Close()
	s.DB = &store.Store{DB: readDB}
	rep, err := s.History(ip, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !stepped {
		t.Fatal("fixture did not interleave a committed write")
	}
	data := rep.Data.(map[string]any)
	snaps := data["snapshots"].([]store.Observation)
	events := data["events"].([]store.Event)
	n := data["neighbors"].(store.LocalNeighbors)
	if len(snaps) != 1 || len(events) != 0 || n.Types["hosting"] != 1 {
		t.Fatalf("one response spliced two committed states: snapshots=%+v events=%+v neighbors=%+v", snaps, events, n)
	}
	var count int
	if err := writer.DB.QueryRow("SELECT COUNT(*) FROM history").Scan(&count); err != nil || count != 2 {
		t.Fatalf("writer did not commit: count=%d err=%v", count, err)
	}
	rep, err = s.History(ip, 1)
	if err != nil {
		t.Fatal(err)
	}
	data = rep.Data.(map[string]any)
	if len(data["snapshots"].([]store.Observation)) != 2 || len(data["events"].([]store.Event)) != 1 || data["neighbors"].(store.LocalNeighbors).Types["unknown"] != 1 {
		t.Fatalf("next view omitted commit: %+v", data)
	}
}
