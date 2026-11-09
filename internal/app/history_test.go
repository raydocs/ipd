package app

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"ipd/internal/lookup"
)

func TestLocalHistoryEvidence(t *testing.T) {
	s := newSvc(t)
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return now }
	// Deliberately use existing public store API: legacy provenance is unknown.
	for _, row := range []struct {
		ip, typ string
		at      time.Time
	}{
		{"192.0.2.1", "residential", now.Add(-100 * 24 * time.Hour)},
		{"192.0.2.1", "unknown", now.Add(-time.Hour)},
		{"192.0.2.2", "unknown", now.Add(-time.Hour)},
		{"192.0.3.2", "hosting", now.Add(-time.Hour)},
	} {
		if _, err := s.DB.AddHistory(row.ip, "192.0.0.0/16", "", row.typ, "", 0, row.at); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := s.History("192.0.2.1", 365)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(rep)
	var got struct {
		Data struct {
			Snapshots []struct {
				Type       string
				Provenance json.RawMessage
			}
			Neighbors struct {
				Observed int `json:"observed_addresses"`
				Prefix   string
			}
		}
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Data.Snapshots) != 1 || got.Data.Snapshots[0].Type != "unknown" || string(got.Data.Snapshots[0].Provenance) != "null" {
		t.Fatalf("retained snapshots with unknown provenance: %s", b)
	}
	if got.Data.Neighbors.Observed != 2 || got.Data.Neighbors.Prefix != "192.0.2.0/24" {
		t.Fatalf("local neighbors: %s", b)
	}
	if strings.Contains(string(b), "192.0.2.2") || strings.Contains(string(b), "192.0.3.2") {
		t.Fatalf("neighbor IP disclosed: %s", b)
	}
	var n int
	if err := s.DB.DB.QueryRow("SELECT COUNT(*) FROM history WHERE ts < ?", now.Add(-90*24*time.Hour).Unix()).Scan(&n); err != nil || n != 0 {
		t.Fatalf("expired rows=%d err=%v", n, err)
	}
	if err := s.recordHistory("192.0.2.1", lookup.Profile{Prefix: "192.0.2.0/24", Flags: []string{"vpn"}}, "unknown"); err != nil {
		t.Fatal(err)
	}
	rep, err = s.History("192.0.2.1", 1)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = json.Marshal(rep)
	if !strings.Contains(string(b), `"provenance":[]`) || !strings.Contains(string(b), `"flags":"vpn"`) {
		t.Fatalf("new provenance/flags missing: %s", b)
	}
}

func TestHistoryConfiguredWindowAndEmpty(t *testing.T) {
	s := newSvc(t)
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return now }
	s.Cfg.HistoryRetention = 48 * time.Hour
	if _, err := s.DB.AddHistory("192.0.2.1", "", "", "unknown", "", 0, now.Add(-49*time.Hour)); err != nil {
		t.Fatal(err)
	}
	rep, err := s.History("192.0.2.1", 365)
	if err != nil || rep.Verdict != "abstain" {
		t.Fatalf("%+v %v", rep, err)
	}
	if err := s.recordHistory("192.0.2.1", lookup.Profile{}, "unknown"); err != nil {
		t.Fatal(err)
	}
	rep, err = s.History("192.0.2.1", 365)
	if err != nil || rep.Verdict != "partial" {
		t.Fatalf("%+v %v", rep, err)
	}
	for _, ip := range []string{"not-an-ip", "192.0.2.0/24", "fe80::1%lo0"} {
		if _, err := s.History(ip, 1); err == nil {
			t.Fatalf("accepted %s", ip)
		}
	}
	s.DB = nil
	rep, err = s.History("192.0.2.1", 1)
	if err != nil || rep.Verdict != "abstain" {
		t.Fatalf("%+v %v", rep, err)
	}
}

func TestHistoryRecordSourceMetadata(t *testing.T) {
	s := newSvc(t)
	if err := s.recordHistory("192.0.2.1", lookup.Profile{
		Hits: []lookup.Hit{{Source: "fixture", Rec: lookup.Rec{Prefix: "192.0.2.0/24", ASN: 64500}}},
	}, "unknown"); err != nil {
		t.Fatal(err)
	}
	rep, err := s.History("192.0.2.1", 1)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(rep)
	if !strings.Contains(string(b), `"id":"fixture"`) || !strings.Contains(string(b), `"asn":64500`) {
		t.Fatalf("source lost: %s", b)
	}
}

func TestHistoryWriteEnforcesRetentionAndErrors(t *testing.T) {
	s := newSvc(t)
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return now }
	s.Cfg.HistoryRetention = time.Hour
	if _, err := s.DB.AddHistory("192.0.2.99", "", "", "unknown", "", 0, now.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.recordHistory("192.0.2.1", lookup.Profile{}, "unknown"); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.DB.DB.QueryRow("SELECT COUNT(*) FROM history").Scan(&n); err != nil || n != 1 {
		t.Fatalf("write retention n=%d err=%v", n, err)
	}
	s.DB.Close()
	if _, err := s.History("192.0.2.1", 1); err == nil {
		t.Fatal("read swallowed database failure")
	}
	if err := s.recordHistory("192.0.2.1", lookup.Profile{}, "unknown"); err == nil {
		t.Fatal("write swallowed purge failure")
	}
}
