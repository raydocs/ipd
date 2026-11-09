package api

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ipd/internal/app"
	"ipd/internal/config"
	"ipd/internal/store"
)

func TestHistoryLocalEvidenceHTTP(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cfg := &config.Config{Offline: true, HistoryRetention: 24 * time.Hour, AnonymousRPM: 1000}
	svc := app.New(cfg, db)
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	svc.Now = func() time.Time { return now }
	for _, ip := range []string{"192.0.2.1", "192.0.2.99"} {
		if _, err := db.AddHistory(ip, "192.0.2.0/24", "", "unknown", "", 0, now); err != nil {
			t.Fatal(err)
		}
	}
	h := New(svc).Handler()
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/v1/ip/192.0.2.1/history?days=365", nil)
	req.Header.Set("Accept", "application/json")
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var got struct {
		Verdict string
		Data    struct {
			Scope     string `json:"evidence_scope"`
			Retention int    `json:"retention_seconds"`
			Neighbors struct {
				Observed int `json:"observed_addresses"`
			}
			Snapshots []json.RawMessage
		}
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Verdict != "partial" || got.Data.Scope != "local_stored_observations" || got.Data.Retention != 86400 || got.Data.Neighbors.Observed != 2 || len(got.Data.Snapshots) != 1 {
		t.Fatal(w.Body.String())
	}
	if strings.Contains(w.Body.String(), "192.0.2.99") {
		t.Fatal("raw neighbor address exposed")
	}
	validateContractResponse(t, contractDoc(t), "/v1/ip/{ip}/history", "get", w)
}
