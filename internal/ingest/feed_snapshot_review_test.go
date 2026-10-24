package ingest

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"ipd/internal/lookup"
)

func TestLoadSnapshotUnknownTime(t *testing.T) {
	u, _ := feedTestUpdater(t)
	m := feedTestMeta("r7_fixture")
	m.UpdatedAt = time.Time{}
	m.Rows = 1
	m.Enabled = true
	snap := feedSnapshot{Version: 1, Meta: m, Rows: feedTestRows("unknown time")}
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(u.cfg.DataDir, "feeds")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, m.ID+feedSnapshotSuffix)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readFeedSnapshot(path, m.ID)
	if err != nil {
		t.Fatal("unknown source time must be reloadable", err)
	}
	if !got.Meta.UpdatedAt.IsZero() {
		t.Fatal("reader invented source time", got.Meta.UpdatedAt)
	}
	if err := Load(u.eng, u.cfg); err != nil {
		t.Fatal(err)
	}
	requireFeedRec(t, u.eng, m.ID, lookup.Rec{Prefix: "192.0.2.0/24", Org: "unknown time"})
	// No assertion of live zero time on the legacy engine; PR8 owns that fix.
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, after) {
		t.Fatal("Load rewrote source metadata", err)
	}
}

func TestLoadSnapshotStrictUnicode(t *testing.T) {
	cases := []struct {
		name, rawText, want string
		invalid             bool
		field               string
	}{
		{name: "invalid byte", rawText: string([]byte{0xff}), invalid: true},
		{name: "truncated rune", rawText: string([]byte{0xe2, 0x82}), invalid: true},
		{name: "overlong rune", rawText: string([]byte{0xc0, 0xaf}), invalid: true},
		{name: "raw surrogate", rawText: string([]byte{0xed, 0xa0, 0x80}), invalid: true},
		{name: "invalid metadata byte", rawText: string([]byte{0xff}), invalid: true, field: "meta"},
		{name: "invalid ignored field byte", rawText: string([]byte{0xff}), invalid: true, field: "extra"},
		{name: "lone high surrogate", rawText: `\ud800`, invalid: true},
		{name: "lone low surrogate", rawText: `\udc00`, invalid: true},
		{name: "high then non-surrogate", rawText: `\ud800\u0041`, invalid: true},
		{name: "two high surrogates", rawText: `\ud800\udbff`, invalid: true},
		{name: "literal replacement rune", rawText: "\ufffd", want: "\ufffd"},
		{name: "escaped replacement rune", rawText: `\ufffd`, want: "\ufffd"},
		{name: "lowest surrogate pair", rawText: `\uD800\uDC00`, want: "\U00010000"},
		{name: "highest surrogate pair", rawText: `\udbff\udfff`, want: "\U0010ffff"},
		{name: "before surrogate range", rawText: `\ud7ff`, want: "\ud7ff"},
		{name: "after surrogate range", rawText: `\ue000`, want: "\ue000"},
		{name: "valid surrogate pair", rawText: `\ud83d\ude42`, want: "🙂"},
		{name: "escaped backslash text", rawText: `\\ud800`, want: `\ud800`},
		{name: "escaped quote", rawText: `quote\"text`, want: `quote"text`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, _ := feedTestUpdater(t)
			m := feedTestMeta("r7_fixture")
			u.eng.MergeSource(m, feedTestRows("old"))
			other := feedTestMeta("other_fixture")
			u.eng.MergeSource(other, feedTestRows("other"))
			oldMeta := feedSource(t, u.eng, m.ID)
			snap, err := prepareFeedSnapshot(m.ID, m, feedTestRows("UNICODE_TOKEN"))
			if err != nil {
				t.Fatal(err)
			}
			if tc.field == "extra" {
				snap.Rows = feedTestRows("new")
			}
			if tc.field == "meta" {
				snap.Rows = feedTestRows("new")
				snap.Meta.Attribution = "UNICODE_TOKEN"
			}
			raw, err := json.Marshal(snap)
			if err != nil {
				t.Fatal(err)
			}
			if tc.field == "extra" {
				raw = append(raw[:len(raw)-1], []byte(`,"ignored":"UNICODE_TOKEN"}`)...)
			}
			raw = bytes.ReplaceAll(raw, []byte("UNICODE_TOKEN"), []byte(tc.rawText))
			dir := filepath.Join(u.cfg.DataDir, "feeds")
			if err := os.MkdirAll(dir, 0755); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, m.ID+feedSnapshotSuffix)
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			err = Load(u.eng, u.cfg)
			if tc.invalid {
				if err == nil {
					t.Error("damaged serialized text was accepted")
				}
				requireFeedRec(t, u.eng, m.ID, lookup.Rec{Prefix: "192.0.2.0/24", Org: "old"})
				if got := feedSource(t, u.eng, m.ID); !reflect.DeepEqual(got, oldMeta) {
					t.Fatal("rejected snapshot changed source metadata", got)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				requireFeedRec(t, u.eng, m.ID, lookup.Rec{Prefix: "192.0.2.0/24", Org: tc.want})
			}
			requireFeedRec(t, u.eng, other.ID, lookup.Rec{Prefix: "192.0.2.0/24", Org: "other"})
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(raw, after) {
				t.Fatal("Load altered the input snapshot", err)
			}
		})
	}
}
