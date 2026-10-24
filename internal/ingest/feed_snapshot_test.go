package ingest

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"ipd/internal/config"
	"ipd/internal/lookup"
)

func feedTestUpdater(t *testing.T) (*updater, *[]string) {
	t.Helper()
	logs := new([]string)
	return &updater{cfg: &config.Config{DataDir: t.TempDir()}, eng: lookup.New(), logf: func(s string) { *logs = append(*logs, s) }}, logs
}

func feedTestRows(org string) []lookup.SourceRow {
	return []lookup.SourceRow{{Source: "ignored by MergeSource", Rec: lookup.Rec{Prefix: "192.0.2.19/24", Org: org}}}
}

func feedTestMeta(id string) lookup.SourceMeta {
	return lookup.SourceMeta{ID: id, Kind: "local", Version: "fixture", UpdatedAt: time.Date(2026, 10, 20, 1, 2, 3, 4, time.UTC), Frequency: "day", License: "test", Attribution: "fixture", URL: "https://example.invalid/feed", Redistributable: true}
}

func requireFeedRec(t *testing.T, eng *lookup.Engine, id string, want lookup.Rec) {
	t.Helper()
	got, ok := eng.Covering(id, netip.MustParsePrefix(want.Prefix))
	if !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("%s record: got %+v (%v), want %+v", id, got, ok, want)
	}
}

func feedSource(t *testing.T, eng *lookup.Engine, id string) lookup.SourceMeta {
	t.Helper()
	for _, m := range eng.Sources(time.Date(2026, 10, 20, 1, 2, 3, 4, time.UTC)) {
		if m.ID == id {
			return m
		}
	}
	t.Fatalf("missing source %s", id)
	return lookup.SourceMeta{}
}

func TestApplySnapshotAllFieldsAndRestart(t *testing.T) {
	u, _ := feedTestUpdater(t)
	other := feedTestMeta("other_fixture")
	if fr := u.apply(other.ID, other, feedTestRows("other"), "", "", nil); fr.Err != "" {
		t.Fatal(fr)
	}
	otherBefore := feedSource(t, u.eng, other.ID)
	rec := lookup.Rec{Prefix: "192.0.2.199/24", ASN: 4294967301, Org: "org\twith\ntext", CC: "US", Region: "region", City: "city", Lat: 1.25, Lon: -2.5, ASType: "hosting", Flags: []string{"vpn", "literal|pipe", "tab\tline\n"}, NetName: "net", Descr: "description\ntext", RegisteredCC: "CA", GeofeedCC: "GB", GeofeedChanged: true, Eyeball: 77, UpstreamASN: 4294967302, UpstreamType: "transit", AnnouncedCC: "DE", RDNS: "fixture.invalid", PrefixAgeDays: 42, RTTRegion: "eu", ChangedAt: "2026-10-19", Cloud: "fixture"}
	// Every current Rec field participates; adding fields requires extending this fixture.
	v := reflect.ValueOf(rec)
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).IsZero() {
			t.Fatalf("fixture omits Rec.%s", v.Type().Field(i).Name)
		}
	}
	m := feedTestMeta("r7_fixture")
	m.Rows = 999
	rows := []lookup.SourceRow{{Rec: rec}, {Rec: lookup.Rec{Prefix: "invalid", Org: "skip"}}}
	fr := u.apply(m.ID, m, rows, "source", "note", nil)
	if fr.Err != "" || fr.Rows != 1 || fr.URL != "source" || fr.Note != "note" {
		t.Fatal(fr)
	}
	rec.Prefix = "192.0.2.0/24"
	requireFeedRec(t, u.eng, m.ID, rec)
	snap, err := readFeedSnapshot(filepath.Join(u.cfg.DataDir, "feeds", m.ID+feedSnapshotSuffix), m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Rows) != 1 || snap.Rows[0].Source != m.ID {
		t.Fatal(snap)
	}
	wantMeta := m
	wantMeta.Rows = 1
	wantMeta.Enabled = true
	if !reflect.DeepEqual(snap.Meta, wantMeta) {
		t.Fatalf("disk metadata %+v != %+v", snap.Meta, wantMeta)
	}
	if got := feedSource(t, u.eng, m.ID); !reflect.DeepEqual(got, wantMeta) {
		t.Fatalf("live metadata %+v", got)
	}
	restarted := lookup.New()
	if err := Load(restarted, u.cfg); err != nil {
		t.Fatal(err)
	}
	requireFeedRec(t, restarted, m.ID, rec)
	requireFeedRec(t, restarted, other.ID, lookup.Rec{Prefix: "192.0.2.0/24", Org: "other"})
	if got := feedSource(t, restarted, m.ID); !reflect.DeepEqual(got, wantMeta) {
		t.Fatalf("restart metadata %+v", got)
	}
	if got := feedSource(t, u.eng, other.ID); !reflect.DeepEqual(got, otherBefore) {
		t.Fatal("other source changed", got)
	}
	if got := feedSource(t, restarted, other.ID); !reflect.DeepEqual(got, otherBefore) {
		t.Fatal("other restart metadata changed", got)
	}
}

func TestApplySnapshotDuplicateLastWins(t *testing.T) {
	u, _ := feedTestUpdater(t)
	m := feedTestMeta("duplicates")
	var rows []lookup.SourceRow
	for i := 0; i < 64; i++ {
		rows = append(rows, lookup.SourceRow{Rec: lookup.Rec{Prefix: "192.0.2.19/24", ASN: i + 1}})
	}
	rows = append(rows, lookup.SourceRow{Rec: lookup.Rec{Prefix: "2001:db8::123/32", Org: "v6"}})
	if fr := u.apply(m.ID, m, rows, "", "", nil); fr.Err != "" || fr.Rows != 65 {
		t.Fatal(fr)
	}
	restarted := lookup.New()
	if err := Load(restarted, u.cfg); err != nil {
		t.Fatal(err)
	}
	for _, eng := range []*lookup.Engine{u.eng, restarted} {
		requireFeedRec(t, eng, m.ID, lookup.Rec{Prefix: "192.0.2.0/24", ASN: 64})
		requireFeedRec(t, eng, m.ID, lookup.Rec{Prefix: "2001:db8::/32", Org: "v6"})
		if got := feedSource(t, eng, m.ID); got.Rows != 65 || !got.Enabled || !got.UpdatedAt.Equal(m.UpdatedAt) {
			t.Fatal(got)
		}
	}
}

type failingSnapshotFile struct {
	*os.File
	operation string
	failure   error
}

func (f *failingSnapshotFile) Write(b []byte) (int, error) {
	if f.operation == "write" {
		return 0, f.failure
	}
	return f.File.Write(b)
}
func (f *failingSnapshotFile) Sync() error {
	if f.operation == "sync" {
		return f.failure
	}
	return f.File.Sync()
}
func (f *failingSnapshotFile) Close() error {
	err := f.File.Close()
	if f.operation == "close" {
		return f.failure
	}
	return err
}

func TestApplySnapshotFileFailuresKeepLastGood(t *testing.T) {
	for _, operation := range []string{"create", "write", "sync", "close", "rename"} {
		t.Run(operation, func(t *testing.T) {
			u, logs := feedTestUpdater(t)
			m := feedTestMeta("r7_fixture")
			for _, id := range []string{m.ID, "other_fixture"} {
				if fr := u.apply(id, feedTestMeta(id), feedTestRows("old"), "", "", nil); fr.Err != "" {
					t.Fatal(fr)
				}
			}
			beforeMeta := feedSource(t, u.eng, m.ID)
			dir := filepath.Join(u.cfg.DataDir, "feeds")
			path := filepath.Join(dir, m.ID+feedSnapshotSuffix)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			unowned := filepath.Join(dir, "."+m.ID+feedSnapshotSuffix+"-unowned")
			if err := os.WriteFile(unowned, []byte("not ours"), 0600); err != nil {
				t.Fatal(err)
			}
			failure := errors.New("injected " + operation + " failure")
			renameCalls := 0
			u.files = &snapshotFiles{
				createTemp: func(dir, pattern string) (snapshotFile, error) {
					if operation == "create" {
						return nil, failure
					}
					f, err := os.CreateTemp(dir, pattern)
					if err != nil {
						return nil, err
					}
					return &failingSnapshotFile{File: f, operation: operation, failure: failure}, nil
				},
				rename: func(from, to string) error { renameCalls++; return failure },
			}
			*logs = nil
			m.UpdatedAt = m.UpdatedAt.Add(time.Hour)
			fr := u.apply(m.ID, m, feedTestRows("new"), "", "", nil)
			if !strings.Contains(fr.Err, failure.Error()) || fr.Rows != 0 {
				t.Fatal(fr)
			}
			if operation != "rename" && renameCalls != 0 {
				t.Fatal("rename attempted before file was ready")
			}
			if strings.Contains(strings.Join(*logs, "\n"), "已更新") {
				t.Fatal("failure logged success", *logs)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("last-good bytes changed", err)
			}
			for _, id := range []string{m.ID, "other_fixture"} {
				requireFeedRec(t, u.eng, id, lookup.Rec{Prefix: "192.0.2.0/24", Org: "old"})
			}
			if got := feedSource(t, u.eng, m.ID); !reflect.DeepEqual(got, beforeMeta) {
				t.Fatal("failed update changed metadata", got)
			}
			restarted := lookup.New()
			if err := Load(restarted, u.cfg); err != nil {
				t.Fatal(err)
			}
			requireFeedRec(t, restarted, m.ID, lookup.Rec{Prefix: "192.0.2.0/24", Org: "old"})
			if got := feedSource(t, restarted, m.ID); !reflect.DeepEqual(got, beforeMeta) {
				t.Fatal("failed update changed restart metadata", got)
			}
			temps, err := filepath.Glob(filepath.Join(dir, "."+m.ID+feedSnapshotSuffix+"-*"))
			if err != nil || !reflect.DeepEqual(temps, []string{unowned}) {
				t.Fatal("temp ownership/cleanup", temps, err)
			}
			if b, err := os.ReadFile(unowned); err != nil || string(b) != "not ours" {
				t.Fatal("unowned temp changed", err)
			}
		})
	}
}

func TestApplySnapshotRejectedInputKeepsLastGood(t *testing.T) {
	for _, kind := range []string{"empty", "invalid", "parse error", "id mismatch", "unsafe id", "json encoding", "invalid metadata text", "invalid row text", "invalid flag text"} {
		t.Run(kind, func(t *testing.T) {
			u, logs := feedTestUpdater(t)
			m := feedTestMeta("r7_fixture")
			if fr := u.apply(m.ID, m, feedTestRows("old"), "", "", nil); fr.Err != "" {
				t.Fatal(fr)
			}
			path := filepath.Join(u.cfg.DataDir, "feeds", m.ID+feedSnapshotSuffix)
			before, _ := os.ReadFile(path)
			rows := feedTestRows("new")
			id := m.ID
			var parseErr error
			switch kind {
			case "empty":
				rows = nil
			case "invalid":
				rows[0].Rec.Prefix = "not a prefix"
			case "parse error":
				parseErr = errors.New("parse failed")
			case "id mismatch":
				m.ID = "other"
			case "unsafe id":
				id = "../escape"
				m.ID = id
			case "json encoding":
				rows[0].Rec.Lat = math.NaN()
			case "invalid metadata text":
				m.Attribution = string([]byte{0xff})
			case "invalid row text":
				rows[0].Rec.Org = string([]byte{0xff})
			case "invalid flag text":
				rows[0].Rec.Flags = []string{string([]byte{0xff})}
			}
			*logs = nil
			if fr := u.apply(id, m, rows, "", "", parseErr); fr.Err == "" || fr.Rows != 0 {
				t.Fatal(fr)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("last-good changed", err)
			}
			requireFeedRec(t, u.eng, "r7_fixture", lookup.Rec{Prefix: "192.0.2.0/24", Org: "old"})
			if strings.Contains(strings.Join(*logs, "\n"), "已更新") {
				t.Fatal(*logs)
			}
			entries, err := os.ReadDir(filepath.Dir(path))
			if err != nil || len(entries) != 1 {
				t.Fatal("temporary snapshot left behind", entries, err)
			}
		})
	}
}

func writeLegacyFeed(t *testing.T, u *updater, m lookup.SourceMeta) ([]byte, []byte) {
	t.Helper()
	dir := filepath.Join(u.cfg.DataDir, "feeds")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	raw := []byte("192.0.2.0/24\t64512\tUS\tlegacy\thosting\tvpn|hosting\tcloud\tCA\n")
	meta, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, m.ID+".tsv"), raw, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, m.ID+".meta.json"), meta, 0644); err != nil {
		t.Fatal(err)
	}
	return raw, meta
}

func TestApplySnapshotLegacyMetadataDirectory(t *testing.T) {
	u, _ := feedTestUpdater(t)
	m := feedTestMeta("r7_fixture")
	legacy, _ := writeLegacyFeed(t, u, m)
	if err := Load(u.eng, u.cfg); err != nil {
		t.Fatal(err)
	}
	metaPath := filepath.Join(u.cfg.DataDir, "feeds", m.ID+".meta.json")
	if err := os.Remove(metaPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(metaPath, 0755); err != nil {
		t.Fatal(err)
	}
	if fr := u.apply(m.ID, m, feedTestRows("new"), "", "", nil); fr.Err != "" {
		t.Fatal(fr)
	}
	after, err := os.ReadFile(filepath.Join(u.cfg.DataDir, "feeds", m.ID+".tsv"))
	if err != nil || !bytes.Equal(legacy, after) {
		t.Fatal("legacy TSV modified", err)
	}
	restarted := lookup.New()
	if err := Load(restarted, u.cfg); err != nil {
		t.Fatal(err)
	}
	for _, eng := range []*lookup.Engine{u.eng, restarted} {
		requireFeedRec(t, eng, m.ID, lookup.Rec{Prefix: "192.0.2.0/24", Org: "new"})
	}
}

func TestApplySnapshotRealRenameFailure(t *testing.T) {
	u, logs := feedTestUpdater(t)
	m := feedTestMeta("r7_fixture")
	legacy, meta := writeLegacyFeed(t, u, m)
	if err := Load(u.eng, u.cfg); err != nil {
		t.Fatal(err)
	}
	want, ok := u.eng.Covering(m.ID, netip.MustParsePrefix("192.0.2.0/24"))
	if !ok {
		t.Fatal("missing fixture")
	}
	dir := filepath.Join(u.cfg.DataDir, "feeds")
	dest := filepath.Join(dir, m.ID+feedSnapshotSuffix)
	if err := os.Mkdir(dest, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dest, "unowned"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if fr := u.apply(m.ID, m, feedTestRows("new"), "", "", nil); fr.Err == "" || fr.Rows != 0 {
		t.Fatal(fr)
	}
	restarted := lookup.New()
	if err := Load(restarted, u.cfg); err != nil {
		t.Fatal(err)
	}
	for _, eng := range []*lookup.Engine{u.eng, restarted} {
		requireFeedRec(t, eng, m.ID, want)
	}
	for suffix, want := range map[string][]byte{".tsv": legacy, ".meta.json": meta} {
		got, err := os.ReadFile(filepath.Join(dir, m.ID+suffix))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal(suffix, err)
		}
	}
	if strings.Contains(strings.Join(*logs, "\n"), "已更新") {
		t.Fatal(*logs)
	}
	temps, _ := filepath.Glob(filepath.Join(dir, "."+m.ID+feedSnapshotSuffix+"-*"))
	if len(temps) != 0 {
		t.Fatal(temps)
	}
	if got, err := os.ReadFile(filepath.Join(dest, "unowned")); err != nil || string(got) != "keep" {
		t.Fatal("unowned destination changed", err)
	}
}

func TestLoadFeedFormatPrecedence(t *testing.T) {
	for _, ipdsOffset := range []time.Duration{-time.Hour, time.Hour} {
		t.Run(ipdsOffset.String(), func(t *testing.T) {
			u, _ := feedTestUpdater(t)
			m := feedTestMeta("r7_fixture")
			legacy, legacyMeta := writeLegacyFeed(t, u, m)
			// Legacy TSV alone still loads all of its supported columns.
			if err := Load(u.eng, u.cfg); err != nil {
				t.Fatal(err)
			}
			requireFeedRec(t, u.eng, m.ID, lookup.Rec{Prefix: "192.0.2.0/24", ASN: 64512, CC: "US", Org: "legacy", ASType: "hosting", Flags: []string{"vpn", "hosting"}, Cloud: "cloud", RegisteredCC: "CA"})
			if fr := u.apply(m.ID, m, feedTestRows("json"), "", "", nil); fr.Err != "" {
				t.Fatal(fr)
			}
			restarted := lookup.New()
			if err := Load(restarted, u.cfg); err != nil {
				t.Fatal(err)
			}
			requireFeedRec(t, restarted, m.ID, lookup.Rec{Prefix: "192.0.2.0/24", Org: "json"})
			dir := filepath.Join(u.cfg.DataDir, "feeds")
			// Creating JSON did not touch the old pair.
			for suffix, want := range map[string][]byte{".tsv": legacy, ".meta.json": legacyMeta} {
				got, err := os.ReadFile(filepath.Join(dir, m.ID+suffix))
				if err != nil || !bytes.Equal(got, want) {
					t.Fatal(suffix, err)
				}
			}
			ipdsMeta := m
			ipdsMeta.UpdatedAt = m.UpdatedAt.Add(ipdsOffset)
			if fr := u.streamRows(ipdsMeta, "", "", func(add func(lookup.Rec)) error { add(lookup.Rec{Prefix: "192.0.2.0/24", Org: "ipds"}); return nil }); fr.Err != "" {
				t.Fatal(fr)
			}
			restarted = lookup.New()
			if err := Load(restarted, u.cfg); err != nil {
				t.Fatal(err)
			}
			requireFeedRec(t, restarted, m.ID, lookup.Rec{Prefix: "192.0.2.0/24", Org: "ipds"})
			if got := feedSource(t, restarted, m.ID); !got.UpdatedAt.Equal(ipdsMeta.UpdatedAt) {
				t.Fatal(got)
			}
			before, err := os.ReadFile(filepath.Join(dir, m.ID+feedSnapshotSuffix))
			if err != nil {
				t.Fatal(err)
			}
			// A normal writer must not claim success behind a mapped source.
			if fr := u.apply(m.ID, m, feedTestRows("masked"), "", "", nil); fr.Err == "" || fr.Rows != 0 {
				t.Fatal(fr)
			}
			after, err := os.ReadFile(filepath.Join(dir, m.ID+feedSnapshotSuffix))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("rejected collision rewrote JSON", err)
			}
			requireFeedRec(t, u.eng, m.ID, lookup.Rec{Prefix: "192.0.2.0/24", Org: "ipds"})
		})
	}
}

func TestApplySnapshotDefaultTimeAndNoEngine(t *testing.T) {
	for _, noEngine := range []bool{false, true} {
		t.Run(map[bool]string{false: "live engine", true: "no engine"}[noEngine], func(t *testing.T) {
			u, _ := feedTestUpdater(t)
			if noEngine {
				u.eng = nil
			}
			m := feedTestMeta("r7_fixture")
			m.UpdatedAt = time.Time{}
			before := time.Now().UTC()
			if fr := u.apply(m.ID, m, append(feedTestRows("new"), lookup.SourceRow{Rec: lookup.Rec{Prefix: "bad"}}), "", "", nil); fr.Err != "" || fr.Rows != 1 {
				t.Fatal(fr)
			}
			after := time.Now().UTC()
			restarted := lookup.New()
			if err := Load(restarted, u.cfg); err != nil {
				t.Fatal(err)
			}
			got := feedSource(t, restarted, m.ID)
			if got.UpdatedAt.Before(before) || got.UpdatedAt.After(after) || got.Rows != 1 || !got.Enabled {
				t.Fatal(got)
			}
			if u.eng != nil && !reflect.DeepEqual(got, feedSource(t, u.eng, m.ID)) {
				t.Fatal("default timestamp differs between memory and disk")
			}
		})
	}
}

func TestApplySnapshotSuccessfulReplacement(t *testing.T) {
	u, _ := feedTestUpdater(t)
	m := feedTestMeta("r7_fixture")
	for _, org := range []string{"old", "new"} {
		m.UpdatedAt = m.UpdatedAt.Add(time.Hour)
		if fr := u.apply(m.ID, m, feedTestRows(org), "", "", nil); fr.Err != "" || fr.Rows != 1 {
			t.Fatal(fr)
		}
	}
	restarted := lookup.New()
	if err := Load(restarted, u.cfg); err != nil {
		t.Fatal(err)
	}
	for _, eng := range []*lookup.Engine{u.eng, restarted} {
		requireFeedRec(t, eng, m.ID, lookup.Rec{Prefix: "192.0.2.0/24", Org: "new"})
		if got := feedSource(t, eng, m.ID); !got.UpdatedAt.Equal(m.UpdatedAt) {
			t.Fatal(got)
		}
	}
	entries, err := os.ReadDir(filepath.Join(u.cfg.DataDir, "feeds"))
	if err != nil || len(entries) != 1 {
		t.Fatal("replacement left extra files", entries, err)
	}
}

func TestLoadRejectsInvalidFeedSnapshot(t *testing.T) {
	for _, kind := range []string{"version", "truncated", "trailing", "meta count", "disabled", "zero time", "invalid row", "id mismatch", "empty"} {
		t.Run(kind, func(t *testing.T) {
			u, _ := feedTestUpdater(t)
			m := feedTestMeta("r7_fixture")
			snap, err := prepareFeedSnapshot(m.ID, m, feedTestRows("new"))
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "version":
				snap.Version = 2
			case "meta count":
				snap.Meta.Rows++
			case "disabled":
				snap.Meta.Enabled = false
			case "zero time":
				snap.Meta.UpdatedAt = time.Time{}
			case "invalid row":
				snap.Rows[0].Rec.Prefix = "bad"
			case "id mismatch":
				snap.Meta.ID = "different"
			case "empty":
				snap.Rows = nil
			}
			b, err := json.Marshal(snap)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "truncated" {
				b = b[:len(b)/2]
			}
			if kind == "trailing" {
				b = append(b, []byte("\n{}")...)
			}
			dir := filepath.Join(u.cfg.DataDir, "feeds")
			if err := os.MkdirAll(dir, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, m.ID+feedSnapshotSuffix), b, 0600); err != nil {
				t.Fatal(err)
			}
			u.eng.MergeSource(m, feedTestRows("old"))
			if err := Load(u.eng, u.cfg); err == nil {
				t.Fatal("invalid snapshot accepted")
			}
			requireFeedRec(t, u.eng, m.ID, lookup.Rec{Prefix: "192.0.2.0/24", Org: "old"})
		})
	}
}
