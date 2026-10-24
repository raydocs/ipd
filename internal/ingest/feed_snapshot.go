package ingest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"ipd/internal/lookup"
)

const feedSnapshotSuffix = ".feed.json"

// feedSnapshot is ingest's lossless, single-file format for ordinary feeds.
// IPDS remains the packed format for streamRows; legacy TSV is read-only.
type feedSnapshot struct {
	Version int                `json:"version"`
	Meta    lookup.SourceMeta  `json:"meta"`
	Rows    []lookup.SourceRow `json:"rows"`
}

func prepareFeedSnapshot(id string, meta lookup.SourceMeta, rows []lookup.SourceRow) (feedSnapshot, error) {
	if id == "" || id == "." || id == ".." || strings.ContainsAny(id, "/\\") || meta.ID != id {
		return feedSnapshot{}, fmt.Errorf("invalid or mismatched feed id %q", id)
	}
	if !validFeedText(meta.ID, meta.Kind, meta.Version, meta.Frequency, meta.License, meta.Attribution, meta.URL) {
		return feedSnapshot{}, fmt.Errorf("feed metadata contains invalid UTF-8")
	}
	snap := feedSnapshot{Version: 1, Meta: meta}
	for _, row := range rows {
		pfx, err := netip.ParsePrefix(row.Rec.Prefix)
		if err != nil {
			continue
		}
		r := row.Rec
		// encoding/json replaces invalid UTF-8 silently. Reject it instead of
		// publishing a live record which differs from its reloaded snapshot.
		if !validFeedText(r.Org, r.CC, r.Region, r.City, r.ASType, r.NetName, r.Descr,
			r.RegisteredCC, r.GeofeedCC, r.UpstreamType, r.AnnouncedCC, r.RDNS,
			r.RTTRegion, r.ChangedAt, r.Cloud) || !validFeedText(r.Flags...) {
			return feedSnapshot{}, fmt.Errorf("feed row contains invalid UTF-8")
		}
		row.Source = id
		row.Rec.Prefix = pfx.Masked().String()
		row.Rec.Flags = slices.Clone(row.Rec.Flags)
		snap.Rows = append(snap.Rows, row)
	}
	if len(snap.Rows) == 0 {
		return feedSnapshot{}, fmt.Errorf("no rows parsed")
	}
	// Keep input order, including duplicates: MergeSource's last insert wins,
	// and its row count is the accepted count before duplicate collapse.
	snap.Meta.Rows = len(snap.Rows)
	snap.Meta.Enabled = true
	// Unknown acquisition time stays unknown; only the producer can supply it.
	return snap, nil
}

func validFeedText(values ...string) bool {
	for _, value := range values {
		if !utf8.ValidString(value) {
			return false
		}
	}
	return true
}

type snapshotFile interface {
	io.Writer
	Sync() error
	Close() error
	Name() string
}

type snapshotFiles struct {
	createTemp func(string, string) (snapshotFile, error)
	rename     func(string, string) error
}

// writeFeedSnapshot has one publication point: a same-directory rename of a
// fully encoded, synced and closed file. Only this call's unique temp is removed
// on failure. The directory is not synced; this is not a power-loss guarantee.
func writeFeedSnapshot(dir string, snap feedSnapshot, files *snapshotFiles) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	if files == nil {
		files = &snapshotFiles{
			createTemp: func(dir, pattern string) (snapshotFile, error) { return os.CreateTemp(dir, pattern) },
			rename:     os.Rename,
		}
	}
	path := filepath.Join(dir, snap.Meta.ID+feedSnapshotSuffix)
	f, err := files.createTemp(dir, "."+snap.Meta.ID+feedSnapshotSuffix+"-*")
	if err != nil {
		return err
	}
	closed, committed := false, false
	defer func() {
		if !closed {
			_ = f.Close()
		}
		if !committed {
			_ = os.Remove(f.Name())
		}
	}()
	if err := json.NewEncoder(f).Encode(snap); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	err = f.Close()
	closed = true
	if err != nil {
		return err
	}
	if err := files.rename(f.Name(), path); err != nil {
		return err
	}
	committed = true
	return nil
}

func readFeedSnapshot(path, id string) (feedSnapshot, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return feedSnapshot{}, err
	}
	// Validate the original bytes, not strings already normalized by json.
	if err := validateFeedJSONText(raw); err != nil {
		return feedSnapshot{}, err
	}
	var snap feedSnapshot
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&snap); err != nil {
		return feedSnapshot{}, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return feedSnapshot{}, fmt.Errorf("feed snapshot has trailing data: %v", err)
	}
	if snap.Version != 1 {
		return feedSnapshot{}, fmt.Errorf("unsupported feed snapshot version %d", snap.Version)
	}
	prepared, err := prepareFeedSnapshot(id, snap.Meta, snap.Rows)
	if err != nil {
		return feedSnapshot{}, err
	}
	if snap.Meta.Rows != len(prepared.Rows) || !snap.Meta.Enabled || len(snap.Rows) != len(prepared.Rows) {
		return feedSnapshot{}, fmt.Errorf("invalid feed snapshot metadata or rows")
	}
	// Read normalization matches publication, without refreshing source timestamps.
	return prepared, nil
}

// validateFeedJSONText rejects Unicode damage that encoding/json would silently
// replace with U+FFFD. JSON syntax is still checked by the decoder afterward.
func validateFeedJSONText(raw []byte) error {
	if !utf8.Valid(raw) {
		return fmt.Errorf("feed snapshot contains invalid UTF-8")
	}
	inString := false
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '"':
			inString = !inString
		case '\\':
			if !inString {
				continue
			}
			i++ // Skip an escaped quote/backslash without changing string state.
			if i >= len(raw) {
				return fmt.Errorf("incomplete feed snapshot string escape")
			}
			if raw[i] != 'u' {
				continue
			}
			unit, err := feedJSONCodeUnit(raw[i+1:])
			if err != nil {
				return err
			}
			i += 4
			switch {
			case unit >= 0xd800 && unit <= 0xdbff:
				if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
					return fmt.Errorf("unpaired high surrogate in feed snapshot")
				}
				low, err := feedJSONCodeUnit(raw[i+3:])
				if err != nil || low < 0xdc00 || low > 0xdfff {
					return fmt.Errorf("unpaired high surrogate in feed snapshot")
				}
				i += 6
			case unit >= 0xdc00 && unit <= 0xdfff:
				return fmt.Errorf("unpaired low surrogate in feed snapshot")
			}
		}
	}
	return nil
}

func feedJSONCodeUnit(raw []byte) (uint64, error) {
	if len(raw) < 4 {
		return 0, fmt.Errorf("incomplete feed snapshot Unicode escape")
	}
	unit, err := strconv.ParseUint(string(raw[:4]), 16, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid feed snapshot Unicode escape: %w", err)
	}
	return unit, nil
}
