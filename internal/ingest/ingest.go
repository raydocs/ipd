// Package ingest refreshes the on-disk note for local datasets and, when a
// MaxMind file is configured, opens it. The binary ships a fixture snapshot;
// this command does not download feeds that need a license key.
package ingest

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/oschwald/maxminddb-golang"
	"ipd/internal/config"
	"ipd/internal/lookup"
)

// Result describes what ingest did.
type Result struct {
	Sources int
	MaxMind string
	Note    string
}

// Run writes a snapshot manifest under the data directory. A missing MaxMind
// path is skipped, not an error: the database is not redistributable.
func Run(ctx context.Context, cfg *config.Config) (Result, error) {
	if cfg == nil {
		cfg = config.FromEnv()
	}
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return Result{}, err
	}
	eng := lookup.New()
	sources := eng.Sources(time.Now())
	var b []byte
	b = append(b, []byte("# ipd ingest manifest\n")...)
	enabled := 0
	for _, s := range sources {
		if s.Kind != "local" {
			continue
		}
		line := fmt.Sprintf("- %s version=%s enabled=%v license=%s rows=%d\n", s.ID, s.Version, s.Enabled, s.License, s.Rows)
		b = append(b, []byte(line)...)
		if s.Enabled {
			enabled++
		}
	}
	b = append(b, []byte("\nMaxMind GeoLite is not bundled. Set IPD_MAXMIND_CITY to a local mmdb if you hold a license.\n")...)
	path := filepath.Join(cfg.DataDir, "manifest.txt")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return Result{}, err
	}
	res := Result{Sources: enabled, Note: path}
	if cfg.MaxMindCity != "" {
		n, err := countMMDB(cfg.MaxMindCity)
		if err != nil {
			return res, err
		}
		res.MaxMind = fmt.Sprintf("%s (%d networks sampled)", cfg.MaxMindCity, n)
	}
	_ = ctx
	return res, nil
}

func countMMDB(path string) (int, error) {
	db, err := maxminddb.Open(path)
	if err != nil {
		return 0, err
	}
	defer db.Close()
	n := 0
	nets := db.Networks(maxminddb.SkipAliasedNetworks)
	for nets.Next() && n < 1000 {
		var raw any
		_, err := nets.Network(&raw)
		if err != nil {
			return n, err
		}
		n++
	}
	if err := nets.Err(); err != nil {
		return n, err
	}
	return n, nil
}

// MaxMindCity looks up one address when a file is configured. The empty
// string means the adapter is disabled.
func MaxMindCity(path, ip string) (map[string]any, error) {
	if path == "" {
		return nil, fmt.Errorf("maxmind disabled")
	}
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	var rec map[string]any
	err = db.Lookup(net.ParseIP(ip), &rec)
	return rec, err
}
