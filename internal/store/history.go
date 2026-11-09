package store

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"time"
)

func nullableJSON(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	return string(raw)
}

// PurgeHistory physically removes observations strictly before the retention boundary.
// Nonpositive retention is rejected, never interpreted as unlimited storage.
func (s *Store) PurgeHistory(now time.Time, retention time.Duration) (int64, error) {
	if retention <= 0 {
		return 0, fmt.Errorf("history retention must be positive")
	}
	res, err := s.DB.Exec("DELETE FROM history WHERE ts < ?", now.Add(-retention).Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Observation is local stored evidence, not a routing announcement or a causal event.
// Null provenance denotes legacy/unknown source metadata, [] denotes no source hits.
type Observation struct {
	TS         time.Time       `json:"ts"`
	Prefix     string          `json:"prefix"`
	ASN        int             `json:"asn"`
	CC         string          `json:"cc"`
	Type       string          `json:"type"`
	Flags      string          `json:"flags"`
	Provenance json.RawMessage `json:"provenance"`
}

func (s *Store) Observations(ip string, since, until time.Time) ([]Observation, error) {
	rows, err := s.DB.Query("SELECT ts,prefix,asn,cc,type,flags,provenance FROM history WHERE ip=? AND ts>=? AND ts<=? ORDER BY ts,id", ip, since.Unix(), until.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Observation{}
	for rows.Next() {
		var o Observation
		var ts int64
		var raw *string
		if err := rows.Scan(&ts, &o.Prefix, &o.ASN, &o.CC, &o.Type, &o.Flags, &raw); err != nil {
			return nil, err
		}
		o.TS = time.Unix(ts, 0).UTC()
		if raw != nil {
			o.Provenance = json.RawMessage(*raw)
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// LocalNeighbors reports aggregate latest observations in an address bucket.
// It does not return addresses, scan the subnet, or interpret absent rows as clean.
type LocalNeighbors struct {
	Prefix            string         `json:"prefix"`
	ObservedAddresses int            `json:"observed_addresses"`
	Types             map[string]int `json:"types"`
}

func (s *Store) LocalNeighbors(prefix netip.Prefix, since, until time.Time) (LocalNeighbors, error) {
	out := LocalNeighbors{Prefix: prefix.Masked().String(), Types: map[string]int{}}
	rows, err := s.DB.Query(`SELECT h.ip,h.type FROM history h WHERE h.ts>=? AND h.ts<=?
 AND NOT EXISTS (SELECT 1 FROM history newer WHERE newer.ip=h.ip AND newer.ts>=? AND newer.ts<=?
 AND (newer.ts>h.ts OR (newer.ts=h.ts AND newer.id>h.id)))`, since.Unix(), until.Unix(), since.Unix(), until.Unix())
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var ip, typ string
		if err := rows.Scan(&ip, &typ); err != nil {
			return out, err
		}
		addr, err := netip.ParseAddr(ip)
		if err != nil || !prefix.Contains(addr.Unmap()) {
			continue
		}
		if typ == "" {
			typ = "unknown"
		}
		out.ObservedAddresses++
		out.Types[typ]++
	}
	return out, rows.Err()
}
