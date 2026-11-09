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

func historyAddr(ip string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("invalid history IP %q", ip)
	}
	return addr.Unmap(), nil
}

func (s *Store) Observations(ip string, since, until time.Time) ([]Observation, error) {
	addr, err := historyAddr(ip)
	if err != nil {
		return nil, err
	}
	out, _, err := s.readHistory(addr, netip.Prefix{}, since.Unix(), until.Unix())
	return out, err
}

// HistoryView derives all response components from one SQLite statement snapshot.
func (s *Store) HistoryView(ip string, prefix netip.Prefix, since, until time.Time) ([]Observation, []Event, LocalNeighbors, error) {
	addr, err := historyAddr(ip)
	if err != nil {
		return nil, nil, LocalNeighbors{}, err
	}
	snaps, neighbors, err := s.readHistory(addr, prefix, since.Unix(), until.Unix())
	if err != nil {
		return nil, nil, neighbors, err
	}
	return snaps, historyEvents(snaps), neighbors, nil
}

// LocalNeighbors reports aggregate latest observations in an address bucket.
// It does not return addresses, scan the subnet, or interpret absent rows as clean.
type LocalNeighbors struct {
	Prefix            string         `json:"prefix"`
	ObservedAddresses int            `json:"observed_addresses"`
	Types             map[string]int `json:"types"`
}

func (s *Store) LocalNeighbors(prefix netip.Prefix, since, until time.Time) (LocalNeighbors, error) {
	_, out, err := s.readHistory(netip.Addr{}, prefix, since.Unix(), until.Unix())
	return out, err
}

// Scan in (ts,id) order: overwriting a canonical address selects its latest
// observation even when old rows used expanded IPv6 or IPv4-mapped keys.
// Only the target snapshots and aggregate neighbor types leave this read view.
func (s *Store) readHistory(target netip.Addr, prefix netip.Prefix, since, until int64) ([]Observation, LocalNeighbors, error) {
	out := []Observation{}
	neighbors := LocalNeighbors{Prefix: prefix.Masked().String(), Types: map[string]int{}}
	rows, err := s.DB.Query(`SELECT ip,ts,prefix,asn,cc,type,flags,provenance FROM history WHERE ts>=? AND ts<=? ORDER BY ts,id`, since, until)
	if err != nil {
		return nil, neighbors, err
	}
	defer rows.Close()
	latest := map[netip.Addr]string{}
	for rows.Next() {
		var ip string
		var ts int64
		var o Observation
		var raw *string
		if err := rows.Scan(&ip, &ts, &o.Prefix, &o.ASN, &o.CC, &o.Type, &o.Flags, &raw); err != nil {
			return nil, neighbors, err
		}
		addr, err := historyAddr(ip)
		if err != nil {
			continue
		} // Unparseable legacy keys are not address evidence.
		o.TS = time.Unix(ts, 0).UTC()
		if raw != nil {
			o.Provenance = json.RawMessage(*raw)
		}
		if addr == target {
			out = append(out, o)
		}
		if prefix.Contains(addr) {
			typ := o.Type
			if typ == "" {
				typ = "unknown"
			}
			latest[addr] = typ
		}
	}
	if err := rows.Err(); err != nil {
		return nil, neighbors, err
	}
	if err := rows.Close(); err != nil {
		return nil, neighbors, err
	}
	for _, typ := range latest {
		neighbors.ObservedAddresses++
		neighbors.Types[typ]++
	}
	return out, neighbors, nil
}
