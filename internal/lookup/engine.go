package lookup

import (
	"net/netip"
	"sync"
	"time"

	"github.com/gaissmai/bart"
	"github.com/oschwald/maxminddb-golang"
	"ipd/internal/privacy"
)

// Engine is an in-memory multi-source prefix index.
// Each source has its own bart table so a lookup is a handful of LPM queries
// and does not touch disk. Large feeds (DB-IP, prefix-to-ASN) can instead sit
// in a memory-mapped snapshot; Lookup consults that table under the same lock.
type Engine struct {
	mu          sync.RWMutex
	tables      map[string]*bart.Table[Rec]
	mapped      map[string]*mappedTable
	prefixTimes map[string]time.Time
	meta        []SourceMeta
	byID        map[string]int
	mmdb        *maxminddb.Reader
}

// New builds an engine from the bundled offline snapshot.
func New() *Engine {
	e := &Engine{
		tables: map[string]*bart.Table[Rec]{},
		byID:   map[string]int{},
	}
	e.load(Bundled())
	return e
}

// MergeSource replaces one source table and leaves every other source in place.
// An empty row list does not wipe a source: a failed download must not drop the bundled snapshot.
func (e *Engine) MergeSource(meta SourceMeta, rows []SourceRow) int {
	if e == nil || len(rows) == 0 {
		return 0
	}
	tbl := &bart.Table[Rec]{}
	n := 0
	for _, row := range rows {
		pfx, err := netip.ParsePrefix(row.Rec.Prefix)
		if err != nil {
			continue
		}
		pfx = pfx.Masked()
		rec := row.Rec
		rec.Prefix = pfx.String()
		tbl.Insert(pfx, rec)
		n++
	}
	if n == 0 {
		return 0
	}
	meta.Rows = n
	meta.Enabled = true
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.tables == nil {
		e.tables = map[string]*bart.Table[Rec]{}
	}
	if e.byID == nil {
		e.byID = map[string]int{}
	}
	old := e.mapped[meta.ID]
	delete(e.mapped, meta.ID)
	e.tables[meta.ID] = tbl
	e.notePrefixLocked(meta.ID, meta.UpdatedAt)
	if i, ok := e.byID[meta.ID]; ok {
		e.meta[i] = meta
	} else {
		e.byID[meta.ID] = len(e.meta)
		e.meta = append(e.meta, meta)
	}
	// The write lock drained every reader of old before retirement. Keep it
	// through Close so publication and mapping lifetime share one boundary.
	if old != nil {
		_ = old.Close()
	}
	return n
}

// AttachMMDB opens a GeoLite2 City database. Lookups fill only fields the prefix index left empty.
func (e *Engine) AttachMMDB(path string) error {
	if e == nil || path == "" {
		return nil
	}
	db, err := maxminddb.Open(path)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.mmdb != nil {
		_ = e.mmdb.Close()
	}
	e.mmdb = db
	if e.byID == nil {
		return nil
	}
	if i, ok := e.byID["maxmind_geolite"]; ok {
		e.meta[i].Enabled = true
		e.meta[i].UpdatedAt = time.Now().UTC()
		e.meta[i].Version = "file"
		e.meta[i].URL = path
	}
	return nil
}

// Reload replaces the entire prefix snapshot. Empty or wholly invalid input
// retains the last good snapshot, just like MergeSource and InstallSnapshot.
func (e *Engine) Reload(meta []SourceMeta, rows []SourceRow) {
	if e == nil || len(rows) == 0 {
		return
	}
	next := &Engine{tables: map[string]*bart.Table[Rec]{}, byID: map[string]int{}}
	if next.load(snapshot{Meta: meta, Rows: rows}) == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	old := e.mapped
	e.mapped = nil
	e.tables = next.tables
	e.meta = next.meta
	e.byID = next.byID
	e.prefixTimes = next.prefixTimes
	for _, mt := range old {
		_ = mt.Close()
	}
}

type snapshot struct {
	Meta []SourceMeta
	Rows []SourceRow
}

// SourceRow is one insertable prefix.
type SourceRow struct {
	Source string
	Rec    Rec
}

func (e *Engine) load(s snapshot) int {
	e.meta = append([]SourceMeta(nil), s.Meta...)
	e.byID = map[string]int{}
	for i := range e.meta {
		e.byID[e.meta[i].ID] = i
		if e.tables[e.meta[i].ID] == nil {
			e.tables[e.meta[i].ID] = &bart.Table[Rec]{}
		}
	}
	counts := map[string]int{}
	for _, row := range s.Rows {
		pfx, err := netip.ParsePrefix(row.Rec.Prefix)
		if err != nil {
			continue
		}
		pfx = pfx.Masked()
		tbl := e.tables[row.Source]
		if tbl == nil {
			tbl = &bart.Table[Rec]{}
			e.tables[row.Source] = tbl
		}
		rec := row.Rec
		rec.Prefix = pfx.String()
		tbl.Insert(pfx, rec)
		counts[row.Source]++
	}
	for i := range e.meta {
		if e.meta[i].Rows == 0 {
			e.meta[i].Rows = counts[e.meta[i].ID]
		}
		e.meta[i].Stale = Stale(e.meta[i], time.Now().UTC())
	}
	n := 0
	for id, count := range counts {
		n += count
		var at time.Time
		if i, ok := e.byID[id]; ok {
			at = e.meta[i].UpdatedAt
		}
		e.notePrefixLocked(id, at)
	}
	return n
}

// SnapshotAge reports the oldest loaded DB-IP / BGP source time, or the
// oldest loaded prefix source if neither is present. A missing timestamp in
// that clock set returns (zero time, 0): unknown, not fresh. Future ages clamp
// to zero. Each call observes one atomic engine state, not a multi-call read.
func (e *Engine) SnapshotAge(now time.Time) (time.Time, int64) {
	if e == nil {
		return time.Time{}, 0
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	at := e.prefixAtLocked()
	if at.IsZero() {
		return time.Time{}, 0
	}
	sec := int64(now.Sub(at).Seconds())
	if sec < 0 {
		sec = 0
	}
	return at.UTC(), sec
}

func (e *Engine) notePrefixLocked(id string, at time.Time) {
	if id != "bgp" && id != "dbip_lite" {
		return
	}
	if e.prefixTimes == nil {
		e.prefixTimes = map[string]time.Time{}
	}
	e.prefixTimes[id] = at.UTC()
}

func (e *Engine) prefixAtLocked() time.Time {
	var oldest time.Time
	for _, id := range []string{"bgp", "dbip_lite"} {
		t, ok := e.prefixTimes[id]
		if !ok {
			continue
		}
		if t.IsZero() {
			return time.Time{}
		}
		if oldest.IsZero() || t.Before(oldest) {
			oldest = t
		}
	}
	if !oldest.IsZero() {
		return oldest
	}
	// Only queryable prefix data participates in the fallback clock, not
	// metadata-only placeholders or an attached MMDB's local open time.
	consider := func(id string) bool {
		i, ok := e.byID[id]
		if !ok || e.meta[i].UpdatedAt.IsZero() {
			return false
		}
		at := e.meta[i].UpdatedAt
		if oldest.IsZero() || at.Before(oldest) {
			oldest = at
		}
		return true
	}
	for id, tbl := range e.tables {
		if tbl.Size() > 0 && !consider(id) {
			return time.Time{}
		}
	}
	for id := range e.mapped {
		if !consider(id) {
			return time.Time{}
		}
	}
	return oldest
}

// Sources returns a copy of source metadata with staleness evaluated at now.
func (e *Engine) Sources(now time.Time) []SourceMeta {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]SourceMeta, len(e.meta))
	copy(out, e.meta)
	for i := range out {
		out[i].Stale = Stale(out[i], now)
	}
	return out
}

// Stale is true when a source is older than twice its declared cadence.
func Stale(m SourceMeta, now time.Time) bool {
	if m.UpdatedAt.IsZero() || !m.Enabled {
		return false
	}
	window := cadence(m.Frequency) * 2
	if window <= 0 {
		return false
	}
	return now.Sub(m.UpdatedAt) > window
}

func cadence(freq string) time.Duration {
	switch freq {
	case "hour":
		return time.Hour
	case "day":
		return 24 * time.Hour
	case "week":
		return 7 * 24 * time.Hour
	case "month":
		return 31 * 24 * time.Hour
	default:
		return 0
	}
}

// Lookup merges every source's longest prefix for ip.
func (e *Engine) Lookup(ip netip.Addr) Profile {
	p := Profile{IP: ip.String(), AnnouncedBy: []int{}, Flags: []string{}}
	if !privacy.IsPublic(ip) {
		p.Reserved = true
		p.CC = ""
		p.ASType = "reserved"
		return p
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	var hits []Hit
	for id, tbl := range e.tables {
		if e.mapped[id] != nil {
			continue
		}
		if rec, ok := tbl.Lookup(ip); ok {
			hits = append(hits, Hit{Source: id, Rec: rec})
		}
	}
	for id, mt := range e.mapped {
		if rec, ok := mt.lookup(ip); ok {
			hits = append(hits, Hit{Source: id, Rec: rec})
		}
	}
	p = merge(ip.String(), hits)
	if e.mmdb != nil && (p.CC == "" || p.City == "") {
		fillMMDB(&p, e.mmdb, ip)
	}
	return p
}

type mmdbCity struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
	Subdivisions []struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
}

func fillMMDB(p *Profile, db *maxminddb.Reader, ip netip.Addr) {
	var rec mmdbCity
	if err := db.Lookup(ip.AsSlice(), &rec); err != nil {
		return
	}
	if p.CC == "" {
		p.CC = rec.Country.ISOCode
	}
	if p.City == "" {
		p.City = rec.City.Names["en"]
	}
	if p.Region == "" && len(rec.Subdivisions) > 0 {
		p.Region = rec.Subdivisions[0].Names["en"]
	}
	if p.Lat == 0 && p.Lon == 0 {
		p.Lat = rec.Location.Latitude
		p.Lon = rec.Location.Longitude
	}
}

// LookupPrefix returns the covering record for an exact prefix in one source, if any.
func (e *Engine) Covering(source string, pfx netip.Prefix) (Rec, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if mt := e.mapped[source]; mt != nil {
		return mt.lookup(pfx.Addr())
	}
	tbl := e.tables[source]
	if tbl == nil {
		return Rec{}, false
	}
	rec, ok := tbl.Lookup(pfx.Addr())
	return rec, ok
}

// Composition summarises what we know about a prefix, typically a /24.
func (e *Engine) Composition(cidr string) PrefixComposition {
	pfx, err := netip.ParsePrefix(cidr)
	if err != nil {
		return PrefixComposition{CIDR: cidr}
	}
	pfx = pfx.Masked()
	// Sample the network address and a few offsets plus any more-specifics.
	e.mu.RLock()
	defer e.mu.RUnlock()
	comp := PrefixComposition{CIDR: pfx.String(), Notable: []string{}}
	seenFlags := map[string]int{}
	classCount := map[string]int{}
	n := 0
	consider := func(rec Rec) {
		n++
		cls := classOf(rec)
		classCount[cls]++
		for _, f := range rec.Flags {
			seenFlags[f]++
			if f == "tor" || f == "vpn" || f == "malicious" || f == "proxy" {
				comp.Notable = appendUnique(comp.Notable, f+"@"+rec.Prefix)
			}
		}
		if rec.Cloud != "" {
			comp.Notable = appendUnique(comp.Notable, "cloud:"+rec.Cloud)
		}
	}
	// Covering match at the base address, from every source. Prefer the most
	// specific signal: cloud and bgp win for classification counts.
	base := pfx.Addr()
	var best Rec
	bestSpec := -1
	bestClass := "unknown"
	considerTable := func(rec Rec, ok bool) {
		if !ok {
			return
		}
		spec := prefixLen(rec.Prefix)
		cls := classOf(rec)
		if spec > bestSpec || (spec == bestSpec && classRank(cls) > classRank(bestClass)) {
			best = rec
			bestSpec = spec
			bestClass = cls
		}
		for _, f := range rec.Flags {
			seenFlags[f]++
		}
	}
	for id, tbl := range e.tables {
		if e.mapped[id] != nil {
			continue
		}
		rec, ok := tbl.Lookup(base)
		considerTable(rec, ok)
	}
	for _, mt := range e.mapped {
		rec, ok := mt.lookup(base)
		considerTable(rec, ok)
	}
	if bestSpec >= 0 {
		consider(best)
	}
	comp.HostsSeen = 1
	if n == 0 {
		comp.Composition = map[string]float64{"unknown": 1}
		comp.Contamination = 0
		return comp
	}
	comp.Composition = map[string]float64{}
	for k, c := range classCount {
		comp.Composition[k] = float64(c) / float64(n)
	}
	bad := classCount["hosting"] + classCount["proxy"] + classCount["cdn"]
	comp.Contamination = float64(bad) / float64(n)
	if seenFlags["tor"] > 0 || seenFlags["vpn"] > 0 || seenFlags["malicious"] > 0 || seenFlags["proxy"] > 0 {
		if comp.Contamination < 0.8 && (classCount["proxy"] > 0 || seenFlags["vpn"] > 0 || seenFlags["tor"] > 0) {
			comp.Contamination = 0.8
		}
	}
	return comp
}

func prefixLen(s string) int {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return -1
	}
	return p.Bits()
}

func classRank(c string) int {
	switch c {
	case "proxy":
		return 5
	case "hosting":
		return 4
	case "cdn":
		return 3
	case "residential", "mobile", "business":
		return 2
	default:
		return 1
	}
}

func classOf(rec Rec) string {
	if rec.Cloud != "" || rec.ASType == "hosting" {
		return "hosting"
	}
	if rec.ASType == "cdn" || has(rec.Flags, "anycast") {
		return "cdn"
	}
	for _, f := range rec.Flags {
		if f == "vpn" || f == "tor" || f == "proxy" {
			return "proxy"
		}
	}
	switch rec.ASType {
	case "cable", "dsl", "isp", "mobile":
		return "residential"
	case "business", "enterprise":
		return "business"
	default:
		if rec.ASType == "" {
			return "unknown"
		}
		return rec.ASType
	}
}

func has(flags []string, want string) bool {
	for _, f := range flags {
		if f == want {
			return true
		}
	}
	return false
}

func appendUnique(ss []string, s string) []string {
	for _, e := range ss {
		if e == s {
			return ss
		}
	}
	return append(ss, s)
}

// PrefixComposition is the /24 (or other) neighbour summary.
type PrefixComposition struct {
	CIDR          string             `json:"cidr"`
	HostsSeen     int                `json:"hosts_seen"`
	Composition   map[string]float64 `json:"composition"`
	Contamination float64            `json:"contamination"`
	Notable       []string           `json:"notable"`
}

// ASNInfo aggregates prefixes announced by an ASN.
func (e *Engine) ASNInfo(asn int) ASNInfo {
	e.mu.RLock()
	defer e.mu.RUnlock()
	info := ASNInfo{ASN: asn, PrefixesV4: []string{}, PrefixesV6: []string{}, Upstreams: []int{}}
	seenP := map[string]struct{}{}
	seenU := map[int]struct{}{}
	absorb := func(source string, pfx netip.Prefix, rec Rec) {
		if rec.ASN != asn && rec.UpstreamASN != asn {
			return
		}
		if rec.ASN != asn {
			return
		}
		if info.Org == "" {
			info.Org = rec.Org
		}
		if info.CC == "" {
			info.CC = firstNonEmpty(rec.AnnouncedCC, rec.CC, rec.RegisteredCC)
		}
		if info.Type == "" {
			info.Type = rec.ASType
		}
		if rec.Eyeball > info.EyeballUsers {
			info.EyeballUsers = rec.Eyeball
		}
		if source == "peeringdb" && rec.ASType != "" {
			info.PeeringDBType = rec.ASType
			info.Type = rec.ASType
		}
		ps := pfx.String()
		if _, ok := seenP[ps]; !ok {
			seenP[ps] = struct{}{}
			if pfx.Addr().Is4() {
				info.PrefixesV4 = append(info.PrefixesV4, ps)
			} else {
				info.PrefixesV6 = append(info.PrefixesV6, ps)
			}
		}
		if rec.UpstreamASN != 0 {
			if _, ok := seenU[rec.UpstreamASN]; !ok {
				seenU[rec.UpstreamASN] = struct{}{}
				info.Upstreams = append(info.Upstreams, rec.UpstreamASN)
			}
		}
	}
	for source, tbl := range e.tables {
		if e.mapped[source] != nil {
			continue
		}
		for pfx, rec := range tbl.All() {
			absorb(source, pfx, rec)
		}
	}
	for source, mt := range e.mapped {
		mt.each(func(pfx netip.Prefix, rec Rec) { absorb(source, pfx, rec) })
	}
	return info
}

// ASNInfo is the asn_lookup payload.
type ASNInfo struct {
	ASN           int      `json:"asn"`
	Org           string   `json:"org"`
	Type          string   `json:"type"`
	CC            string   `json:"cc"`
	PrefixesV4    []string `json:"prefixes_v4"`
	PrefixesV6    []string `json:"prefixes_v6"`
	Upstreams     []int    `json:"upstreams"`
	PeeringDBType string   `json:"peeringdb_type"`
	EyeballUsers  int      `json:"eyeball_users"`
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
