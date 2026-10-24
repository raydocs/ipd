package lookup

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/gaissmai/bart"
	"golang.org/x/sys/unix"
)

const (
	snapMagic   = "IPDS"
	snapVersion = 1
	snapRecSize = 32
	snapFixed   = 24
)

// SnapshotBuilder packs prefix rows into a memory-mappable file.
// Rows are stored packed, not as the Go Rec slice the old TSV path kept.
type SnapshotBuilder struct {
	Meta SourceMeta
	rows []packedRow
}

type packedRow struct {
	bits    uint8
	fam     uint8
	addr    [16]byte
	asn     uint32
	payload string
}

// NewSnapshotBuilder starts a snapshot for one source.
func NewSnapshotBuilder(meta SourceMeta) *SnapshotBuilder {
	return &SnapshotBuilder{Meta: meta}
}

// Add inserts one prefix. Invalid prefixes are skipped.
func (b *SnapshotBuilder) Add(r Rec) {
	if b == nil {
		return
	}
	pfx, err := netip.ParsePrefix(r.Prefix)
	if err != nil {
		return
	}
	pfx = pfx.Masked()
	row := packedRow{bits: uint8(pfx.Bits()), asn: uint32(r.ASN), payload: encodePayload(r)}
	if pfx.Addr().Is4() {
		row.fam = 4
		a := pfx.Addr().As4()
		copy(row.addr[:4], a[:])
	} else {
		row.fam = 6
		copy(row.addr[:], pfx.Addr().AsSlice())
	}
	b.rows = append(b.rows, row)
}

// Len is the number of accepted prefixes, before same-prefix collapse.
func (b *SnapshotBuilder) Len() int {
	if b == nil {
		return 0
	}
	return len(b.rows)
}

// CommitFile sorts, collapses duplicate prefixes, and atomically replaces path.
// A reader of path never observes a partial snapshot.
func (b *SnapshotBuilder) CommitFile(path string) error {
	if b == nil || len(b.rows) == 0 {
		return fmt.Errorf("empty snapshot")
	}
	sort.Slice(b.rows, func(i, j int) bool { return packedLess(b.rows[i], b.rows[j]) })
	w := 0
	for i := range b.rows {
		if w > 0 && samePacked(b.rows[w-1], b.rows[i]) {
			b.rows[w-1] = b.rows[i]
			continue
		}
		b.rows[w] = b.rows[i]
		w++
	}
	b.rows = b.rows[:w]
	b.Meta.Rows = len(b.rows)
	b.Meta.Enabled = true
	meta, err := json.Marshal(b.Meta)
	if err != nil {
		return err
	}
	var blob bytes.Buffer
	type placed struct {
		row packedRow
		off uint32
		n   uint32
	}
	placedRows := make([]placed, len(b.rows))
	for i, row := range b.rows {
		if blob.Len() > int(^uint32(0))-len(row.payload)-1 {
			return fmt.Errorf("snapshot string blob exceeds 4GiB")
		}
		placedRows[i] = placed{row: row, off: uint32(blob.Len()), n: uint32(len(row.payload))}
		blob.WriteString(row.payload)
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	hdr := make([]byte, snapFixed)
	copy(hdr[0:4], snapMagic)
	binary.LittleEndian.PutUint32(hdr[4:8], snapVersion)
	if !b.Meta.UpdatedAt.IsZero() {
		binary.LittleEndian.PutUint64(hdr[8:16], uint64(b.Meta.UpdatedAt.UTC().UnixNano()))
	}
	binary.LittleEndian.PutUint32(hdr[16:20], uint32(len(placedRows)))
	binary.LittleEndian.PutUint32(hdr[20:24], uint32(len(meta)))
	if _, err := f.Write(hdr); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if _, err := f.Write(meta); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	rec := make([]byte, snapRecSize)
	for _, pr := range placedRows {
		for i := range rec {
			rec[i] = 0
		}
		rec[0] = pr.row.bits
		rec[1] = pr.row.fam
		binary.LittleEndian.PutUint32(rec[4:8], pr.row.asn)
		binary.LittleEndian.PutUint32(rec[8:12], pr.off)
		binary.LittleEndian.PutUint32(rec[12:16], pr.n)
		copy(rec[16:32], pr.row.addr[:])
		if _, err := f.Write(rec); err != nil {
			f.Close()
			os.Remove(tmp)
			return err
		}
	}
	if _, err := f.Write(blob.Bytes()); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

func packedLess(a, b packedRow) bool {
	if a.fam != b.fam {
		return a.fam < b.fam
	}
	if c := bytes.Compare(a.addr[:], b.addr[:]); c != 0 {
		return c < 0
	}
	return a.bits < b.bits
}

func samePacked(a, b packedRow) bool {
	return a.fam == b.fam && a.bits == b.bits && a.addr == b.addr
}

func encodePayload(r Rec) string {
	return strings.Join([]string{
		cleanField(r.Org),
		cleanField(r.Region),
		cleanField(r.City),
		strconv.FormatFloat(r.Lat, 'f', -1, 64),
		strconv.FormatFloat(r.Lon, 'f', -1, 64),
		cleanField(r.ASType),
		cleanField(strings.Join(r.Flags, "|")),
		cleanField(r.RegisteredCC),
		cleanField(r.AnnouncedCC),
		cleanField(r.RDNS),
		cleanField(r.NetName),
		cleanField(r.Descr),
		strconv.Itoa(r.PrefixAgeDays),
		strconv.Itoa(r.UpstreamASN),
		cleanField(r.UpstreamType),
		cleanField(r.Cloud),
		cleanField(r.CC),
	}, "\t")
}

func cleanField(s string) string {
	s = strings.ReplaceAll(s, "\t", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func decodePayload(prefix string, asn int, payload string) Rec {
	f := strings.Split(payload, "\t")
	get := func(i int) string {
		if i < len(f) {
			return f[i]
		}
		return ""
	}
	rec := Rec{Prefix: prefix, ASN: asn, Org: get(0), Region: get(1), City: get(2), ASType: get(5), RegisteredCC: get(7), AnnouncedCC: get(8), RDNS: get(9), NetName: get(10), Descr: get(11), UpstreamType: get(14), Cloud: get(15), CC: get(16)}
	rec.Lat, _ = strconv.ParseFloat(get(3), 64)
	rec.Lon, _ = strconv.ParseFloat(get(4), 64)
	if flags := get(6); flags != "" {
		rec.Flags = strings.Split(flags, "|")
	}
	rec.PrefixAgeDays, _ = strconv.Atoi(get(12))
	rec.UpstreamASN, _ = strconv.Atoi(get(13))
	return rec
}

// mappedTable is a read-only prefix index backed by a mapped snapshot.
type mappedTable struct {
	f      *os.File
	data   []byte
	meta   SourceMeta
	n      int
	recAt  int
	blobAt int
	lens4  uint64
	lens6  [3]uint64
}

// OpenSnapshot maps path. The file stays mapped until Close.
func OpenSnapshot(path string) (*mappedTable, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if st.Size() < snapFixed {
		f.Close()
		return nil, fmt.Errorf("snapshot too small")
	}
	data, err := unix.Mmap(int(f.Fd()), 0, int(st.Size()), unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		f.Close()
		return nil, err
	}
	mt, err := parseMapped(data)
	if err != nil {
		unix.Munmap(data)
		f.Close()
		return nil, err
	}
	mt.f = f
	mt.data = data
	return mt, nil
}

func parseMapped(data []byte) (*mappedTable, error) {
	if len(data) < snapFixed || string(data[0:4]) != snapMagic {
		return nil, fmt.Errorf("not an ipd snapshot")
	}
	if binary.LittleEndian.Uint32(data[4:8]) != snapVersion {
		return nil, fmt.Errorf("snapshot version")
	}
	n := int(binary.LittleEndian.Uint32(data[16:20]))
	metaLen := int(binary.LittleEndian.Uint32(data[20:24]))
	if metaLen < 0 || snapFixed+metaLen > len(data) {
		return nil, fmt.Errorf("snapshot meta")
	}
	var meta SourceMeta
	if err := json.Unmarshal(data[snapFixed:snapFixed+metaLen], &meta); err != nil {
		return nil, err
	}
	recAt := snapFixed + metaLen
	need := recAt + n*snapRecSize
	if need > len(data) {
		return nil, fmt.Errorf("snapshot records truncated")
	}
	mt := &mappedTable{meta: meta, n: n, recAt: recAt, blobAt: need}
	for i := 0; i < n; i++ {
		rec := data[recAt+i*snapRecSize : recAt+(i+1)*snapRecSize]
		bits := rec[0]
		fam := rec[1]
		if fam == 4 && bits <= 32 {
			mt.lens4 |= uint64(1) << bits
		}
		if fam == 6 && bits <= 128 {
			mt.lens6[bits/64] |= uint64(1) << (bits % 64)
		}
		off := binary.LittleEndian.Uint32(rec[8:12])
		ln := binary.LittleEndian.Uint32(rec[12:16])
		if int(off)+int(ln) > len(data)-need {
			return nil, fmt.Errorf("snapshot payload truncated")
		}
	}
	return mt, nil
}

// Close releases the mapping.
func (m *mappedTable) Close() error {
	if m == nil {
		return nil
	}
	var err error
	if m.data != nil {
		err = unix.Munmap(m.data)
		m.data = nil
	}
	if m.f != nil {
		if cErr := m.f.Close(); err == nil {
			err = cErr
		}
		m.f = nil
	}
	return err
}

func (m *mappedTable) lookup(ip netip.Addr) (Rec, bool) {
	if m == nil || m.n == 0 || !ip.IsValid() {
		return Rec{}, false
	}
	fam := uint8(4)
	var addr [16]byte
	maxBits := 32
	if ip.Is4() {
		a := ip.As4()
		copy(addr[:4], a[:])
	} else {
		fam = 6
		maxBits = 128
		copy(addr[:], ip.AsSlice())
	}
	for bits := maxBits; bits >= 0; bits-- {
		if !m.hasLen(fam, bits) {
			continue
		}
		masked := maskAddr(addr, fam, bits)
		i := m.find(fam, masked, uint8(bits))
		if i < 0 {
			continue
		}
		return m.recAtIndex(i, masked, fam, bits), true
	}
	return Rec{}, false
}

func (m *mappedTable) hasLen(fam uint8, bits int) bool {
	if fam == 4 {
		return bits >= 0 && bits <= 32 && m.lens4&(uint64(1)<<uint(bits)) != 0
	}
	if bits < 0 || bits > 128 {
		return false
	}
	return m.lens6[bits/64]&(uint64(1)<<uint(bits%64)) != 0
}

func maskAddr(addr [16]byte, fam uint8, bits int) [16]byte {
	n := 4
	if fam == 6 {
		n = 16
	}
	var out [16]byte
	copy(out[:], addr[:n])
	for i := 0; i < n; i++ {
		left := bits - i*8
		switch {
		case left >= 8:
		case left <= 0:
			out[i] = 0
		default:
			out[i] &= ^byte(0xff >> left)
		}
	}
	return out
}

func (m *mappedTable) find(fam uint8, addr [16]byte, bits uint8) int {
	i := sort.Search(m.n, func(i int) bool {
		rf, ra, rb := m.key(i)
		if rf != fam {
			return rf > fam
		}
		if c := bytes.Compare(ra[:], addr[:]); c != 0 {
			return c > 0
		}
		return rb >= bits
	})
	if i >= m.n {
		return -1
	}
	rf, ra, rb := m.key(i)
	if rf != fam || rb != bits || ra != addr {
		return -1
	}
	return i
}

func (m *mappedTable) key(i int) (fam uint8, addr [16]byte, bits uint8) {
	rec := m.data[m.recAt+i*snapRecSize : m.recAt+(i+1)*snapRecSize]
	bits = rec[0]
	fam = rec[1]
	copy(addr[:], rec[16:32])
	return fam, addr, bits
}

func (m *mappedTable) recAtIndex(i int, addr [16]byte, fam uint8, bits int) Rec {
	raw := m.data[m.recAt+i*snapRecSize : m.recAt+(i+1)*snapRecSize]
	asn := int(binary.LittleEndian.Uint32(raw[4:8]))
	off := int(binary.LittleEndian.Uint32(raw[8:12]))
	n := int(binary.LittleEndian.Uint32(raw[12:16]))
	payload := string(m.data[m.blobAt+off : m.blobAt+off+n])
	ip, _ := addrToIP(addr, fam)
	pfx := netip.PrefixFrom(ip, bits).Masked()
	return decodePayload(pfx.String(), asn, payload)
}

func addrToIP(addr [16]byte, fam uint8) (netip.Addr, bool) {
	if fam == 4 {
		return netip.AddrFrom4([4]byte{addr[0], addr[1], addr[2], addr[3]}), true
	}
	var a [16]byte
	copy(a[:], addr[:])
	return netip.AddrFrom16(a), true
}

func (m *mappedTable) each(fn func(netip.Prefix, Rec)) {
	if m == nil {
		return
	}
	for i := 0; i < m.n; i++ {
		fam, addr, bits := m.key(i)
		ip, _ := addrToIP(addr, fam)
		pfx := netip.PrefixFrom(ip, int(bits)).Masked()
		fn(pfx, m.recAtIndex(i, addr, fam, int(bits)))
	}
}

// InstallSnapshot maps path and swaps it in as the live table for that source.
// Data, metadata and source time are published under the same write lock.
// That lock also drains readers before the previous mapping is unmapped.
func (e *Engine) InstallSnapshot(path string) (int, error) {
	if e == nil {
		return 0, fmt.Errorf("nil engine")
	}
	mt, err := OpenSnapshot(path)
	if err != nil {
		return 0, err
	}
	if mt.meta.ID == "" || mt.n == 0 {
		mt.Close()
		return 0, fmt.Errorf("snapshot missing source id")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.mapped == nil {
		e.mapped = map[string]*mappedTable{}
	}
	if e.tables == nil {
		e.tables = map[string]*bart.Table[Rec]{}
	}
	old := e.mapped[mt.meta.ID]
	e.mapped[mt.meta.ID] = mt
	delete(e.tables, mt.meta.ID)
	e.notePrefixLocked(mt.meta.ID, mt.meta.UpdatedAt)
	if e.byID == nil {
		e.byID = map[string]int{}
	}
	meta := mt.meta
	meta.Rows = mt.n
	meta.Enabled = true
	if i, ok := e.byID[meta.ID]; ok {
		e.meta[i] = meta
	} else {
		e.byID[meta.ID] = len(e.meta)
		e.meta = append(e.meta, meta)
	}
	if old != nil {
		_ = old.Close()
	}
	return mt.n, nil
}
