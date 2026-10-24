package lookup

import (
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gaissmai/bart"
)

func rssBytes() uint64 {
	b, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) < 2 {
		return 0
	}
	pages, _ := strconv.ParseUint(f[1], 10, 64)
	return pages * uint64(os.Getpagesize())
}

// mappingRSS is the resident size of the file-backed mapping, from smaps.
func mappingRSS(path string) uint64 {
	b, err := os.ReadFile("/proc/self/smaps")
	if err != nil {
		return 0
	}
	lines := strings.Split(string(b), "\n")
	var total uint64
	want := false
	for _, line := range lines {
		if strings.Contains(line, path) {
			want = true
			continue
		}
		if want && strings.HasPrefix(line, "Rss:") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				kb, _ := strconv.ParseUint(f[1], 10, 64)
				total += kb * 1024
			}
			want = false
		}
		if want && len(line) > 0 && !strings.Contains(line, ":") && !strings.HasPrefix(line, "VmFlags") {
			// next mapping header without an Rss line
			if strings.Contains(line, "-") {
				want = false
			}
		}
	}
	return total
}

func TestSnapshotUncappedMapLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bgp.ipds")
	const n = 400001
	built := time.Date(2026, 10, 23, 3, 0, 0, 0, time.UTC)
	func() {
		b := NewSnapshotBuilder(SourceMeta{
			ID: "bgp", Kind: "local", UpdatedAt: built, Frequency: "day",
			License: "public BGP table", Attribution: "test", Enabled: true,
		})
		for i := 0; i < n; i++ {
			b.Add(Rec{Prefix: snapIP(i).String(), ASN: 1000 + i%17, CC: "US", Org: "row"})
		}
		// The old cap stopped at 400000. One more row must be stored.
		if b.Len() != n {
			t.Fatalf("builder kept %d", b.Len())
		}
		if err := b.CommitFile(path); err != nil {
			t.Fatal(err)
		}
	}()
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temp snapshot left behind")
	}
	runtime.GC()
	t0 := time.Now()
	mt, err := OpenSnapshot(path)
	load := time.Since(t0)
	if err != nil {
		t.Fatal(err)
	}
	defer mt.Close()
	if mt.n != n {
		t.Fatalf("mapped rows %d", mt.n)
	}
	maps, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(maps), path) {
		t.Fatal("snapshot is not memory-mapped")
	}
	page := os.Getpagesize()
	var touch int
	for i := 0; i < len(mt.data); i += page {
		touch += int(mt.data[i])
	}
	if touch == -1 {
		t.Fatal("unreachable")
	}
	mappedRSS := mappingRSS(path)
	procRSS := rssBytes()
	t.Logf("SNAPSHOT_ROWS %d LOAD %s MAPPED_RSS_BYTES %d PROCESS_RSS_BYTES %d", n, load, mappedRSS, procRSS)
	if load > 3*time.Second {
		t.Fatalf("load %s", load)
	}
	// The packed file is resident. A []Rec of this many rows would be several times larger.
	if mappedRSS == 0 || mappedRSS > 96<<20 {
		t.Fatalf("mapped rss %d", mappedRSS)
	}
	sample := snapIP(257).Addr()
	rec, ok := mt.lookup(sample)
	if !ok || rec.ASN == 0 || rec.CC != "US" {
		t.Fatalf("lookup %+v %v", rec, ok)
	}

	eng := &Engine{tables: map[string]*bart.Table[Rec]{}, byID: map[string]int{}}
	if _, err := eng.InstallSnapshot(path); err != nil {
		t.Fatal(err)
	}
	var ds []time.Duration
	for i := 0; i < 2000; i++ {
		ip := snapIP((i * 97) % n).Addr()
		t1 := time.Now()
		got := eng.Lookup(ip)
		ds = append(ds, time.Since(t1))
		if i == 0 && got.ASN == 0 {
			t.Fatalf("engine miss %s %+v", ip, got)
		}
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	p95 := ds[int(float64(len(ds))*0.95)]
	t.Logf("SNAPSHOT_P95 %s", p95)
	if p95 > 20*time.Millisecond {
		t.Fatalf("p95 %s", p95)
	}
	at, age := eng.SnapshotAge(built.Add(48 * time.Hour))
	if !at.Equal(built) || age != 48*3600 {
		t.Fatalf("snapshot age %s %d", at, age)
	}
}

func TestSnapshotAtomicSwap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dbip_lite.ipds")
	write := func(cc string, asn int) {
		b := NewSnapshotBuilder(SourceMeta{ID: "dbip_lite", UpdatedAt: time.Now().UTC(), Kind: "local", Frequency: "month"})
		b.Add(Rec{Prefix: "9.9.9.0/24", CC: cc, ASN: asn, City: "Test"})
		if err := b.CommitFile(path); err != nil {
			t.Fatal(err)
		}
	}
	write("US", 1)
	eng := &Engine{tables: map[string]*bart.Table[Rec]{}, byID: map[string]int{}}
	if _, err := eng.InstallSnapshot(path); err != nil {
		t.Fatal(err)
	}
	if eng.Lookup(netip.MustParseAddr("9.9.9.9")).CC != "US" {
		t.Fatal(eng.Lookup(netip.MustParseAddr("9.9.9.9")))
	}
	write("DE", 2)
	if _, err := eng.InstallSnapshot(path); err != nil {
		t.Fatal(err)
	}
	p := eng.Lookup(netip.MustParseAddr("9.9.9.9"))
	if p.CC != "DE" || p.ASN != 2 || p.City != "Test" {
		t.Fatalf("%+v", p)
	}
}

func snapIP(i int) netip.Prefix {
	a := uint32(i)
	ip := netip.AddrFrom4([4]byte{45, byte(a >> 16), byte(a >> 8), byte(a)})
	return netip.PrefixFrom(ip, 32)
}

func BenchmarkSnapshotLoad(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "bgp.ipds")
	const n = 100000
	bld := NewSnapshotBuilder(SourceMeta{ID: "bgp", UpdatedAt: time.Now().UTC(), Kind: "local"})
	for i := 0; i < n; i++ {
		bld.Add(Rec{Prefix: snapIP(i).String(), ASN: 1, CC: "US"})
	}
	if err := bld.CommitFile(path); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mt, err := OpenSnapshot(path)
		if err != nil {
			b.Fatal(err)
		}
		mt.Close()
	}
}
