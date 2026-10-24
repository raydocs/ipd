package lookup

import (
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
	"time"

	"github.com/gaissmai/bart"
)

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
	page := os.Getpagesize()
	var touch int
	for i := 0; i < len(mt.data); i += page {
		touch += int(mt.data[i])
	}
	if touch == -1 {
		t.Fatal("unreachable")
	}
	t.Logf("SNAPSHOT_ROWS %d LOAD %s", n, load)
	assertSnapshotMemory(t, path)
	if load > 3*time.Second {
		t.Fatalf("load %s", load)
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
