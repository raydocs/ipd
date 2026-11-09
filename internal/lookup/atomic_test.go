package lookup

import (
	"fmt"
	"net/netip"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"
)

var atomicIP = netip.MustParseAddr("9.9.9.9")

// This is a deterministic counterexample to composing the two legacy APIs.
// The channel forces publication between the two individually safe reads.
func TestLookupSplitCallsNotAtomic(t *testing.T) {
	e := replacementEngine(t)
	e.MergeSource(replacementMeta("bgp", 1), replacementRows("bgp", 1))
	refresh, done := make(chan struct{}), make(chan struct{})
	go func() {
		<-refresh
		e.MergeSource(replacementMeta("bgp", 2), replacementRows("bgp", 2))
		close(done)
	}()
	p := e.Lookup(atomicIP)
	close(refresh)
	<-done
	sources := e.Sources(replacementAt)
	if p.Org != "1" || sources[0].Version != "2" {
		t.Fatalf("counterexample not reproduced: ASN=%d metadata=%+v", p.ASN, sources)
	}
}

func TestLookupWithSourcesMatchesLegacy(t *testing.T) {
	e := replacementEngine(t)
	meta := []SourceMeta{
		{ID: "bgp", Kind: "local", Version: "a", Rows: 9, UpdatedAt: replacementAt, Frequency: "hour", License: "license", Attribution: "credit", URL: "offline:test", Redistributable: true, Enabled: true},
		{ID: "dbip_lite", Version: "disabled", UpdatedAt: replacementAt, Frequency: "day", Enabled: false},
		{ID: "placeholder", Version: "unknown-time", Enabled: true},
	}
	rows := append(replacementRows("bgp", 1), replacementRows("dbip_lite", 2)...)
	rows[0].Rec.Flags = []string{"anycast", "vpn"}
	rows[0].Rec.GeofeedCC, rows[0].Rec.RDNS = "DE", "offline.invalid"
	rows[1].Rec.CC = "DE"
	e.Reload(meta, rows)
	for _, ip := range []netip.Addr{atomicIP, netip.MustParseAddr("9.9.8.1"), netip.MustParseAddr("127.0.0.1"), netip.Addr{}} {
		for _, now := range []time.Time{replacementAt, replacementAt.Add(72 * time.Hour)} {
			p, sources := e.LookupWithSources(ip, now)
			if !reflect.DeepEqual(p, e.Lookup(ip)) || !reflect.DeepEqual(sources, e.Sources(now)) {
				t.Fatalf("legacy semantics changed: ip=%s profile=%+v sources=%+v", ip, p, sources)
			}
			if sources[0].Stale != Stale(meta[0], now) || sources[1].Enabled || sources[1].Stale || sources[2].Stale {
				t.Fatalf("staleness/disabled semantics changed: %+v", sources)
			}
			sources[0].License = "caller-owned"
			if e.Sources(now)[0].License != meta[0].License {
				t.Fatal("metadata slice aliases engine")
			}
		}
	}
}

func atomicWait(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("writer/reader did not finish (possible recursive RLock)")
	}
}

// A pending writer must not cause lookupLocked or sourcesLocked to reacquire
// RLock. TryRLock detects the writer's queueing, without sleeps.
func TestLookupWithSourcesPendingWriter(t *testing.T) {
	e := replacementEngine(t)
	installReplacement(t, e, replacementMeta("bgp", 1), replacementRows("bgp", 1))
	e.mu.RLock()
	old := e.mapped["bgp"]
	done := make(chan struct{})
	go func() {
		e.MergeSource(replacementMeta("bgp", 2), replacementRows("bgp", 2))
		close(done)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for e.mu.TryRLock() {
		e.mu.RUnlock()
		if time.Now().After(deadline) {
			e.mu.RUnlock()
			t.Fatal("writer never queued")
		}
		runtime.Gosched()
	}
	read := make(chan struct{})
	var p Profile
	var sources []SourceMeta
	go func() {
		// The test owns a read lock until this goroutine completes.
		p, sources = e.lookupLocked(atomicIP), e.sourcesLocked(replacementAt)
		close(read)
	}()
	select {
	case <-read:
		if p.Org != "1" || sources[0].Version != "1" || old.data == nil {
			t.Error("pinned reader lost its mapped generation")
		}
	case <-time.After(10 * time.Second):
		// Release before failing so cleanup can drain an incorrect nested lock.
		e.mu.RUnlock()
		atomicWait(t, done)
		atomicWait(t, read)
		t.Fatal("locked helpers reacquired RLock")
	}
	// The public API queues behind the already-pending writer. Releasing the
	// pinned reader must let that writer publish before the new reader runs.
	publicRead := make(chan struct{})
	var next Profile
	var nextSources []SourceMeta
	go func() {
		next, nextSources = e.LookupWithSources(atomicIP, replacementAt)
		close(publicRead)
	}()
	e.mu.RUnlock()
	atomicWait(t, done)
	atomicWait(t, publicRead)
	assertReleased(t, old)
	if next.Org != "2" || nextSources[0].Version != "2" {
		t.Fatalf("queued reader did not see writer's atomic pair: %+v %+v", next, nextSources)
	}
}

func TestLookupWithSourcesConcurrentPair(t *testing.T) {
	e := replacementEngine(t)
	e.MergeSource(replacementMeta("bgp", 1), replacementRows("bgp", 1))
	const rounds = 60
	paths := make([]string, rounds)
	for i := range paths {
		paths[i] = replacementFile(t, replacementMeta("bgp", i+2), replacementRows("bgp", i+2))
	}
	start, done := make(chan struct{}), make(chan struct{})
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range rounds * 8 {
				p, sources := e.LookupWithSources(atomicIP, replacementAt.Add(100*time.Hour))
				if len(sources) != 1 || len(p.Hits) != 1 {
					t.Errorf("incomplete pair: %+v %+v", p, sources)
					return
				}
				m := sources[0]
				if m.Version != p.Org || p.Org != fmt.Sprint(p.ASN-65000) || p.Hits[0].Rec.ASN != p.ASN ||
					!m.UpdatedAt.Equal(replacementMeta("bgp", p.ASN-65000).UpdatedAt) || m.Stale != Stale(m, replacementAt.Add(100*time.Hour)) {
					t.Errorf("mixed pair: %+v %+v", p, sources)
					return
				}
			}
		}()
	}
	for mode := range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := mode; i < rounds; i += 3 {
				m, rows := replacementMeta("bgp", i+2), replacementRows("bgp", i+2)
				switch mode {
				case 0:
					if _, err := e.InstallSnapshot(paths[i]); err != nil {
						t.Error(err)
					}
				case 1:
					e.MergeSource(m, rows)
				case 2:
					e.Reload([]SourceMeta{m}, rows)
				}
			}
		}()
	}
	close(start)
	go func() { wg.Wait(); close(done) }()
	atomicWait(t, done)
}

func TestLookupWithSourcesMappedLifetime(t *testing.T) {
	for _, mode := range []string{"merge", "reload", "install"} {
		t.Run(mode, func(t *testing.T) {
			e := replacementEngine(t)
			rows := replacementRows("bgp", 1)
			rows[0].Rec = Rec{Prefix: "9.9.9.0/24", ASN: 65001, Org: "retained org", CC: "US", City: "retained city", Region: "retained region", Flags: []string{"anycast", "vpn"}, RDNS: "offline.invalid", NetName: "retained net", Descr: "retained description", RegisteredCC: "DE", AnnouncedCC: "US", UpstreamType: "transit", Cloud: "test"}
			installReplacement(t, e, replacementMeta("bgp", 1), rows)
			old := e.mapped["bgp"]
			p, sources := e.LookupWithSources(atomicIP, replacementAt)
			want := e.Lookup(atomicIP)
			m, next := replacementMeta("bgp", 2), replacementRows("bgp", 2)
			switch mode {
			case "merge":
				e.MergeSource(m, next)
			case "reload":
				e.Reload([]SourceMeta{m}, next)
			case "install":
				installReplacement(t, e, m, next)
			}
			assertReleased(t, old)
			runtime.GC()
			if !reflect.DeepEqual(p, want) || p.Org != "retained org" || p.Hits[0].Rec.Descr != "retained description" || sources[0].Version != "1" {
				t.Fatalf("returned mmap data did not survive retirement: %+v %+v", p, sources)
			}
		})
	}
}
