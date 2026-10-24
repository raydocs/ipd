//go:build linux

package lookup

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

// assertSnapshotMemory keeps procfs mapping and RSS checks mandatory on Linux.
func assertSnapshotMemory(t *testing.T, path string) {
	t.Helper()
	maps, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(maps), path) {
		t.Fatal("snapshot is not memory-mapped")
	}
	mappedRSS := mappingRSS(path)
	procRSS := rssBytes()
	t.Logf("MAPPED_RSS_BYTES %d PROCESS_RSS_BYTES %d", mappedRSS, procRSS)
	// The packed file is resident. A []Rec of this many rows would be several times larger.
	if mappedRSS == 0 || mappedRSS > 96<<20 {
		t.Fatalf("mapped rss %d", mappedRSS)
	}
}

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
