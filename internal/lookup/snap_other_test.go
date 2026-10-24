//go:build !linux

package lookup

import "testing"

func assertSnapshotMemory(t *testing.T, path string) {
	t.Helper()
	t.Log("procfs mapping/RSS checks are Linux-only; functional and latency checks still run")
}
