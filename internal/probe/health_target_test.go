package probe

import (
	"encoding/json"
	"testing"
)

// This test uses only the pre-change API so it can run against origin/main.
func TestTargetResultsAreNotAnchors(t *testing.T) {
	for _, status := range []string{"failed", "finished"} {
		var doc gpDoc
		if err := json.Unmarshal([]byte(`{"status":"finished","results":[{"probe":{"asn":4134,"city":"target-isolation","country":"CN"},"result":{"status":"`+status+`"}}]}`), &doc); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 5; i++ {
			got := decodeGP(doc, Query{Kind: KindPing, Target: "192.0.2.1"})
			if !got[0].Healthy {
				t.Fatalf("%s target result %d incorrectly rejected unknown probe", status, i)
			}
		}
	}
}
