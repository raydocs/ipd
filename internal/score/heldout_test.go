package score

import (
	"encoding/json"
	"net/netip"
	"os"
	"testing"

	"ipd/internal/lookup"
)

func TestResidentialHeldOut(t *testing.T) {
	raw, err := os.ReadFile("testdata/residential_heldout.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Rows []struct {
			ID      string `json:"id"`
			IP      string `json:"ip"`
			Label   string `json:"label"`
			Source  string `json:"source"`
			Profile struct {
				CC     string `json:"cc"`
				ASType string `json:"as_type"`
				RDNS   string `json:"rdns"`
				Descr  string `json:"descr"`
			} `json:"profile"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Rows) < 10 {
		t.Fatalf("held-out rows %d", len(doc.Rows))
	}
	eng := lookup.New()
	decided, correct, abstain := 0, 0, 0
	for _, row := range doc.Rows {
		if row.Source == "" || row.Label == "" {
			t.Fatalf("unlabeled %s", row.ID)
		}
		var p lookup.Profile
		var comp lookup.PrefixComposition
		if row.IP != "" {
			p = eng.Lookup(netip.MustParseAddr(row.IP))
			comp = eng.Composition(prefix24(p.IP))
		} else {
			p = lookup.Profile{CC: row.Profile.CC, ASType: row.Profile.ASType, RDNS: row.Profile.RDNS, Descr: row.Profile.Descr}
		}
		got := ClassifyObserved(p, comp, nil)
		abstained := got.Abstained || got.Class == "cannot determine" || got.Class == "abstain"
		if abstained {
			abstain++
			if row.Label != "cannot determine" {
				t.Errorf("abstained on labeled %s (%s)", row.ID, row.Label)
			}
			continue
		}
		decided++
		if got.Class == row.Label {
			correct++
		} else {
			t.Errorf("%s got %s want %s evidence %v features-class %+v", row.ID, got.Class, row.Label, got.Evidence, got)
		}
	}
	if decided == 0 {
		t.Fatal("no decisions")
	}
	precision := float64(correct) / float64(len(doc.Rows))
	// Precision over decided rows only. Abstaining on a positive label counts against it
	// so the gate cannot hide mistakes by refusing everything.
	decidedPrecision := 0.0
	hits := 0
	for _, row := range doc.Rows {
		var p lookup.Profile
		var comp lookup.PrefixComposition
		if row.IP != "" {
			p = eng.Lookup(netip.MustParseAddr(row.IP))
			comp = eng.Composition(prefix24(p.IP))
		} else {
			p = lookup.Profile{CC: row.Profile.CC, ASType: row.Profile.ASType, RDNS: row.Profile.RDNS, Descr: row.Profile.Descr}
		}
		got := ClassifyObserved(p, comp, nil)
		if got.Abstained || got.Class == "cannot determine" || got.Class == "abstain" {
			continue
		}
		hits++
		if got.Class == row.Label {
			decidedPrecision++
		}
	}
	prec := decidedPrecision / float64(hits)
	abstainRate := float64(abstain) / float64(len(doc.Rows))
	t.Logf("RESIDENTIAL_PRECISION %.4f ABSTAIN_RATE %.4f DECIDED %d/%d OVERALL %.4f", prec, abstainRate, decided, len(doc.Rows), precision)
	if prec < 0.90 {
		t.Fatalf("precision %.3f", prec)
	}
	if abstainRate < 0.15 {
		t.Fatalf("abstain rate %.3f; low-evidence rows were classified", abstainRate)
	}
}

func prefix24(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is4() {
		return ip
	}
	a := addr.As4()
	p := netip.PrefixFrom(netip.AddrFrom4([4]byte{a[0], a[1], a[2], 0}), 24)
	return p.String()
}
