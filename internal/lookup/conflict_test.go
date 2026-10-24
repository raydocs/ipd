package lookup

import (
	"encoding/json"
	"net/netip"
	"os"
	"testing"

	"github.com/gaissmai/bart"
)

func TestGoldenConflicts(t *testing.T) {
	raw, err := os.ReadFile("testdata/golden_conflicts.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name         string `json:"name"`
		IP           string `json:"ip"`
		WantAnycast  bool   `json:"want_anycast"`
		WantConflict bool   `json:"want_conflict"`
		WantField    string `json:"want_field"`
		WantChosenCC string `json:"want_chosen_cc"`
		Rows         []struct {
			Source       string `json:"source"`
			Prefix       string `json:"prefix"`
			ASN          int    `json:"asn"`
			CC           string `json:"cc"`
			Org          string `json:"org"`
			ASType       string `json:"as_type"`
			City         string `json:"city"`
			RegisteredCC string `json:"registered_cc"`
			NetName      string `json:"net_name"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) < 3 {
		t.Fatalf("golden set %d", len(cases))
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			e := &Engine{tables: map[string]*bart.Table[Rec]{}, byID: map[string]int{}}
			bySource := map[string][]SourceRow{}
			for _, row := range tc.Rows {
				bySource[row.Source] = append(bySource[row.Source], SourceRow{Source: row.Source, Rec: Rec{
					Prefix: row.Prefix, ASN: row.ASN, CC: row.CC, Org: row.Org, ASType: row.ASType,
					City: row.City, RegisteredCC: row.RegisteredCC, NetName: row.NetName,
				}})
			}
			for id, rows := range bySource {
				e.MergeSource(SourceMeta{ID: id, Kind: "local", Enabled: true}, rows)
			}
			p := e.Lookup(netip.MustParseAddr(tc.IP))
			if p.Anycast != tc.WantAnycast {
				t.Fatalf("anycast %v conflicts %+v", p.Anycast, p.Conflicts)
			}
			conflict := false
			hasField := tc.WantField == ""
			for _, c := range p.Conflicts {
				if c.Field == "anycast" && !tc.WantAnycast {
					t.Fatalf("unexpected anycast section %+v", c)
				}
				if c.Field != "anycast" {
					conflict = true
				}
				if c.Field == "anycast" {
					conflict = true
				}
				if tc.WantField != "" && c.Field == tc.WantField {
					hasField = true
				}
			}
			if tc.WantAnycast {
				conflict = true
			}
			if conflict != tc.WantConflict && !(tc.WantAnycast && tc.WantConflict) {
				t.Fatalf("conflict=%v want %v %+v", conflict, tc.WantConflict, p.Conflicts)
			}
			if tc.WantConflict && !hasField {
				t.Fatalf("missing field %s in %+v", tc.WantField, p.Conflicts)
			}
			if !tc.WantConflict && len(p.Conflicts) != 0 {
				t.Fatalf("normal prefix has conflicts %+v", p.Conflicts)
			}
			if tc.WantChosenCC != "" && p.CC != tc.WantChosenCC {
				t.Fatalf("cc %s", p.CC)
			}
			if tc.Name == "cloudflare-dns-anycast-omitted" {
				if p.CC != "US" {
					t.Fatalf("weighted cc %s", p.CC)
				}
				found := false
				for _, c := range p.Conflicts {
					if c.Field == "anycast" && c.Anycast && c.Note != "" {
						found = true
					}
					if c.Field == "cc" {
						found = found && c.Chosen == "US"
					}
				}
				if !found {
					t.Fatalf("%+v", p.Conflicts)
				}
			}
		})
	}
}
