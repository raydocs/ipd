package gfw

import (
	"encoding/json"
	"os"
	"testing"
)

func obs(net, icmp string, loss float64, tcp map[int]string, dns []string, sni string) Obs {
	return Obs{ID: net, Network: net, ASN: 1, City: "x", Healthy: true, ICMP: icmp, Loss: loss, TCP: tcp, DNSAddrs: dns, SNI: sni}
}

func TestStateMachine(t *testing.T) {
	poison := map[string]struct{}{"4.36.66.178": {}}
	ports := []int{22, 443}
	okTCP := map[int]string{22: "ok", 443: "ok"}
	cases := []struct {
		name string
		in   []Obs
		want string
	}{
		{"ok", []Obs{
			obs("ct", "ok", 0, okTCP, nil, "ok"),
			obs("cu", "ok", 0, okTCP, nil, "ok"),
			obs("cm", "ok", 0, okTCP, nil, "ok"),
			obs("control", "ok", 0, okTCP, nil, "ok"),
			{Network: "ct", Healthy: false, ICMP: "timeout"},
		}, VerdictOK},
		{"ip_blocked", []Obs{
			obs("ct", "timeout", 1, map[int]string{443: "timeout"}, nil, ""),
			obs("cu", "timeout", 1, map[int]string{443: "timeout"}, nil, ""),
			obs("cm", "timeout", 1, map[int]string{443: "timeout"}, nil, ""),
			obs("control", "ok", 0, okTCP, nil, "ok"),
		}, VerdictIPBlocked},
		{"port_blocked", []Obs{
			obs("ct", "ok", 0, map[int]string{22: "timeout", 443: "ok"}, nil, "ok"),
			obs("cu", "ok", 0, map[int]string{22: "timeout", 443: "ok"}, nil, "ok"),
			obs("cm", "ok", 0, okTCP, nil, "ok"),
			obs("control", "ok", 0, okTCP, nil, "ok"),
		}, VerdictPortBlocked},
		{"carrier_partial", []Obs{
			obs("ct", "timeout", 1, map[int]string{443: "timeout"}, nil, ""),
			obs("cu", "ok", 0, okTCP, nil, "ok"),
			obs("cm", "ok", 0, okTCP, nil, "ok"),
			obs("control", "ok", 0, okTCP, nil, "ok"),
		}, VerdictCarrierPartial},
		{"dns_poisoned", []Obs{
			obs("ct", "ok", 0, okTCP, []string{"4.36.66.178"}, "ok"),
			obs("cu", "ok", 0, okTCP, nil, "ok"),
			obs("cm", "ok", 0, okTCP, nil, "ok"),
			obs("control", "ok", 0, okTCP, []string{"1.1.1.1"}, "ok"),
		}, VerdictDNSPoisoned},
		{"sni_reset", []Obs{
			obs("ct", "ok", 0, okTCP, nil, "reset"),
			obs("cu", "ok", 0, okTCP, nil, "reset"),
			obs("cm", "ok", 0, okTCP, nil, "ok"),
			obs("control", "ok", 0, okTCP, nil, "ok"),
		}, VerdictSNIReset},
		{"congested", []Obs{
			obs("ct", "ok", 0.4, okTCP, nil, "ok"),
			obs("cu", "ok", 0.3, okTCP, nil, "ok"),
			obs("cm", "ok", 0, okTCP, nil, "ok"),
			obs("control", "ok", 0, okTCP, nil, "ok"),
		}, VerdictCongested},
		{"target_down", []Obs{
			obs("ct", "timeout", 1, map[int]string{443: "timeout"}, nil, ""),
			obs("cu", "timeout", 1, map[int]string{443: "timeout"}, nil, ""),
			obs("control", "timeout", 1, map[int]string{443: "timeout"}, nil, ""),
		}, VerdictTargetDown},
	}
	for _, tc := range cases {
		in := withQuorum(tc.in)
		a := Judge(in, ports, poison)
		b := Judge(in, ports, poison)
		if a.Verdict != tc.want || b.Verdict != a.Verdict {
			t.Fatalf("%s got %s (%v)", tc.name, a.Verdict, a.Notes)
		}
	}
	one := []Obs{obs("ct", "timeout", 1, map[int]string{443: "timeout"}, nil, "")}
	if got := Judge(one, ports, poison).Verdict; got != VerdictInsufficient {
		t.Fatalf("single probe verdict %s", got)
	}
	text := ExplainWallVsSent(VerdictIPBlocked, true)
	if text == "" {
		t.Fatal("explain")
	}
}

func withQuorum(in []Obs) []Obs {
	var out []Obs
	for _, o := range in {
		if o.Network == "control" || o.Network == "global" || o.Network == "overseas" {
			out = append(out, o)
			continue
		}
		a, b := o, o
		if a.ID == "" {
			a.ID = a.Network
		}
		b.ID = a.ID + "-2"
		out = append(out, a, b)
	}
	return out
}

func TestRecordedFixtures(t *testing.T) {
	raw, err := os.ReadFile("testdata/states.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []struct {
			Name  string `json:"name"`
			Want  string `json:"want"`
			Ports []int  `json:"ports"`
			Obs   []Obs  `json:"obs"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	poison := map[string]struct{}{"4.36.66.178": {}}
	for _, tc := range doc.Cases {
		got := Judge(tc.Obs, tc.Ports, poison)
		if got.Verdict != tc.Want {
			t.Fatalf("%s got %s notes %v", tc.Name, got.Verdict, got.Notes)
		}
		seen[tc.Want] = true
	}
	for _, v := range []string{VerdictOK, VerdictIPBlocked, VerdictPortBlocked, VerdictCarrierPartial, VerdictDNSPoisoned, VerdictSNIReset, VerdictCongested, VerdictTargetDown, VerdictInsufficient} {
		if !seen[v] {
			t.Fatalf("fixture missing %s", v)
		}
	}
}
