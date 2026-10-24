package gfw

import "testing"

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
		a := Judge(tc.in, ports, poison)
		b := Judge(tc.in, ports, poison)
		if a.Verdict != tc.want || b.Verdict != a.Verdict {
			t.Fatalf("%s got %s (%v)", tc.name, a.Verdict, a.Notes)
		}
	}
	text := ExplainWallVsSent(VerdictIPBlocked, true)
	if text == "" {
		t.Fatal("explain")
	}
}
