// Package gfw decides whether a target is blocked from China, and why.
// It does not move traffic. It classifies ping, TCP, DNS, and SNI observations
// that a vantage provider already collected.
package gfw

import "strconv"

// Verdicts, in the priority used by Judge.
const (
	VerdictTargetDown     = "target_down"
	VerdictIPBlocked      = "ip_blocked"
	VerdictPortBlocked    = "port_blocked"
	VerdictCarrierPartial = "carrier_partial"
	VerdictDNSPoisoned    = "dns_poisoned"
	VerdictSNIReset       = "sni_reset"
	VerdictCongested      = "congested"
	VerdictOK             = "ok"
	VerdictInsufficient   = "insufficient_sample"
)

// Quorum is the minimum number of healthy probes that must agree inside one
// carrier before that carrier can vote for ip_blocked or port_blocked.
const Quorum = 2

// Obs is one probe's raw observation. Healthy probes that failed their anchor
// check are ignored.
type Obs struct {
	ID       string         `json:"id"`
	Network  string         `json:"network"` // ct, cu, cm, or control
	ASN      int            `json:"asn"`
	City     string         `json:"city"`
	Healthy  bool           `json:"healthy"`
	ICMP     string         `json:"icmp"` // ok, loss, timeout
	Loss     float64        `json:"loss"` // 0-1
	TCP      map[int]string `json:"tcp"`  // port -> ok, timeout, reset
	DNSAddrs []string       `json:"dns_addrs"`
	SNI      string         `json:"sni"` // ok, reset, timeout, or empty
}

// Result is the gfw_check payload.
type Result struct {
	Verdict    string            `json:"verdict"`
	PerCarrier map[string]string `json:"per_carrier"`
	Probes     []ProbeView       `json:"probes"`
	Control    []ProbeView       `json:"control"`
	Confidence float64           `json:"confidence"`
	Notes      []string          `json:"notes"`
}

// ProbeView is the public per-probe row.
type ProbeView struct {
	ASN  int               `json:"asn"`
	City string            `json:"city"`
	ICMP string            `json:"icmp"`
	TCP  map[string]string `json:"tcp"`
}

// Judge applies the priority order from the plan.
// ip_blocked requires two carriers to agree. Unhealthy probes are dropped.
func Judge(obs []Obs, ports []int, poison map[string]struct{}) Result {
	cn := map[string][]Obs{}
	var control []Obs
	for _, o := range obs {
		if !o.Healthy {
			continue
		}
		if o.Network == "control" || o.Network == "global" || o.Network == "overseas" {
			control = append(control, o)
			continue
		}
		if o.Network == "ct" || o.Network == "cu" || o.Network == "cm" {
			cn[o.Network] = append(cn[o.Network], o)
		}
	}
	res := Result{
		PerCarrier: map[string]string{"ct": "no_data", "cu": "no_data", "cm": "no_data"},
		Probes:     []ProbeView{},
		Control:    views(control),
		Notes:      []string{},
	}
	for _, net := range []string{"ct", "cu", "cm"} {
		for _, o := range cn[net] {
			res.Probes = append(res.Probes, view(o))
		}
		res.PerCarrier[net] = carrierState(cn[net], ports)
	}
	controlDown := len(control) > 0 && groupDown(control, ports, 1)
	carriersDown := 0
	carriersUp := 0
	for _, net := range []string{"ct", "cu", "cm"} {
		st := res.PerCarrier[net]
		switch st {
		case "down":
			carriersDown++
		case "ok", "port", "loss", "dns", "sni":
			carriersUp++
		}
	}
	insuff := 0
	for _, net := range []string{"ct", "cu", "cm"} {
		if res.PerCarrier[net] == "insufficient" {
			insuff++
		}
	}
	// Priority: target_down > ip_blocked > port_blocked > carrier_partial > dns_poisoned > sni_reset > congested > insufficient_sample > ok.
	// ip_blocked and port_blocked already require a per-carrier quorum, so one failed probe cannot produce them.
	switch {
	case controlDown && carriersDown >= 2:
		res.Verdict = VerdictTargetDown
		res.Notes = append(res.Notes, "overseas control also failed, so this is not evidence of a China block")
		res.Confidence = 0.8
	case carriersDown >= 2 && !controlDown:
		res.Verdict = VerdictIPBlocked
		res.Notes = append(res.Notes, "at least two China carriers cannot reach the target while the overseas control can")
		res.Confidence = 0.9
	case portBlocked(cn, ports) && !controlDown:
		res.Verdict = VerdictPortBlocked
		res.Notes = append(res.Notes, "some ports answer and others do not, on more than one carrier")
		res.Confidence = 0.86
	case carriersDown == 1 && carriersUp >= 1:
		res.Verdict = VerdictCarrierPartial
		res.Notes = append(res.Notes, "only one carrier is failing; not called an IP block")
		res.Confidence = 0.8
	case dnsPoison(cn, poison):
		res.Verdict = VerdictDNSPoisoned
		res.Notes = append(res.Notes, "China resolvers returned a known poisoned address")
		res.Confidence = 0.84
	case sniReset(cn) && !sniResetAll(control):
		res.Verdict = VerdictSNIReset
		res.Notes = append(res.Notes, "TLS handshake reset from China and not from the control")
		res.Confidence = 0.8
	case congested(cn):
		res.Verdict = VerdictCongested
		res.Notes = append(res.Notes, "high loss with the port still reachable; this is congestion, not a block")
		res.Confidence = 0.7
	case insuff > 0 || carriersDown+carriersUp < 2:
		res.Verdict = VerdictInsufficient
		res.Notes = append(res.Notes, "fewer than two agreeing probes on enough carriers; insufficient_sample")
		res.Confidence = 0.3
	default:
		res.Verdict = VerdictOK
		res.Notes = append(res.Notes, "reachable from the probes that answered")
		res.Confidence = 0.85
	}
	return res
}

func carrierState(obs []Obs, ports []int) string {
	if len(obs) == 0 {
		return "no_data"
	}
	if len(obs) < Quorum {
		return "insufficient"
	}
	if allDown(obs, ports) {
		return "down"
	}
	sniN := 0
	for _, o := range obs {
		if o.SNI == "reset" {
			sniN++
		}
	}
	if sniN >= Quorum {
		return "sni"
	}
	lossN := 0
	for _, o := range obs {
		if o.Loss >= 0.2 {
			lossN++
		}
	}
	if lossN >= Quorum && !allDown(obs, ports) {
		return "loss"
	}
	if len(ports) >= 2 && somePortFails(obs, ports) {
		return "port"
	}
	return "ok"
}

func allDown(obs []Obs, ports []int) bool {
	return groupDown(obs, ports, Quorum)
}

func groupDown(obs []Obs, ports []int, need int) bool {
	if len(obs) < need || need <= 0 {
		return false
	}
	down := 0
	for _, o := range obs {
		if probeDown(o, ports) {
			down++
		}
	}
	return down >= need && down*2 >= len(obs)
}

func probeDown(o Obs, ports []int) bool {
	if o.ICMP == "ok" {
		return false
	}
	for _, p := range ports {
		if o.TCP[p] == "ok" {
			return false
		}
	}
	return true
}

func portBlocked(cn map[string][]Obs, ports []int) bool {
	if len(ports) < 2 {
		return false
	}
	badCarriers := 0
	for _, net := range []string{"ct", "cu", "cm"} {
		obs := cn[net]
		if len(obs) == 0 || allDown(obs, ports) {
			continue
		}
		if somePortFails(obs, ports) {
			badCarriers++
		}
	}
	return badCarriers >= 2
}

func somePortFails(obs []Obs, ports []int) bool {
	okN, badN := 0, 0
	for _, p := range ports {
		okC, badC := 0, 0
		for _, o := range obs {
			switch o.TCP[p] {
			case "ok":
				okC++
			case "timeout", "reset":
				badC++
			}
		}
		if okC >= Quorum && badC == 0 {
			okN++
		}
		if badC >= Quorum && okC == 0 {
			badN++
		}
	}
	return okN >= 1 && badN >= 1
}

func dnsPoison(cn map[string][]Obs, poison map[string]struct{}) bool {
	if len(poison) == 0 {
		return false
	}
	n := 0
	for _, net := range []string{"ct", "cu", "cm"} {
		for _, o := range cn[net] {
			for _, a := range o.DNSAddrs {
				if _, ok := poison[a]; ok {
					n++
					break
				}
			}
		}
	}
	return n >= Quorum
}

func sniReset(cn map[string][]Obs) bool {
	n := 0
	for _, net := range []string{"ct", "cu", "cm"} {
		resets := 0
		for _, o := range cn[net] {
			if o.SNI == "reset" {
				resets++
			}
		}
		if resets >= Quorum {
			n++
		}
	}
	return n >= 2
}

func sniResetAll(obs []Obs) bool {
	if len(obs) == 0 {
		return false
	}
	for _, o := range obs {
		if o.SNI == "reset" {
			return true
		}
	}
	return false
}

func congested(cn map[string][]Obs) bool {
	for _, net := range []string{"ct", "cu", "cm"} {
		n := 0
		for _, o := range cn[net] {
			if o.Loss >= 0.2 {
				n++
			}
		}
		if n >= Quorum {
			return true
		}
	}
	return false
}

func view(o Obs) ProbeView {
	tcp := map[string]string{}
	for p, st := range o.TCP {
		tcp[strconv.Itoa(p)] = st
	}
	return ProbeView{ASN: o.ASN, City: o.City, ICMP: o.ICMP, TCP: tcp}
}

func views(obs []Obs) []ProbeView {
	out := make([]ProbeView, 0, len(obs))
	for _, o := range obs {
		out = append(out, view(o))
	}
	return out
}

// ExplainWallVsSent separates a GFW block from Google treating the egress as mainland China.
func ExplainWallVsSent(gfwVerdict string, sentToChina bool) string {
	switch {
	case gfwVerdict == VerdictIPBlocked && sentToChina:
		return "被墙，并且 Google 也把出口判成中国大陆。被墙是国内探针连不上；送中是出口访问 Google 时被跳到 google.cn 或 .hk。"
	case gfwVerdict == VerdictIPBlocked:
		return "更像被墙：海外对照通，国内至少两个运营商不通。这和「送中」不是一回事。送中是 Google 把出口当成中国大陆（跳转 google.cn / .hk），机器本身从国内未必连不上。"
	case sentToChina:
		return "这是送中，不是被墙：出口还能访问 Google，但 Google 把地区判成中国大陆（.hk 或 google.cn）。被墙指的是国内探针连不上这个 IP。"
	default:
		return "没有看到被墙，也没有看到送中。"
	}
}
