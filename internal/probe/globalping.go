package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Globalping is the default China vantage. Anonymous quota applies; a token
// is optional and only changes the Authorization header.
// MinInterval spaces measurement creates. Zero means 1100ms. Negative skips the wait (tests).
type Globalping struct {
	BaseURL     string
	Token       string
	Client      *http.Client
	MinInterval time.Duration
	// Runner overrides the live probe picker in tests.
	Runner func(ctx context.Context, q Query) ([]Sample, error)
}

func (g Globalping) Name() string  { return "globalping" }
func (g Globalping) Enabled() bool { return true }

func (g Globalping) Measure(ctx context.Context, q Query) ([]Sample, error) {
	if g.Runner != nil {
		return g.Runner(ctx, q)
	}
	base := g.BaseURL
	if base == "" {
		base = "https://api.globalping.io/v1"
	}
	client := g.Client
	if client == nil {
		client = &http.Client{Timeout: 55 * time.Second}
	}
	if err := g.wait(ctx); err != nil {
		return nil, err
	}
	if err := g.reserve(time.Now()); err != nil {
		return nil, err
	}
	body := g.request(q)
	raw, _ := json.Marshal(body)
	b, status, hdr, err := g.do(ctx, client, http.MethodPost, base+"/measurements", raw)
	if err != nil {
		return nil, err
	}
	if status == http.StatusTooManyRequests {
		wait := retryAfter(hdr)
		gpGate.push(wait)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
		b, status, _, err = g.do(ctx, client, http.MethodPost, base+"/measurements", raw)
		if err != nil {
			return nil, err
		}
	}
	if status >= 300 {
		return nil, fmt.Errorf("globalping %d: %s", status, truncate(b))
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(b, &created); err != nil {
		return nil, err
	}
	if created.ID == "" {
		return nil, fmt.Errorf("globalping: empty id")
	}
	deadline := time.Now().Add(50 * time.Second)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		b, status, _, err = g.do(ctx, client, http.MethodGet, base+"/measurements/"+created.ID, nil)
		if err != nil {
			return nil, err
		}
		if status >= 300 {
			return nil, fmt.Errorf("globalping %d: %s", status, truncate(b))
		}
		var doc gpDoc
		if err := json.Unmarshal(b, &doc); err != nil {
			return nil, err
		}
		if doc.Status == "finished" || doc.Status == "failed" {
			return decodeGP(doc, q), nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(700 * time.Millisecond):
		}
	}
	return nil, fmt.Errorf("globalping: timed out waiting for %s", created.ID)
}

func (g Globalping) do(ctx context.Context, client *http.Client, method, url string, body []byte) ([]byte, int, http.Header, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return nil, 0, nil, err
	}
	if body != nil {
		req.Header.Set("content-type", "application/json")
	}
	req.Header.Set("user-agent", "ipd/0.9")
	if g.Token != "" {
		req.Header.Set("authorization", "Bearer "+g.Token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	return b, resp.StatusCode, resp.Header, nil
}

func (g Globalping) wait(ctx context.Context) error {
	if g.MinInterval < 0 {
		return nil
	}
	d := g.MinInterval
	if d == 0 {
		d = 1100 * time.Millisecond
	}
	return gpGate.wait(ctx, d)
}

// gpGate spaces anonymous measurement creates across the process.
var gpGate gate

type gate struct {
	mu   sync.Mutex
	next time.Time
}

func (g *gate) wait(ctx context.Context, d time.Duration) error {
	g.mu.Lock()
	now := time.Now()
	if g.next.Before(now) {
		g.next = now
	}
	wait := time.Until(g.next)
	g.next = g.next.Add(d)
	g.mu.Unlock()
	if wait <= 0 {
		return nil
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (g *gate) push(d time.Duration) {
	g.mu.Lock()
	until := time.Now().Add(d)
	if until.After(g.next) {
		g.next = until
	}
	g.mu.Unlock()
}

func retryAfter(h http.Header) time.Duration {
	if h == nil {
		return 5 * time.Second
	}
	v := h.Get("Retry-After")
	if v == "" {
		return 5 * time.Second
	}
	if n, err := strconv.Atoi(v); err == nil && n >= 0 {
		if n == 0 {
			return 50 * time.Millisecond
		}
		if n > 60 {
			n = 60
		}
		return time.Duration(n) * time.Second
	}
	return 5 * time.Second
}

// primaryASN is one backbone ASN per carrier. Asking for every regional ASN
// spends the anonymous credit budget without changing the route class.
var primaryASN = map[string]int{"ct": 4134, "cu": 4837, "cm": 9808}

func (g Globalping) request(q Query) map[string]any {
	limit := q.Limit
	if limit <= 0 {
		limit = 1
	}
	if limit > 50 {
		limit = 50
	}
	var locs []map[string]any
	if len(q.Countries) > 0 {
		for _, c := range q.Countries {
			locs = append(locs, map[string]any{"country": strings.ToUpper(c), "limit": limit})
		}
	} else {
		carriers := q.Carriers
		if len(carriers) == 0 {
			carriers = []string{"ct", "cu", "cm"}
		}
		for _, c := range carriers {
			asn := primaryASN[c]
			if asn == 0 {
				continue
			}
			locs = append(locs, map[string]any{"country": "CN", "asn": asn, "limit": limit})
		}
		if q.Control > 0 {
			locs = append(locs, map[string]any{"country": "US", "limit": q.Control})
		}
	}
	target := q.Target
	typ := "ping"
	opts := map[string]any{}
	switch q.Kind {
	case KindTCP:
		typ = "ping"
		opts["protocol"] = "TCP"
		port := q.Port
		if port == 0 {
			port = 443
		}
		opts["port"] = port
		opts["packets"] = packetsOf(q)
	case KindTrace:
		typ = "traceroute"
		if q.Port != 0 {
			opts["protocol"] = "TCP"
			opts["port"] = q.Port
		}
	case KindMTR:
		typ = "mtr"
		opts["packets"] = packetsOf(q)
		if q.Port != 0 {
			opts["protocol"] = "TCP"
			opts["port"] = q.Port
		}
	case KindDNS:
		typ = "dns"
		if q.DNSName != "" {
			target = q.DNSName
		}
		opts["query"] = map[string]any{"type": "A"}
	case KindHTTP:
		typ = "http"
		port := q.Port
		if port == 0 {
			port = 443
		}
		opts["port"] = port
		if port == 443 {
			opts["protocol"] = "HTTPS"
		} else {
			opts["protocol"] = "HTTP"
		}
		opts["request"] = map[string]any{"method": "HEAD", "path": "/"}
	default:
		typ = "ping"
		opts["protocol"] = "ICMP"
		opts["packets"] = packetsOf(q)
	}
	// Globalping rejects ipVersion when the target is already an address.
	if net.ParseIP(target) == nil {
		opts["ipVersion"] = 4
	}
	return map[string]any{
		"type":               typ,
		"target":             target,
		"locations":          locs,
		"measurementOptions": opts,
	}
}

func packetsOf(q Query) int {
	if q.Packets > 0 {
		return q.Packets
	}
	return 3
}

var carrierASNs = map[string][]int{
	"ct": {4134, 4812},
	"cu": {4837, 17621, 9929},
	"cm": {9808, 56046},
}

// CarrierOfASN maps a China backbone ASN to ct/cu/cm.
func CarrierOfASN(asn int) string {
	for c, asns := range carrierASNs {
		for _, a := range asns {
			if a == asn {
				return c
			}
		}
	}
	switch asn {
	case 4134, 4812, 4809:
		return "ct"
	case 4837, 17621, 9929, 10099:
		return "cu"
	case 9808, 56046, 58453, 58807:
		return "cm"
	default:
		return ""
	}
}

type gpDoc struct {
	Status  string     `json:"status"`
	Results []gpResult `json:"results"`
}

type gpResult struct {
	Probe struct {
		ASN     flexInt `json:"asn"`
		City    string  `json:"city"`
		Country string  `json:"country"`
		Network string  `json:"network"`
	} `json:"probe"`
	Result struct {
		Status          string  `json:"status"`
		Raw             string  `json:"rawOutput"`
		StatusCode      int     `json:"statusCode"`
		ResolvedAddress string  `json:"resolvedAddress"`
		Hops            []gpHop `json:"hops"`
		Stats           struct {
			Loss float64 `json:"loss"`
			Avg  float64 `json:"avg"`
		} `json:"stats"`
		Answers []struct {
			Value string `json:"value"`
		} `json:"answers"`
	} `json:"result"`
}

type gpHop struct {
	IP               string  `json:"ip"`
	Avg              float64 `json:"avg"`
	ASN              flexInt `json:"asn"`
	ResolvedAddress  string  `json:"resolvedAddress"`
	ResolvedHostname string  `json:"resolvedHostname"`
	Timings          []struct {
		RTT float64 `json:"rtt"`
	} `json:"timings"`
	Stats struct {
		Avg  float64 `json:"avg"`
		Loss float64 `json:"loss"`
	} `json:"stats"`
}

type flexInt int

func (f *flexInt) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	b = bytes.Trim(b, `"`)
	if len(b) == 0 {
		return nil
	}
	n, err := strconv.Atoi(string(b))
	if err != nil {
		return err
	}
	*f = flexInt(n)
	return nil
}

func decodeGP(doc gpDoc, q Query) []Sample {
	var out []Sample
	for _, r := range doc.Results {
		asn := int(r.Probe.ASN)
		netw := CarrierOfASN(asn)
		if r.Probe.Country != "" && r.Probe.Country != "CN" {
			netw = "control"
		}
		if netw == "" && r.Probe.Country == "CN" {
			netw = "ct"
		}
		loss := r.Result.Stats.Loss
		if loss > 1 {
			loss = loss / 100
		}
		probeFailed := r.Result.Status == "failed" && strings.TrimSpace(r.Result.Raw) == "" && r.Result.Stats.Avg == 0 && r.Result.Stats.Loss == 0 && len(r.Result.Hops) == 0 && len(r.Result.Answers) == 0
		id := strconv.Itoa(asn) + "/" + r.Probe.City
		healthy := !probeFailed && DefaultHealth.Healthy(id)
		DefaultHealth.Observe(id, !probeFailed)
		s := Sample{
			Provider: "globalping",
			Network:  netw,
			ASN:      asn,
			City:     r.Probe.City,
			Country:  r.Probe.Country,
			Healthy:  healthy,
			Loss:     loss,
			RTTMS:    r.Result.Stats.Avg,
		}
		applyKind(&s, q, r)
		if q.Kind == KindTrace {
			s.TraceDestination, s.DestinationReached = traceCompletion(q.Target, r)
		}
		for _, h := range r.Result.Hops {
			ip := h.ResolvedAddress
			if ip == "" {
				ip = h.IP
			}
			if ip == "" {
				ip = "*"
			}
			rtt := h.Avg
			if rtt == 0 {
				rtt = h.Stats.Avg
			}
			if rtt == 0 && len(h.Timings) > 0 {
				var sum float64
				n := 0
				for _, t := range h.Timings {
					if t.RTT > 0 {
						sum += t.RTT
						n++
					}
				}
				if n > 0 {
					rtt = sum / float64(n)
				}
			}
			s.Hops = append(s.Hops, Hop{IP: ip, RTTMS: rtt, ASN: int(h.ASN)})
		}
		for _, a := range r.Result.Answers {
			if a.Value != "" {
				s.DNSAddrs = append(s.DNSAddrs, a.Value)
			}
		}
		out = append(out, s)
	}
	return out
}

// A finished measurement is not necessarily a finished route. Use the actual
// destination address and a responding final hop; never resolve a hostname here
// using a different vantage from the provider that performed the measurement.
func traceCompletion(target string, r gpResult) (string, *bool) {
	dst, err := netip.ParseAddr(target)
	if err != nil {
		dst, err = netip.ParseAddr(r.Result.ResolvedAddress)
	}
	if err != nil {
		return "", nil
	}
	dst = dst.Unmap()
	if r.Result.Status != "finished" {
		return dst.String(), nil
	}
	reached := false
	if len(r.Result.Hops) > 0 {
		last := r.Result.Hops[len(r.Result.Hops)-1]
		address := last.ResolvedAddress
		if address == "" {
			address = last.IP
		}
		ip, err := netip.ParseAddr(address)
		replied := len(last.Timings) > 0 || last.Avg > 0 || last.Stats.Avg > 0
		reached = err == nil && ip.Unmap() == dst && replied
	}
	return dst.String(), &reached
}

func applyKind(s *Sample, q Query, r gpResult) {
	status := r.Result.Status
	raw := strings.ToLower(r.Result.Raw)
	switch q.Kind {
	case KindTCP:
		port := q.Port
		if port == 0 {
			port = 443
		}
		if s.TCP == nil {
			s.TCP = map[int]string{}
		}
		s.TCP[port] = reachState(status, raw, r.Result.Stats.Loss)
		s.ICMP = ""
	case KindHTTP:
		s.SNI = sniState(status, raw, r.Result.StatusCode)
		s.ICMP = ""
	case KindDNS:
		s.ICMP = ""
		if status == "failed" {
			s.Healthy = true
		}
	case KindTrace, KindMTR:
		if status == "failed" {
			s.ICMP = "timeout"
		} else if len(r.Result.Hops) > 0 || status == "finished" {
			s.ICMP = "ok"
		}
	default:
		s.ICMP = reachState(status, raw, r.Result.Stats.Loss)
	}
}

func reachState(status, raw string, loss float64) string {
	if strings.Contains(raw, "reset") {
		return "reset"
	}
	if status == "failed" || loss >= 100 || (loss > 1 && loss >= 99) {
		return "timeout"
	}
	if loss > 1 {
		loss = loss / 100
	}
	if loss >= 1 {
		return "timeout"
	}
	if loss >= 0.2 {
		return "loss"
	}
	if status == "finished" || status == "" {
		return "ok"
	}
	return "timeout"
}

func sniState(status, raw string, code int) string {
	if strings.Contains(raw, "reset") {
		return "reset"
	}
	if status == "failed" {
		return "timeout"
	}
	if code > 0 || status == "finished" {
		return "ok"
	}
	return "timeout"
}

func truncate(b []byte) string {
	if len(b) > 200 {
		return string(b[:200])
	}
	return string(b)
}
