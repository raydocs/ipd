package route

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Trace runs a traceroute to target and returns hops.
// It tries a Linux UDP traceroute, then ICMP and TCP when the process may
// open raw sockets, then tracepath or traceroute on PATH. A permission or
// network failure is returned as an error so the caller can abstain.
func Trace(ctx context.Context, target string, maxHops int) ([]Hop, error) {
	if maxHops <= 0 {
		maxHops = 12
	}
	if maxHops > 20 {
		maxHops = 20
	}
	ip, err := resolve4(ctx, target)
	if err != nil {
		return nil, err
	}
	var notes []string
	hops, platErr := platformTrace(ctx, ip, maxHops)
	if platErr != nil {
		notes = append(notes, platErr.Error())
	}
	if realHops(hops) > 0 {
		return hops, nil
	}
	cmdHops, cmdErr := commandTrace(ctx, ip.String(), maxHops)
	if cmdErr != nil {
		notes = append(notes, cmdErr.Error())
	}
	if realHops(cmdHops) > realHops(hops) {
		return cmdHops, nil
	}
	if realHops(hops) > 0 {
		return hops, nil
	}
	if len(notes) == 0 {
		notes = append(notes, "no hops")
	}
	return nil, fmt.Errorf("traceroute unavailable: %s", strings.Join(notes, "; "))
}

func resolve4(ctx context.Context, target string) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(target); err == nil {
		ip = ip.Unmap()
		if !ip.Is4() {
			return netip.Addr{}, fmt.Errorf("traceroute: %s is not ipv4", target)
		}
		return ip, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", target)
	if err != nil || len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("traceroute: resolve %s: %w", target, err)
	}
	return ips[0].Unmap(), nil
}

func realHops(hops []Hop) int {
	n := 0
	for _, h := range hops {
		if h.IP != "" && h.IP != "*" {
			n++
		}
	}
	return n
}

func commandTrace(ctx context.Context, ip string, maxHops int) ([]Hop, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	candidates := [][]string{
		{"tracepath", "-n", "-m", strconv.Itoa(maxHops), ip},
		{"traceroute", "-n", "-m", strconv.Itoa(maxHops), "-w", "1", "-q", "1", ip},
	}
	var last error
	for _, argv := range candidates {
		bin, err := exec.LookPath(argv[0])
		if err != nil {
			last = err
			continue
		}
		cmd := exec.CommandContext(ctx, bin, argv[1:]...)
		out, err := cmd.CombinedOutput()
		hops := ParseTraceOutput(string(out))
		if realHops(hops) > 0 {
			return hops, nil
		}
		if err != nil {
			last = fmt.Errorf("%s: %w", argv[0], err)
			continue
		}
		last = fmt.Errorf("%s returned no hops", argv[0])
	}
	if last == nil {
		last = fmt.Errorf("tracepath and traceroute are not installed")
	}
	return nil, last
}

var (
	tracePathLine  = regexp.MustCompile(`^\s*(\d+)[:?]\s+(\S+)`)
	traceRouteLine = regexp.MustCompile(`^\s*(\d+)\s+(\S+)`)
)

// ParseTraceOutput reads tracepath or traceroute -n text.
func ParseTraceOutput(s string) []Hop {
	var hops []Hop
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.Contains(line, "pmtu") && !strings.Contains(line, "ms") {
			continue
		}
		m := tracePathLine.FindStringSubmatch(line)
		if m == nil {
			m = traceRouteLine.FindStringSubmatch(line)
		}
		if m == nil {
			continue
		}
		host := m[2]
		if host == "[LOCALHOST]" || host == "no" || strings.HasPrefix(host, "[") {
			continue
		}
		if host == "*" {
			hops = append(hops, Hop{IP: "*"})
			continue
		}
		ip := host
		if parsed, err := netip.ParseAddr(host); err != nil || !parsed.Is4() {
			// traceroute may print a hostname when -n was not used. Keep dotted quads only.
			if !strings.Contains(host, ".") {
				continue
			}
		}
		rtt := rttFrom(line)
		hops = append(hops, Hop{IP: ip, RTTMS: rtt})
	}
	return hops
}

func rttFrom(line string) float64 {
	fields := strings.Fields(line)
	for i, f := range fields {
		if strings.HasSuffix(f, "ms") {
			n := strings.TrimSuffix(f, "ms")
			if v, err := strconv.ParseFloat(n, 64); err == nil {
				return v
			}
			if i > 0 {
				if v, err := strconv.ParseFloat(fields[i-1], 64); err == nil {
					return v
				}
			}
		}
	}
	return 0
}
