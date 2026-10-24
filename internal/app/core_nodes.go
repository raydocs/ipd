package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
	"ipd/internal/nodes"
)

const (
	coreSourceLimit = 4 << 20
	coreBatchBudget = 45 * time.Second
	coreProbeBudget = 5 * time.Second
	coreEgressURL   = "https://api.ipify.org"
)

var (
	ErrCoreNodesInput       = errors.New("invalid local native node document")
	ErrCoreNodesUnsupported = errors.New("unsupported node document or backend")
	ErrCoreNodesExecutable  = errors.New("explicit absolute core executable required")
)

// CoreNodeOptions is CLI invocation state, deliberately not process-wide config.
// Neither the HTTP nor MCP surface accepts it. Executables are trusted local code.
type CoreNodeOptions struct {
	Backend    nodes.Backend
	MihomoBin  string
	SingBoxBin string
	UnlockIDs  []string
}

// CoreNodeObservation contains no source identity or credential-bearing metadata.
// Index is 1-based and follows the original document sequence, never map order.
type CoreNodeObservation struct {
	Index    int                         `json:"index"`
	Backend  nodes.Backend               `json:"backend,omitempty"`
	EgressIP string                      `json:"egress_ip,omitempty"`
	Status   string                      `json:"status"`
	Reason   string                      `json:"reason,omitempty"`
	Unlock   []CoreNodeUnlockObservation `json:"unlock,omitempty"`
}

// CoreNodes is explicit opt-in observation, not Nodes' default checker.
// UnlockIDs adds service markers, never a purity or account-safety verdict.
func (s *Service) CoreNodes(ctx context.Context, source string, opts CoreNodeOptions) (Report, error) {
	return s.coreNodes(ctx, source, opts, coreProbeTarget{url: coreEgressURL})
}

// Tests may inject a loopback HTTPS URL and its trust root only at this unexported
// function boundary. There is no env, flag, service field or public URL/CA option.
type coreProbeTarget struct {
	url       string
	roots     *x509.CertPool
	unlockURL func(string) string // test-only mapping at this unexported boundary
}

func (s *Service) coreNodes(ctx context.Context, source string, opts CoreNodeOptions, target coreProbeTarget) (report Report, err error) {
	if err := validateCoreUnlockIDs(opts.UnlockIDs); err != nil {
		return Report{}, err
	}
	opts.UnlockIDs = append([]string(nil), opts.UnlockIDs...)
	if s.Cfg.Offline {
		return s.coreNodeReport(nil, "unavailable", "offline"), nil
	}
	ctx, cancel := context.WithTimeout(ctx, coreBatchBudget)
	defer cancel()
	if ctx.Err() != nil {
		return s.coreNodeReport(nil, "unavailable", coreNodeReason(ctx.Err())), nil
	}
	data, err := readCoreSource(source)
	if err != nil {
		return Report{}, ErrCoreNodesInput
	}
	backend, err := nodes.SelectBackend(data, opts.Backend)
	if err != nil {
		if errors.Is(err, nodes.ErrRunnerUnsupported) {
			return Report{}, ErrCoreNodesUnsupported
		}
		return Report{}, ErrCoreNodesInput
	}
	// SelectBackend validated the exact original bytes (including keys, duplicate
	// names, depth, count and types). Decode only ordered names/tags from that same
	// snapshot with the selected native decoder, exactly as the runner does.
	// YAML quoted-line folding is NOT valid JSON string interpretation. Never
	// normalize names, use compatibility Parse/Run or serialize credentials.
	var doc struct {
		Proxies []struct {
			Name string `yaml:"name" json:"name"`
		} `yaml:"proxies" json:"proxies"`
		Outbounds []struct {
			Tag string `yaml:"tag" json:"tag"`
		} `yaml:"outbounds" json:"outbounds"`
	}
	if backend == nodes.BackendSingBox {
		err = json.Unmarshal(data, &doc)
	} else {
		err = yaml.Unmarshal(data, &doc)
	}
	if err != nil {
		return Report{}, ErrCoreNodesInput
	}
	var names []string
	if backend == nodes.BackendMihomo {
		for _, p := range doc.Proxies {
			names = append(names, p.Name)
		}
	} else {
		for _, p := range doc.Outbounds {
			names = append(names, p.Tag)
		}
	}
	if len(names) == 0 || len(names) > 64 {
		return Report{}, ErrCoreNodesInput
	}
	rows := make([]CoreNodeObservation, len(names))
	for i := range rows {
		rows[i] = CoreNodeObservation{Index: i + 1, Backend: backend, Status: "unknown"}
	}
	bins := map[nodes.Backend]string{nodes.BackendMihomo: opts.MihomoBin, nodes.BackendSingBox: opts.SingBoxBin}
	for _, bin := range bins {
		if bin != "" && !filepath.IsAbs(bin) {
			return Report{}, ErrCoreNodesExecutable
		}
	}
	if !filepath.IsAbs(bins[backend]) {
		return Report{}, ErrCoreNodesExecutable
	}
	// A private immutable snapshot prevents path replacement between validation,
	// ordered metadata extraction and runner startup from changing node identity.
	dir, err := os.MkdirTemp("", "ipd-egress-input-")
	if err != nil {
		return s.coreNodeReport(rows, "unavailable", "storage_unavailable"), nil
	}
	defer func() {
		if os.RemoveAll(dir) != nil {
			report = s.coreNodeReport(rows, "unavailable", "cleanup_incomplete")
		}
	}()
	path := filepath.Join(dir, "input")
	if os.WriteFile(path, data, 0600) != nil {
		return s.coreNodeReport(rows, "unavailable", "storage_unavailable"), nil
	}
	runner := &nodes.ExecRunner{Backend: backend, Executables: bins, Budget: coreBatchBudget, StartupTimeout: 10 * time.Second}
	// Defer before Start, including partial startup failures. Stop waits for all
	// children and cleanup. A cleanup failure must never publish observations.
	defer func() {
		prior, interrupted := runner.Err(), ctx.Err()
		runner.Stop()
		terminal := runner.Err()
		switch {
		case errors.Is(terminal, nodes.ErrRunnerCleanup):
			report = s.coreNodeReport(rows, "unavailable", "cleanup_incomplete")
		case prior != nil || errors.Is(terminal, nodes.ErrRunnerExit):
			report = s.coreNodeReport(rows, "unavailable", "core_unavailable")
		case errors.Is(terminal, context.DeadlineExceeded):
			report = s.coreNodeReport(rows, "unavailable", "timeout")
		case interrupted != nil || ctx.Err() != nil:
			if interrupted == nil {
				interrupted = ctx.Err()
			}
			report = s.coreNodeReport(rows, "unavailable", coreNodeReason(interrupted))
		}
	}()
	if _, err = runner.Start(ctx, path); err != nil {
		return s.coreNodeReport(rows, "unavailable", coreNodeReason(err)), nil
	}
	if runner.SelectedBackend() != backend {
		return s.coreNodeReport(rows, "unavailable", "core_unavailable"), nil
	}
	live := func(name string, expected nodes.Endpoint) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := runner.Err(); err != nil {
			return err
		}
		endpoints := runner.Endpoints() // never reuse a startup endpoint snapshot
		ep, ok := endpoints[name]
		if !ok || len(endpoints) != len(names) || ep.Backend != backend || ep != expected {
			return nodes.ErrRunnerExit
		}
		return nil
	}
	// Existing runner API has no revocation channel. Observe its validity gate
	// while requests block; pre-dial/post-read/final gates also check synchronously.
	done := make(chan struct{})
	var monitor sync.WaitGroup
	monitor.Add(1)
	go func() {
		defer monitor.Done()
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if runner.Err() != nil || len(runner.Endpoints()) != len(names) {
					cancel()
					return
				}
			}
		}
	}()
	defer func() { close(done); monitor.Wait() }()
	// Four workers, independent transport/client per node, no shared connections,
	// no retry and a fixed whole-batch budget including startup.
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				ep, ok := runner.Endpoints()[names[i]]
				if !ok {
					rows[i].Reason = "core_unavailable"
					continue
				}
				gate := func() error { return live(names[i], ep) }
				nodeCtx, nodeCancel := context.WithTimeout(ctx, coreNodeBudget)
				client, cleanup, e := coreHTTPClient(ep.HTTP, target.roots, gate)
				if e != nil {
					nodeCancel()
					rows[i].Reason = coreNodeReason(e)
					continue
				}
				ip, e := queryCoreEgressClient(nodeCtx, client, target.url, gate)
				if e == nil && len(opts.UnlockIDs) > 0 {
					rows[i].Unlock, e = queryCoreUnlock(nodeCtx, client, opts.UnlockIDs, target.unlockURL, gate)
					if e != nil {
						cancel()
					}
				}
				if nodeCtx.Err() != nil {
					cancel()
				}
				if liveErr := gate(); liveErr != nil {
					e = liveErr
					cancel()
				}
				cleanup()
				nodeCancel()
				if e != nil {
					rows[i].Reason = coreNodeReason(e)
					continue
				}
				rows[i].EgressIP, rows[i].Status = ip, "observed"
			}
		}()
	}
	for i := range names {
		select {
		case jobs <- i:
		case <-ctx.Done():
		}
	}
	close(jobs)
	wg.Wait()
	reason := ""
	if runner.Err() != nil || len(runner.Endpoints()) != len(names) {
		reason = "core_unavailable"
	} else if ctx.Err() != nil {
		reason = coreNodeReason(ctx.Err())
	}
	for i := range rows {
		if rows[i].Status != "observed" && reason == "" {
			reason = "batch_incomplete"
		}
	}
	if reason != "" {
		return s.coreNodeReport(rows, "unavailable", reason), nil
	}
	return s.coreNodeReport(rows, "completed", ""), nil
}

func readCoreSource(source string) ([]byte, error) {
	if len(source) > coreSourceLimit {
		return nil, ErrCoreNodesInput
	}
	text := strings.TrimSpace(source)
	if strings.HasPrefix(text, "http://") || strings.HasPrefix(text, "https://") {
		return nil, ErrCoreNodesInput
	}
	if strings.Contains(text, "\n") || strings.HasPrefix(text, "{") || strings.HasPrefix(text, "[") || strings.HasPrefix(text, "proxies:") || strings.HasPrefix(text, "---") {
		return []byte(text), nil
	}
	st, err := os.Lstat(source)
	if err != nil || !st.Mode().IsRegular() || st.Size() > coreSourceLimit {
		return nil, ErrCoreNodesInput
	}
	// Nonblocking open also prevents a raced-in FIFO from escaping the budget.
	f, err := os.OpenFile(source, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrCoreNodesInput
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !actual.Mode().IsRegular() || !os.SameFile(st, actual) {
		return nil, ErrCoreNodesInput
	}
	b, err := io.ReadAll(io.LimitReader(f, coreSourceLimit+1))
	if err != nil || len(b) > coreSourceLimit {
		return nil, ErrCoreNodesInput
	}
	return b, nil
}

// queryCoreEgress is the single HTTP observation implementation for both cores.
// It accepts only authenticated loopback runner endpoints, never env proxy or
// DIRECT; all failures are evidence gaps. It does not return raw network errors.
func queryCoreEgress(ctx context.Context, endpoint string, target coreProbeTarget, gate func() error) (string, error) {
	client, cleanup, err := coreHTTPClient(endpoint, target.roots, gate)
	if err != nil {
		return "", err
	}
	defer cleanup()
	return queryCoreEgressClient(ctx, client, target.url, gate)
}

// Shared authenticated loopback client; only the runner proxy may be dialed.
func coreHTTPClient(endpoint string, roots *x509.CertPool, gate func() error) (*http.Client, func(), error) {
	if err := gate(); err != nil {
		return nil, nil, err
	}
	proxy, err := url.Parse(endpoint)
	if err != nil || proxy.User == nil || proxy.User.Username() == "" || proxy.Hostname() != "127.0.0.1" || proxy.Port() == "" || proxy.Path != "" || proxy.RawQuery != "" || proxy.Fragment != "" || (proxy.Scheme != "http" && proxy.Scheme != "socks5") {
		return nil, nil, ErrNodeMeasurementUnavailable
	}
	if pw, ok := proxy.User.Password(); !ok || pw == "" {
		return nil, nil, ErrNodeMeasurementUnavailable
	}
	dialer := &net.Dialer{Timeout: coreProbeBudget}
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxy), DisableKeepAlives: true, DisableCompression: true,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout: coreProbeBudget, ResponseHeaderTimeout: coreProbeBudget,
		MaxResponseHeaderBytes: 8192, MaxConnsPerHost: 1,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if err := gate(); err != nil {
				return nil, err
			}
			// HTTP transport may only dial the selected authenticated local proxy.
			if addr != proxy.Host {
				return nil, ErrNodeMeasurementUnavailable
			}
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if err := gate(); err != nil {
				conn.Close()
				return nil, err
			}
			return conn, nil
		},
	}

	client := &http.Client{Transport: transport, Timeout: coreProbeBudget, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return client, transport.CloseIdleConnections, nil
}

func queryCoreEgressClient(ctx context.Context, client *http.Client, rawURL string, gate func() error) (string, error) {
	if err := gate(); err != nil {
		return "", err
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return "", ErrNodeMeasurementUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, coreProbeBudget)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", ErrNodeMeasurementUnavailable
	}
	req.Header.Set("Accept", "text/plain")
	resp, err := client.Do(req)
	if err != nil {
		if e := ctx.Err(); e != nil {
			return "", e
		}
		return "", ErrNodeMeasurementUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", ErrNodeMeasurementUnavailable
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 257))
	if err != nil || len(b) > 256 {
		return "", ErrNodeMeasurementUnavailable
	}
	if err := gate(); err != nil {
		return "", err
	}
	ip, ok := publicCoreEgressIP(strings.TrimSpace(string(b)))
	if !ok {
		return "", ErrNodeMeasurementUnavailable
	}
	return ip.String(), nil
}

// Conservative ordinary-public-address policy, not evidence of live BGP
// routability. IANA special-purpose IPv4 entries (even special-service anycast),
// multicast and reserved space are excluded. IPv6 must be in a listed IANA RIR
// allocation, excluding the special-purpose subranges inside those allocations.
// Registry snapshot checked 2026-10-24; see docs/CLI_NODE_EGRESS.md for sources.
// Future allocations fail closed until this local policy is reviewed/updated.
var coreNonPublicIPv4 = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

var corePublicIPv6Allocations = [...]netip.Prefix{
	netip.MustParsePrefix("2001:200::/23"),
	netip.MustParsePrefix("2001:400::/23"),
	netip.MustParsePrefix("2001:600::/23"),
	netip.MustParsePrefix("2001:800::/22"),
	netip.MustParsePrefix("2001:c00::/23"),
	netip.MustParsePrefix("2001:e00::/23"),
	netip.MustParsePrefix("2001:1200::/23"),
	netip.MustParsePrefix("2001:1400::/22"),
	netip.MustParsePrefix("2001:1800::/23"),
	netip.MustParsePrefix("2001:1a00::/23"),
	netip.MustParsePrefix("2001:1c00::/22"),
	netip.MustParsePrefix("2001:2000::/19"),
	netip.MustParsePrefix("2001:4000::/23"),
	netip.MustParsePrefix("2001:4200::/23"),
	netip.MustParsePrefix("2001:4400::/23"),
	netip.MustParsePrefix("2001:4600::/23"),
	netip.MustParsePrefix("2001:4800::/23"),
	netip.MustParsePrefix("2001:4a00::/23"),
	netip.MustParsePrefix("2001:4c00::/23"),
	netip.MustParsePrefix("2001:5000::/20"),
	netip.MustParsePrefix("2001:8000::/19"),
	netip.MustParsePrefix("2001:a000::/20"),
	netip.MustParsePrefix("2001:b000::/20"),
	netip.MustParsePrefix("2003::/18"),
	netip.MustParsePrefix("2400::/12"),
	netip.MustParsePrefix("2410::/12"),
	netip.MustParsePrefix("2600::/12"),
	netip.MustParsePrefix("2610::/23"),
	netip.MustParsePrefix("2620::/23"),
	netip.MustParsePrefix("2630::/12"),
	netip.MustParsePrefix("2800::/12"),
	netip.MustParsePrefix("2a00::/12"),
	netip.MustParsePrefix("2a10::/12"),
	netip.MustParsePrefix("2c00::/12"),
}

var coreNonPublicIPv6 = [...]netip.Prefix{
	netip.MustParsePrefix("2001:db8::/32"),     // Documentation inside APNIC allocation.
	netip.MustParsePrefix("2620:4f:8000::/48"), // Special-purpose AS112 service.
}

func publicCoreEgressIP(text string) (netip.Addr, bool) {
	ip, err := netip.ParseAddr(text)
	// Zones are local scope/opaque text, never egress evidence. Check BEFORE
	// Unmap, which discards a mapped IPv6 zone along with its IPv6 representation.
	if err != nil || ip.Zone() != "" {
		return netip.Addr{}, false
	}
	ip = ip.Unmap()
	if ip.Is4() {
		for _, prefix := range coreNonPublicIPv4 {
			if prefix.Contains(ip) {
				return netip.Addr{}, false
			}
		}
		return ip, true
	}
	for _, prefix := range coreNonPublicIPv6 {
		if prefix.Contains(ip) {
			return netip.Addr{}, false
		}
	}
	for _, prefix := range corePublicIPv6Allocations {
		if prefix.Contains(ip) {
			return ip, true
		}
	}
	return netip.Addr{}, false
}

func coreNodeReason(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, nodes.ErrRunnerCleanup):
		return "cleanup_incomplete"
	case errors.Is(err, nodes.ErrRunnerUnsupported):
		return "unsupported"
	case errors.Is(err, nodes.ErrRunnerExecutable):
		return "executable_unavailable"
	case errors.Is(err, nodes.ErrRunnerStorage):
		return "storage_unavailable"
	case errors.Is(err, ErrNodeMeasurementUnavailable):
		return "query_unavailable"
	default:
		return "core_unavailable"
	}
}

func (s *Service) coreNodeReport(rows []CoreNodeObservation, status, reason string) Report {
	// Withhold all successful IPs on partial batches, interruption or core failure.
	if status != "completed" {
		rows = append([]CoreNodeObservation(nil), rows...)
		for i := range rows {
			rows[i].EgressIP = ""
			rows[i].Unlock = nil
			rows[i].Status = "unknown"
			rows[i].Reason = reason
		}
	}
	if rows == nil {
		rows = []CoreNodeObservation{}
	}
	summary := fmt.Sprintf("%d node egress observations; %s (no purity or unlock assessment)", len(rows), status)
	for _, row := range rows {
		if len(row.Unlock) > 0 {
			summary = fmt.Sprintf("%d node observations; %s (no purity, safety, login or playback assessment)", len(rows), status)
			break
		}
	}
	return Report{Verdict: "abstain", Summary: summary, Data: map[string]any{"nodes": rows, "measurement_status": status, "measurement_reason": reason}, Sources: []Source{{ID: "node_egress"}}, CachedAt: s.now()}
}
