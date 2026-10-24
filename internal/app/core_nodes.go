package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
}

// CoreNodeObservation contains no source identity or credential-bearing metadata.
// Index is 1-based and follows the original document sequence, never map order.
type CoreNodeObservation struct {
	Index    int           `json:"index"`
	Backend  nodes.Backend `json:"backend,omitempty"`
	EgressIP string        `json:"egress_ip,omitempty"`
	Status   string        `json:"status"`
	Reason   string        `json:"reason,omitempty"`
}

// CoreNodes is explicit opt-in exit-IP observation, not Nodes' default checker.
// Even a complete observation is not a reachability/purity/unlock/safety verdict.
func (s *Service) CoreNodes(ctx context.Context, source string, opts CoreNodeOptions) (Report, error) {
	return s.coreNodes(ctx, source, opts, coreProbeTarget{url: coreEgressURL})
}

// Tests may inject a loopback HTTPS URL and its trust root only at this unexported
// function boundary. There is no env, flag, service field or public URL/CA option.
type coreProbeTarget struct {
	url   string
	roots *x509.CertPool
}

func (s *Service) coreNodes(ctx context.Context, source string, opts CoreNodeOptions, target coreProbeTarget) (report Report, err error) {
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
	// snapshot; never use compatibility Parse/Run or serialize source credentials.
	var doc struct {
		Proxies []struct {
			Name string `yaml:"name"`
		} `yaml:"proxies"`
		Outbounds []struct {
			Tag string `yaml:"tag"`
		} `yaml:"outbounds"`
	}
	if yaml.Unmarshal(data, &doc) != nil {
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
				ip, e := queryCoreEgress(ctx, ep.HTTP, target, gate)
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
	if err := gate(); err != nil {
		return "", err
	}
	proxy, err := url.Parse(endpoint)
	if err != nil || proxy.User == nil || proxy.User.Username() == "" || proxy.Hostname() != "127.0.0.1" || proxy.Port() == "" || proxy.Path != "" || proxy.RawQuery != "" || proxy.Fragment != "" || (proxy.Scheme != "http" && proxy.Scheme != "socks5") {
		return "", ErrNodeMeasurementUnavailable
	}
	if pw, ok := proxy.User.Password(); !ok || pw == "" {
		return "", ErrNodeMeasurementUnavailable
	}
	u, err := url.Parse(target.url)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return "", ErrNodeMeasurementUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, coreProbeBudget)
	defer cancel()
	dialer := &net.Dialer{Timeout: coreProbeBudget}
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxy), DisableKeepAlives: true, DisableCompression: true,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: target.roots},
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
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: coreProbeBudget, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.url, nil)
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
	ip, err := netip.ParseAddr(strings.TrimSpace(string(b)))
	if err != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return "", ErrNodeMeasurementUnavailable
	}
	return ip.Unmap().String(), nil
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
			rows[i].Status = "unknown"
			rows[i].Reason = reason
		}
	}
	if rows == nil {
		rows = []CoreNodeObservation{}
	}
	return Report{Verdict: "abstain", Summary: fmt.Sprintf("%d node egress observations; %s (no purity or unlock assessment)", len(rows), status), Data: map[string]any{"nodes": rows, "measurement_status": status, "measurement_reason": reason}, Sources: []Source{{ID: "node_egress"}}, CachedAt: s.now()}
}
