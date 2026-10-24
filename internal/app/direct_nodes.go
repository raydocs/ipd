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
	"strconv"
	"strings"
	"sync"
	"time"

	"ipd/internal/nodes"

	"gopkg.in/yaml.v3"
)

const (
	directNodeEndpoint     = "https://api64.ipify.org?format=json"
	directNodeLimit        = 32
	directNodeConcurrency  = 4
	directNodeTimeout      = 8 * time.Second
	directNodeBatchTimeout = 45 * time.Second
	directNodeSourceLimit  = 2 << 20
)

// directNodeOptions is deliberately internal: no CLI/config URL or TLS bypass.
type directNodeOptions struct {
	endpoint string
	roots    *x509.CertPool
}

// directNodeObservation identifies the input position, never a credential-bearing
// name/server/Extra. Unknown results are not evidence that a node is dead.
type directNodeObservation struct {
	Index    int        `json:"index"`
	Status   string     `json:"status"`
	EgressIP string     `json:"egress_ip,omitempty"`
	At       *time.Time `json:"at,omitempty"`
	Error    string     `json:"error,omitempty"`
}

// MeasureDirectNodes is the CLI-only opt-in path. It neither calls Nodes nor
// starts a runner, fetches a subscription, scores, renames, or exports config.
func (s *Service) MeasureDirectNodes(ctx context.Context, source string) (Report, error) {
	return s.measureDirectNodes(ctx, source, directNodeOptions{})
}

func readDirectNodeSource(source string) (string, error) {
	source = strings.TrimSpace(source)
	// Inline Clash YAML only. URI subscriptions are intentionally not supported:
	// the legacy URI parser does not preserve per-node authentication.
	if !strings.Contains(source, "proxies:") && !strings.Contains(source, "\n") {
		if strings.Contains(source, "://") {
			return "", errors.New("measurement requires local Clash YAML; remote sources are refused")
		}
		info, err := os.Stat(source)
		if err != nil || !info.Mode().IsRegular() {
			return "", errors.New("measurement requires a regular local file")
		}
		f, err := os.Open(source)
		if err != nil {
			return "", errors.New("could not read local node configuration")
		}
		defer f.Close()
		b, err := io.ReadAll(io.LimitReader(f, directNodeSourceLimit+1))
		if err != nil || len(b) > directNodeSourceLimit {
			return "", errors.New("local node configuration is unreadable or too large")
		}
		source = string(b)
	}
	if len(source) > directNodeSourceLimit || !strings.Contains(source, "proxies:") {
		return "", errors.New("measurement requires bounded local Clash YAML")
	}
	return source, nil
}

// Only this closed subset is implemented. Unknown keys (including arbitrary
// metadata) are unsupported configuration, not inferred transport instructions.
// In particular, node/global interface binding, chaining, resolver selection,
// routing marks, IP-family policy, custom TLS and transports cannot be ignored.
func directNodeFieldSupported(key string) bool {
	switch key {
	case "name", "type", "server", "port", "username", "password", "tls", "skip-cert-verify":
		return true
	default:
		return false
	}
}

type directNodeFile struct {
	Proxies     []nodes.Proxy
	unsupported bool
}

var errDirectNodeConfiguration = errors.New("invalid local node configuration; no requests sent")

// Check the representation tree before map decoding can erase duplicate keys,
// expand merges, or resolve aliases. All aliases (including values) and merge
// keys are refused; never follow Alias pointers, so cycles cannot bypass this
// check. Apply the same rules inside unsupported fields, not just known nodes.
func validDirectNodeYAML(n *yaml.Node) bool {
	switch n.Kind {
	case yaml.DocumentNode:
		return len(n.Content) == 1 && validDirectNodeYAML(n.Content[0])
	case yaml.MappingNode:
		if n.Tag != "!!map" || len(n.Content)%2 != 0 {
			return false
		}
		seen := make(map[string]bool, len(n.Content)/2)
		for i := 0; i < len(n.Content); i += 2 {
			key := n.Content[i]
			// Value is already unquoted/unescaped. Tags and spelling must not
			// create distinct keys that later decode to the same Go string.
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Value == "<<" || seen[key.Value] {
				return false
			}
			seen[key.Value] = true
			if !validDirectNodeYAML(n.Content[i+1]) {
				return false
			}
		}
		return true
	case yaml.SequenceNode:
		if n.Tag != "!!seq" {
			return false
		}
		for _, child := range n.Content {
			if !validDirectNodeYAML(child) {
				return false
			}
		}
		return true
	case yaml.ScalarNode:
		switch n.Tag {
		case "!!str", "!!bool", "!!int", "!!float", "!!null":
			return true
		}
	}
	return false
}

// Parse separately from nodes.Parse: that compatibility parser skips malformed
// items and coerces bad fields. Here every original position must survive, or
// the entire document fails before even its first valid node is scheduled.
func parseDirectNodeFile(text string) (directNodeFile, error) {
	var rawDoc yaml.Node
	decoder := yaml.NewDecoder(strings.NewReader(text))
	if decoder.Decode(&rawDoc) != nil || !validDirectNodeYAML(&rawDoc) {
		return directNodeFile{}, errDirectNodeConfiguration
	}
	var extra yaml.Node
	if decoder.Decode(&extra) != io.EOF {
		return directNodeFile{}, errDirectNodeConfiguration
	}
	var doc map[string]any
	if rawDoc.Decode(&doc) != nil {
		return directNodeFile{}, errDirectNodeConfiguration
	}
	raw, ok := doc["proxies"].([]any)
	if !ok || len(raw) == 0 {
		return directNodeFile{}, errDirectNodeConfiguration
	}
	if len(raw) > directNodeLimit {
		return directNodeFile{}, fmt.Errorf("node measurement limit is %d; no requests sent", directNodeLimit)
	}
	f := directNodeFile{Proxies: make([]nodes.Proxy, len(raw))}
	// No inherited global behavior is implemented. Even unfamiliar metadata is
	// rejected conservatively; do not guess whether a future key affects dialing.
	for key := range doc {
		if key != "proxies" {
			f.unsupported = true
		}
	}
	for i, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			return directNodeFile{}, errDirectNodeConfiguration
		}
		p := nodes.Proxy{Extra: m}
		for key, dst := range map[string]*string{"name": &p.Name, "type": &p.Type, "server": &p.Server} {
			value, ok := m[key].(string)
			if !ok || strings.TrimSpace(value) == "" {
				return directNodeFile{}, errDirectNodeConfiguration
			}
			*dst = value
		}
		port, ok := m["port"].(int)
		if !ok || port < 1 || port > 65535 || strings.TrimSpace(p.Server) != p.Server || strings.ContainsAny(p.Server, " /@?#\\\r\n\t") {
			return directNodeFile{}, errDirectNodeConfiguration
		}
		p.Port = port
		for _, key := range []string{"username", "password"} {
			if value, exists := m[key]; exists {
				if _, ok := value.(string); !ok {
					return directNodeFile{}, errDirectNodeConfiguration
				}
			}
		}
		for _, key := range []string{"tls", "skip-cert-verify"} {
			if value, exists := m[key]; exists {
				if _, ok := value.(bool); !ok {
					return directNodeFile{}, errDirectNodeConfiguration
				}
			}
		}
		f.Proxies[i] = p
	}
	return f, nil
}

func (s *Service) measureDirectNodes(ctx context.Context, source string, opts directNodeOptions) (Report, error) {
	ctx, cancel := context.WithTimeout(ctx, directNodeBatchTimeout)
	defer cancel()
	text, err := readDirectNodeSource(source)
	if err != nil {
		return Report{}, err
	}
	f, err := parseDirectNodeFile(text)
	if err != nil {
		return Report{}, err
	}
	out := make([]directNodeObservation, len(f.Proxies))
	offline := s.Cfg != nil && s.Cfg.Offline
	for i := range out {
		out[i] = directNodeObservation{Index: i + 1, Status: "unknown", Error: "canceled"}
	}
	if offline {
		for i := range out {
			out[i].Status = "skipped"
			out[i].Error = "offline"
		}
	} else if f.unsupported {
		for i := range out {
			out[i].Status, out[i].Error = "unsupported", "unsupported"
		}
	} else {
		// A fixed worker pool bounds both requests and goroutines. Each worker owns
		// its slice slot; cancellation stops scheduling and all workers join.
		jobs := make(chan int)
		var wg sync.WaitGroup
		for n := 0; n < directNodeConcurrency; n++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range jobs {
					out[i] = measureDirectNode(ctx, i+1, f.Proxies[i], opts)
				}
			}()
		}
	schedule:
		for i := range f.Proxies {
			select {
			case <-ctx.Done():
				break schedule
			case jobs <- i:
			}
		}
		close(jobs)
		wg.Wait()
		if ctx.Err() == context.DeadlineExceeded {
			for i := range out {
				if out[i].Error == "canceled" {
					out[i].Error = "timeout"
				}
			}
		}
	}
	measured := 0
	for _, o := range out {
		if o.Status == "measured" {
			measured++
		}
	}
	verdict, status, reason := "abstain", "unavailable", "no_observation"
	if measured > 0 {
		verdict, status, reason = "ok_with_caveats", "partial", "incomplete"
	}
	if measured == len(out) && measured > 0 {
		verdict, status, reason = "ok", "completed", ""
	}
	if offline {
		reason = "offline"
	}
	sources := []Source{{ID: "local"}}
	for _, o := range out {
		if o.At != nil {
			sources = append(sources, Source{ID: "ipify"})
			break
		}
	}
	return Report{
		Verdict: verdict,
		Summary: fmt.Sprintf("%d/%d nodes observed; exit IP only, not a reachability or quality verdict", measured, len(out)),
		Data:    map[string]any{"nodes": out, "count": len(out), "measured_count": measured, "measurement_status": status, "measurement_reason": reason, "scope": "proxy_exit_ip_only"},
		Sources: sources, CachedAt: s.now(),
	}, nil
}

func directProxyURL(p nodes.Proxy) (*url.URL, string) {
	for key := range p.Extra {
		if !directNodeFieldSupported(key) {
			return nil, "unsupported"
		}
	}
	scheme := strings.ToLower(p.Type)
	if scheme != "http" && scheme != "socks5" {
		return nil, "unsupported"
	}
	if p.Server == "" || strings.TrimSpace(p.Server) != p.Server || strings.ContainsAny(p.Server, "/@?#\\\r\n\t") || p.Port < 1 || p.Port > 65535 {
		return nil, "invalid_config"
	}
	// Never honor an insecure TLS flag, even if the endpoint is otherwise HTTPS.
	if v, ok := p.Extra["skip-cert-verify"]; ok && v != false {
		return nil, "invalid_config"
	}
	if v, ok := p.Extra["tls"]; ok && v != false {
		if v != true || scheme != "http" {
			return nil, "unsupported"
		}
		scheme = "https"
	}
	u := &url.URL{Scheme: scheme, Host: net.JoinHostPort(p.Server, strconv.Itoa(p.Port))}
	username, password := "", ""
	for key, dst := range map[string]*string{"username": &username, "password": &password} {
		if v, ok := p.Extra[key]; ok {
			value, ok := v.(string)
			if !ok {
				return nil, "invalid_config"
			}
			*dst = value
		}
	}
	if scheme == "socks5" && (len(username) > 255 || len(password) > 255 || (username == "" && password != "")) {
		return nil, "invalid_config"
	}
	if username != "" || password != "" {
		u.User = url.UserPassword(username, password)
	}
	return u, ""
}

func measureDirectNode(ctx context.Context, index int, p nodes.Proxy, opts directNodeOptions) directNodeObservation {
	o := directNodeObservation{Index: index, Status: "unknown"}
	fail := func(reason string) directNodeObservation { o.Error = reason; return o }
	u, reason := directProxyURL(p)
	if reason != "" {
		if reason == "unsupported" {
			o.Status = "unsupported"
		}
		return fail(reason)
	}
	if ctx.Err() != nil {
		return fail(directNodeError(ctx, nil))
	}
	timeout := directNodeTimeout
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	endpoint := directNodeEndpoint
	if opts.endpoint != "" {
		endpoint = opts.endpoint
	}
	// New transport per input slot: no environment proxy, shared connections,
	// global client, direct fallback, redirect, cookies, or original config data.
	tr := &http.Transport{
		Proxy:             http.ProxyURL(u),
		DialContext:       (&net.Dialer{Timeout: timeout}).DialContext,
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: opts.roots},
		DisableKeepAlives: true, DisableCompression: true,
		MaxResponseHeaderBytes: 8192,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil || req.URL.Scheme != "https" {
		return fail("invalid_endpoint")
	}
	req.Header.Set("Accept", "application/json")
	at := time.Now().UTC()
	o.At = &at
	res, err := client.Do(req)
	if err != nil {
		return fail(directNodeError(ctx, err))
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fail("endpoint_status")
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 1025))
	if err != nil {
		return fail(directNodeError(ctx, err))
	}
	if len(body) > 1024 {
		return fail("invalid_response")
	}
	var payload struct {
		IP string `json:"ip"`
	}
	if json.Unmarshal(body, &payload) != nil {
		return fail("invalid_response")
	}
	addr, err := netip.ParseAddr(payload.IP)
	if err != nil || addr.Zone() != "" {
		return fail("invalid_response")
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return fail("invalid_response")
	}
	o.Status, o.EgressIP = "measured", addr.String()
	return o
}

func directNodeError(ctx context.Context, err error) string {
	switch ctx.Err() {
	case context.Canceled:
		return "canceled"
	case context.DeadlineExceeded:
		return "timeout"
	default:
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return "timeout"
		}
		return "request_failed"
	}
}
