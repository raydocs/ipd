package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/url"
	"sync"
)

// One client and connection registry per node. Each GET gets an unpooled
// transport so its dial checks retain THAT request's earliest deadline, even
// when net/http detaches a speculative dial context from request cancellation.
func newCoreHTTPClient(ctx context.Context, endpoint string, roots *x509.CertPool, gate coreGate, state func() error) (*http.Client, func(), error) {
	if err := gate(ctx); err != nil {
		return nil, nil, err
	}
	proxy, err := url.Parse(endpoint)
	if err != nil || proxy.User == nil || proxy.User.Username() == "" || proxy.Hostname() != "127.0.0.1" || proxy.Port() == "" || proxy.Path != "" || proxy.RawQuery != "" || proxy.Fragment != "" || (proxy.Scheme != "http" && proxy.Scheme != "socks5") {
		return nil, nil, ErrNodeMeasurementUnavailable
	}
	if pw, ok := proxy.User.Password(); !ok || pw == "" {
		return nil, nil, ErrNodeMeasurementUnavailable
	}
	connections := &coreConnectionSet{active: make(map[*coreTrackedConn]struct{})}
	stop := context.AfterFunc(ctx, connections.closeAll)
	rt := &coreHTTPRoundTripper{proxy: proxy, roots: roots, gate: gate, state: state, connections: connections, ctx: ctx}
	client := &http.Client{Transport: rt, Timeout: coreProbeBudget, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return client, func() { stop(); connections.closeAll() }, nil
}

type coreHTTPRoundTripper struct {
	proxy       *url.URL
	roots       *x509.CertPool
	gate        coreGate
	state       func() error
	connections *coreConnectionSet
	ctx         context.Context
}

func (t *coreHTTPRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.gate(req.Context()); err != nil {
		return nil, err
	}
	if err := t.ctx.Err(); err != nil {
		return nil, err
	}
	transport := &http.Transport{
		Proxy: http.ProxyURL(t.proxy), DisableKeepAlives: true, DisableCompression: true,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: t.roots},
		TLSHandshakeTimeout: coreProbeBudget, ResponseHeaderTimeout: coreProbeBudget,
		MaxResponseHeaderBytes: 8192, MaxConnsPerHost: 1,
	}
	transport.DialContext = func(dialCtx context.Context, network, addr string) (net.Conn, error) {
		// Inherit the actual request deadline; also honor transport/node cancellation.
		ctx, cancel := context.WithCancel(req.Context())
		stopDial := context.AfterFunc(dialCtx, cancel)
		stopNode := context.AfterFunc(t.ctx, cancel)
		defer func() { stopDial(); stopNode(); cancel() }()
		if err := t.gate(ctx); err != nil {
			return nil, err
		}
		if addr != t.proxy.Host {
			return nil, ErrNodeMeasurementUnavailable
		}
		raw, err := (&net.Dialer{Timeout: coreProbeBudget}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		conn := &coreTrackedConn{Conn: raw, owner: t.connections, ctx: req.Context(), state: t.state}
		if !t.connections.add(conn) {
			raw.Close()
			return nil, ErrNodeMeasurementUnavailable
		}
		// Before returning a socket on which net/http may write proxy credentials,
		// establish fresh ownership again. Never authenticate to a known-lost owner.
		if err := t.gate(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		if err := conn.usable(); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}
	defer transport.CloseIdleConnections()
	resp, err := transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if err := t.gate(req.Context()); err != nil {
		resp.Body.Close()
		return nil, err
	}
	return resp, nil
}

type coreConnectionSet struct {
	mu     sync.Mutex
	closed bool
	active map[*coreTrackedConn]struct{}
}

func (s *coreConnectionSet) add(c *coreTrackedConn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.active[c] = struct{}{}
	return true
}
func (s *coreConnectionSet) closeAll() {
	s.mu.Lock()
	s.closed = true
	active := make([]*coreTrackedConn, 0, len(s.active))
	for c := range s.active {
		active = append(active, c)
	}
	s.mu.Unlock()
	for _, c := range active {
		c.Close()
	}
}

type coreTrackedConn struct {
	net.Conn
	owner *coreConnectionSet
	ctx   context.Context
	state func() error
	once  sync.Once
}

func (c *coreTrackedConn) usable() error {
	if err := c.ctx.Err(); err != nil {
		return err
	}
	if c.state != nil {
		return c.state()
	}
	return nil
}
func (c *coreTrackedConn) Write(b []byte) (int, error) {
	// Synchronous state check also covers Done closing before its cancellation
	// callback has been scheduled. It is NOT atomic receiver authentication.
	if err := c.usable(); err != nil {
		c.Close()
		return 0, err
	}
	return c.Conn.Write(b)
}
func (c *coreTrackedConn) Close() error {
	var err error
	c.once.Do(func() { err = c.Conn.Close(); c.owner.mu.Lock(); delete(c.owner.active, c); c.owner.mu.Unlock() })
	return err
}
