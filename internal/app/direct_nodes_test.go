package app

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ipd/internal/nodes"
)

func directResults(t *testing.T, rep Report) []directNodeObservation {
	t.Helper()
	return rep.Data.(map[string]any)["nodes"].([]directNodeObservation)
}

func directTLS(t *testing.T, body string, status int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	hits := new(atomic.Int32)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("proxy credentials reached endpoint")
		}
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, hits
}

func directOptions(s *httptest.Server) directNodeOptions {
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	return directNodeOptions{endpoint: s.URL + "?format=json", roots: roots}
}

func directYAML(ps ...nodes.Proxy) string {
	var b strings.Builder
	b.WriteString("proxies:\n")
	for _, p := range ps {
		user, pass := "fixture-user", "fixture-secret-password"
		if p.Type == "socks5" {
			user, pass = "fixture-socks-user", "fixture-secret-socks-password"
		}
		fmt.Fprintf(&b, "- {name: fixture-secret-name, type: %s, server: %s, port: %d, username: %s, password: %s}\n", p.Type, p.Server, p.Port, user, pass)
	}
	return b.String()
}

func proxyEntry(addr, kind string) nodes.Proxy {
	h, p, _ := net.SplitHostPort(addr)
	n, _ := strconv.Atoi(p)
	return nodes.Proxy{Type: kind, Server: h, Port: n}
}

// Only loopback is dialed, regardless of the destination requested by a client.
func directTunnel(a net.Conn, reader io.Reader, target string) {
	b, err := net.Dial("tcp", target)
	if err != nil {
		return
	}
	defer b.Close()
	done := make(chan struct{})
	go func() { io.Copy(b, reader); b.Close(); close(done) }()
	io.Copy(a, b)
	a.Close()
	<-done
}

func directHTTPProxy(t *testing.T, target, expectedHost string, auth bool, accepted ...*atomic.Int32) (nodes.Proxy, *atomic.Int32) {
	t.Helper()
	hits := new(atomic.Int32)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte("fixture-user:fixture-secret-password"))
		if r.Method != "CONNECT" || r.Host != expectedHost || (auth && r.Header.Get("Proxy-Authorization") != want) {
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		c, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
		directTunnel(c, rw, target)
	}))
	if len(accepted) > 0 {
		srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
			if state == http.StateNew {
				accepted[0].Add(1)
			}
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return proxyEntry(u.Host, "http"), hits
}

// Minimal RFC1928/1929 fixture with connection tracking and a joined shutdown.
func directSOCKSProxy(t *testing.T, target, expectedHost string, stall bool) (nodes.Proxy, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hits, active := new(atomic.Int32), new(atomic.Int32)
	var conns sync.Map
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Store(c, true)
			wg.Add(1)
			active.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				defer conns.Delete(c)
				defer active.Add(-1)
				c.SetDeadline(time.Now().Add(5 * time.Second))
				hits.Add(1)
				if stall {
					io.Copy(io.Discard, c)
					return
				}
				r := bufio.NewReader(c)
				head := make([]byte, 2)
				if _, err := io.ReadFull(r, head); err != nil || head[0] != 5 {
					return
				}
				methods := make([]byte, int(head[1]))
				if _, err := io.ReadFull(r, methods); err != nil {
					return
				}
				hasAuth := false
				for _, m := range methods {
					if m == 2 {
						hasAuth = true
					}
				}
				if !hasAuth {
					c.Write([]byte{5, 255})
					return
				}
				c.Write([]byte{5, 2})
				readText := func() string {
					n, e := r.ReadByte()
					if e != nil {
						return ""
					}
					b := make([]byte, int(n))
					io.ReadFull(r, b)
					return string(b)
				}
				v, err := r.ReadByte()
				if err != nil || v != 1 {
					return
				}
				user, pass := readText(), readText()
				if user != "fixture-socks-user" || pass != "fixture-secret-socks-password" {
					c.Write([]byte{1, 1})
					return
				}
				c.Write([]byte{1, 0})
				h := make([]byte, 4)
				if _, err := io.ReadFull(r, h); err != nil || h[0] != 5 || h[1] != 1 {
					return
				}
				host := ""
				switch h[3] {
				case 1:
					b := make([]byte, 4)
					io.ReadFull(r, b)
					host = net.IP(b).String()
				case 4:
					b := make([]byte, 16)
					io.ReadFull(r, b)
					host = net.IP(b).String()
				case 3:
					host = readText()
				default:
					return
				}
				port := make([]byte, 2)
				if _, err := io.ReadFull(r, port); err != nil {
					return
				}
				requested := net.JoinHostPort(host, strconv.Itoa(int(port[0])<<8|int(port[1])))
				if requested != expectedHost {
					c.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				directTunnel(c, r, target)
			}()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		<-done
		conns.Range(func(k, v any) bool { k.(net.Conn).Close(); return true })
		wg.Wait()
	})
	return proxyEntry(ln.Addr().String(), "socks5"), hits, active
}

func TestDirectNodesDistinctExitsAndNoCredentialExport(t *testing.T) {
	first, h1 := directTLS(t, `{"ip":"192.0.2.10"}`, 200)
	second, h2 := directTLS(t, `{"ip":"2001:db8::20"}`, 200)
	opts := directOptions(first)
	roots := opts.roots
	roots.AddCert(second.Certificate())
	u, _ := url.Parse(first.URL)
	a, pa := directHTTPProxy(t, first.Listener.Addr().String(), u.Host, true)
	b, pb, _ := directSOCKSProxy(t, second.Listener.Addr().String(), u.Host, false)
	// Both proxies receive the exact same endpoint; only the per-node tunnel differs.
	rep, err := nodeService().measureDirectNodes(context.Background(), directYAML(a, b), opts)
	if err != nil {
		t.Fatal(err)
	}
	out := directResults(t, rep)
	if rep.Verdict != "ok" || out[0].EgressIP != "192.0.2.10" || out[1].EgressIP != "2001:db8::20" || out[0].Index != 1 || out[1].Index != 2 || out[0].At == nil || out[1].At == nil {
		t.Fatalf("incorrect observations: %+v", rep)
	}
	if h1.Load() != 1 || h2.Load() != 1 || pa.Load() != 1 || pb.Load() != 1 {
		t.Fatal("did not use distinct authenticated tunnels")
	}
	blob, _ := json.Marshal(rep)
	for _, secret := range []string{"fixture-secret", "fixture-user", "password", "username", "server", "renamed_yaml", "grade", "tiktok", "residential", "Extra"} {
		if strings.Contains(string(blob), secret) {
			t.Errorf("unsafe/fabricated field %q: %s", secret, blob)
		}
	}
}

func TestDirectNodesEnvironmentAndNoFallback(t *testing.T) {
	endpoint, hits := directTLS(t, `{"ip":"192.0.2.30"}`, 200)
	u, _ := url.Parse(endpoint.URL)
	good, proxyHits := directHTTPProxy(t, endpoint.Listener.Addr().String(), u.Host, true)
	trap, envHits := directHTTPProxy(t, endpoint.Listener.Addr().String(), u.Host, false)
	trapURL := "http://" + net.JoinHostPort(trap.Server, strconv.Itoa(trap.Port))
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(key, trapURL)
	}
	for _, key := range []string{"NO_PROXY", "no_proxy"} {
		t.Setenv(key, "*")
	}
	rep, err := nodeService().measureDirectNodes(context.Background(), directYAML(good), directOptions(endpoint))
	if err != nil || rep.Verdict != "ok" || proxyHits.Load() != 1 || envHits.Load() != 0 {
		t.Fatalf("environment affected tunnel: %+v %v", rep, err)
	}
	// Wrong authentication on each protocol must not fall back to the directly reachable endpoint.
	socks, _, _ := directSOCKSProxy(t, endpoint.Listener.Addr().String(), u.Host, false)
	for _, p := range []nodes.Proxy{good, socks} {
		text := strings.ReplaceAll(directYAML(p), "fixture-secret-password", "fixture-wrong-password")
		text = strings.ReplaceAll(text, "fixture-secret-socks-password", "fixture-wrong-password")
		rep, err = nodeService().measureDirectNodes(context.Background(), text, directOptions(endpoint))
		if err != nil {
			t.Fatal(err)
		}
		o := directResults(t, rep)[0]
		if rep.Verdict != "abstain" || o.Status != "unknown" || o.EgressIP != "" || o.Error != "request_failed" {
			t.Fatalf("authentication failure fabricated evidence: %+v", rep)
		}
	}
	if hits.Load() != 1 || envHits.Load() != 0 {
		t.Fatal("failed proxy fell back direct/environment")
	}
}

func TestDirectNodesUnknownResponsesAndTLS(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"html", "<html>192.0.2.40</html>", 200}, {"empty_json", "{}", 200}, {"invalid_ip", `{"ip":"not-an-ip"}`, 200},
		{"empty", "", 200}, {"endpoint_failed", `{"ip":"192.0.2.40"}`, 503}, {"redirect", "", 302},
		{"large", strings.Repeat(" ", 1025) + `{"ip":"192.0.2.40"}`, 200},
		{"trailing", `{"ip":"192.0.2.40"} {}`, 200}, {"unspecified", `{"ip":"0.0.0.0"}`, 200},
		{"mapped_unspecified", `{"ip":"::ffff:0.0.0.0"}`, 200},
		{"loopback", `{"ip":"127.0.0.1"}`, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, hits := directTLS(t, tc.body, tc.status)
			u, _ := url.Parse(srv.URL)
			p, _ := directHTTPProxy(t, srv.Listener.Addr().String(), u.Host, true)
			rep, err := nodeService().measureDirectNodes(context.Background(), directYAML(p), directOptions(srv))
			if err != nil {
				t.Fatal(err)
			}
			if rep.Verdict != "abstain" || directResults(t, rep)[0].Status != "unknown" || hits.Load() != 1 {
				t.Fatalf("invalid response treated as evidence: %+v", rep)
			}
		})
	}
	srv, hits := directTLS(t, `{"ip":"192.0.2.40"}`, 200)
	u, _ := url.Parse(srv.URL)
	p, _ := directHTTPProxy(t, srv.Listener.Addr().String(), u.Host, true)
	opts := directOptions(srv)
	opts.roots = nil
	rep, err := nodeService().measureDirectNodes(context.Background(), directYAML(p), opts)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verdict != "abstain" || hits.Load() != 0 {
		t.Fatal("untrusted TLS accepted")
	}
}

func TestDirectNodesMixedUnsupportedOfflineCapAndSources(t *testing.T) {
	srv, hits := directTLS(t, `{"ip":"192.0.2.50"}`, 200)
	u, _ := url.Parse(srv.URL)
	good, _ := directHTTPProxy(t, srv.Listener.Addr().String(), u.Host, true)
	unsupported := nodes.Proxy{Type: "ss", Server: "127.0.0.1", Port: 1}
	text := directYAML(good, unsupported)
	rep, err := nodeService().measureDirectNodes(context.Background(), text, directOptions(srv))
	if err != nil {
		t.Fatal(err)
	}
	out := directResults(t, rep)
	if rep.Verdict != "ok_with_caveats" || out[0].EgressIP != "192.0.2.50" || out[1].Status != "unsupported" || out[1].At != nil {
		t.Fatalf("partial evidence lost: %+v", rep)
	}
	s := nodeService()
	s.Cfg.Offline = true
	rep, err = s.measureDirectNodes(context.Background(), text, directOptions(srv))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verdict != "abstain" || directResults(t, rep)[0].Error != "offline" || hits.Load() != 1 {
		t.Fatal("offline sent traffic")
	}
	for _, kind := range []string{"ss", "vmess", "unknown"} {
		rep, err = nodeService().MeasureDirectNodes(context.Background(), directYAML(nodes.Proxy{Type: kind, Server: "127.0.0.1", Port: 1}))
		if err != nil {
			t.Fatal(err)
		}
		if rep.Verdict != "abstain" || directResults(t, rep)[0].Status != "unsupported" {
			t.Fatalf("unsupported became blocked: %+v", rep)
		}
	}
	many := make([]nodes.Proxy, directNodeLimit+1)
	for i := range many {
		many[i] = good
	}
	if _, err = nodeService().measureDirectNodes(context.Background(), directYAML(many...), directOptions(srv)); err == nil {
		t.Fatal("cap ignored")
	}
	if hits.Load() != 1 {
		t.Fatal("cap sent traffic")
	}
	for _, source := range []string{"http://fixture-user:fixture-secret-password@127.0.0.1:1/config", "https://127.0.0.1:1/config", "socks5://fixture-user:fixture-secret-password@127.0.0.1:1", "proxies: [fixture-secret-password"} {
		_, err = nodeService().MeasureDirectNodes(context.Background(), source)
		if err == nil || strings.Contains(err.Error(), "fixture-") {
			t.Fatalf("unsafe source error: %v", err)
		}
	}
	path := filepath.Join(t.TempDir(), "local.yaml")
	if err = os.WriteFile(path, []byte(directYAML(unsupported)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = nodeService().MeasureDirectNodes(context.Background(), path); err != nil {
		t.Fatal(err)
	}
}

func TestDirectNodesTimeoutAndCancellationJoin(t *testing.T) {
	srv, hits := directTLS(t, `{"ip":"192.0.2.60"}`, 200)
	u, _ := url.Parse(srv.URL)
	p, proxyHits, active := directSOCKSProxy(t, srv.Listener.Addr().String(), u.Host, true)
	opts := directOptions(srv)
	timeoutCtx, timeoutCancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer timeoutCancel()
	start := time.Now()
	rep, err := nodeService().measureDirectNodes(timeoutCtx, directYAML(p), opts)
	if err != nil {
		t.Fatal(err)
	}
	if directResults(t, rep)[0].Error != "timeout" || time.Since(start) > time.Second {
		t.Fatalf("timeout not bounded: %+v", rep)
	}
	deadline := time.Now().Add(time.Second)
	for active.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if active.Load() != 0 || hits.Load() != 0 {
		t.Fatal("timed out handshake connection leaked")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := proxyHits.Load()
	rep, err = nodeService().measureDirectNodes(ctx, directYAML(p), opts)
	if err != nil || directResults(t, rep)[0].Error != "canceled" || proxyHits.Load() != before {
		t.Fatalf("canceled work sent traffic: %+v %v", rep, err)
	}
	// Cancellation while work and queued nodes exist must join all workers.
	ctx, cancel = context.WithCancel(context.Background())
	many := make([]nodes.Proxy, directNodeLimit)
	for i := range many {
		many[i] = p
	}
	finished := make(chan Report, 1)
	go func() {
		r, _ := nodeService().measureDirectNodes(ctx, directYAML(many...), directOptions(srv))
		finished <- r
	}()
	deadline = time.Now().Add(time.Second)
	for active.Load() < directNodeConcurrency && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if active.Load() != directNodeConcurrency {
		cancel()
		t.Fatal("fixed worker pool did not start")
	}
	cancel()
	select {
	case rep = <-finished:
	case <-time.After(time.Second):
		t.Fatal("canceled batch failed to join")
	}
	if rep.Verdict != "abstain" {
		t.Fatal("canceled batch fabricated evidence")
	}
	deadline = time.Now().Add(time.Second)
	for active.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if active.Load() != 0 {
		t.Fatal("canceled SOCKS connection leaked")
	}
}

func TestDirectNodesConcurrencyAndLimitBoundary(t *testing.T) {
	var active, max, hits atomic.Int32
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := active.Add(1)
		defer active.Add(-1)
		hits.Add(1)
		for old := max.Load(); n > old && !max.CompareAndSwap(old, n); old = max.Load() {
		}
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		fmt.Fprint(w, `{"ip":"192.0.2.70"}`)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	p, _ := directHTTPProxy(t, srv.Listener.Addr().String(), u.Host, true)
	many := make([]nodes.Proxy, directNodeLimit)
	for i := range many {
		many[i] = p
	}
	done := make(chan Report, 1)
	go func() {
		r, _ := nodeService().measureDirectNodes(context.Background(), directYAML(many...), directOptions(srv))
		done <- r
	}()
	deadline := time.Now().Add(2 * time.Second)
	for active.Load() < directNodeConcurrency && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	reached := active.Load()
	unblock()
	select {
	case rep := <-done:
		if reached != directNodeConcurrency || max.Load() > directNodeConcurrency || hits.Load() != directNodeLimit || rep.Verdict != "ok" {
			t.Fatalf("unbounded/lost work: reached=%d max=%d hits=%d report=%+v", reached, max.Load(), hits.Load(), rep)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("bounded batch did not finish")
	}
}

func TestDirectNodesInvalidConfigNoRequests(t *testing.T) {
	for _, tc := range []struct {
		extra     string
		malformed bool
	}{{", skip-cert-verify: true", false}, {", username: 123", true}, {", tls: invalid", true}} {
		text := "proxies: [{name: fixture-secret, type: http, server: 127.0.0.1, port: 1" + tc.extra + "}]"
		rep, err := nodeService().MeasureDirectNodes(context.Background(), text)
		if tc.malformed {
			if err == nil {
				t.Fatal("malformed known field accepted")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if rep.Verdict != "abstain" || directResults(t, rep)[0].At != nil {
			t.Fatalf("invalid config attempted: %+v", rep)
		}
	}
}

func TestDirectNodesRefusedRemoteSourceMakesNoRequest(t *testing.T) {
	var hits atomic.Int32
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); fmt.Fprint(w, "proxies: []") }))
	defer remote.Close()
	for _, offline := range []bool{false, true} {
		s := nodeService()
		s.Cfg.Offline = offline
		if _, err := s.MeasureDirectNodes(context.Background(), remote.URL); err == nil {
			t.Fatal("remote source accepted")
		}
	}
	if hits.Load() != 0 {
		t.Fatal("remote source fetched")
	}
}

func TestDirectNodesHTTPConnectAndBodyCancellation(t *testing.T) {
	for _, phase := range []string{"connect", "body"} {
		t.Run(phase, func(t *testing.T) {
			entered, closed := make(chan struct{}), make(chan struct{})
			endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(entered)
				w.WriteHeader(200)
				w.(http.Flusher).Flush()
				<-r.Context().Done()
				close(closed)
			}))
			defer endpoint.Close()
			u, _ := url.Parse(endpoint.URL)
			var p nodes.Proxy
			if phase == "connect" {
				proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					c, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						return
					}
					defer c.Close()
					close(entered)
					io.Copy(io.Discard, c)
					close(closed)
				}))
				defer proxy.Close()
				pu, _ := url.Parse(proxy.URL)
				p = proxyEntry(pu.Host, "http")
			} else {
				p, _ = directHTTPProxy(t, endpoint.Listener.Addr().String(), u.Host, true)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan Report, 1)
			go func() {
				r, _ := nodeService().measureDirectNodes(ctx, directYAML(p), directOptions(endpoint))
				done <- r
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("fixture not entered")
			}
			cancel()
			select {
			case r := <-done:
				if directResults(t, r)[0].Error != "canceled" {
					t.Fatalf("bad cancellation: %+v", r)
				}
			case <-time.After(time.Second):
				t.Fatal("request did not cancel")
			}
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("connection/handler leaked")
			}
		})
	}
}

func TestDirectNodesFixedBudgetsAndInputBounds(t *testing.T) {
	if directNodeLimit != 32 || directNodeConcurrency != 4 || directNodeTimeout != 8*time.Second || directNodeBatchTimeout != 45*time.Second || directNodeSourceLimit != 2<<20 {
		t.Fatal("documented resource budgets changed")
	}
	oversized := "proxies: " + strings.Repeat(" ", (2<<20))
	if _, err := nodeService().MeasureDirectNodes(context.Background(), oversized); err == nil {
		t.Fatal("oversized inline configuration accepted")
	}
	dir := t.TempDir()
	if _, err := nodeService().MeasureDirectNodes(context.Background(), dir); err == nil {
		t.Fatal("directory accepted")
	}
	path := filepath.Join(dir, "oversized.yaml")
	if err := os.WriteFile(path, []byte(oversized), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := nodeService().MeasureDirectNodes(context.Background(), path); err == nil {
		t.Fatal("oversized file accepted")
	}
}

func TestDirectNodesUnsupportedConfigurationBeforeCONNECT(t *testing.T) {
	for _, field := range []struct{ name, value string }{
		{"dialer-proxy", "fixture-chain"}, {"interface-name", "fixture-interface"}, {"routing-mark", "123"}, {"ip-version", "ipv4"},
		{"bind-address", "127.0.0.1"}, {"bind-interface", "fixture-interface"}, {"source-ip", "127.0.0.1"},
		{"tfo", "true"}, {"mptcp", "true"}, {"udp", "false"}, {"udp-over-tcp", "true"},
		{"sni", "fixture.invalid"}, {"servername", "fixture.invalid"}, {"alpn", "[h2]"}, {"client-fingerprint", "chrome"},
		{"fingerprint", "fixture-secret"}, {"certificate", "fixture-secret"}, {"private-key", "fixture-secret"},
		{"name-cert-verify", "fixture.invalid"}, {"grpc-opts", "{grpc-service-name: fixture-service}"}, {"network", "ws"},
		{"headers", "{X-Fixture: fixture-secret}"}, {"http-opts", "{path: /fixture}"}, {"ws-opts", "{path: /fixture}"},
		{"smux", "{enabled: true}"}, {"packet-encoding", "xudp"}, {"future-outbound-option", "fixture-secret"},
		{"metadata", "{description: fixture-secret, dialer-proxy: fixture-metadata}"},
	} {
		t.Run("node/"+field.name, func(t *testing.T) {
			srv, endpointHits := directTLS(t, `{"ip":"192.0.2.80"}`, 200)
			u, _ := url.Parse(srv.URL)
			p, connects := directHTTPProxy(t, srv.Listener.Addr().String(), u.Host, true)
			text := strings.Replace(directYAML(p), "}\n", ", "+field.name+": "+field.value+"}\n", 1)
			rep, err := nodeService().measureDirectNodes(context.Background(), text, directOptions(srv))
			if err != nil {
				t.Fatal(err)
			}
			out := directResults(t, rep)
			if rep.Verdict != "abstain" || len(out) != 1 || out[0].Index != 1 || out[0].Status != "unsupported" || out[0].At != nil {
				t.Errorf("unsupported configuration measured: %+v", rep)
			}
			if connects.Load() != 0 || endpointHits.Load() != 0 {
				t.Errorf("unsupported configuration sent CONNECT=%d endpoint=%d", connects.Load(), endpointHits.Load())
			}
			blob, _ := json.Marshal(rep)
			if strings.Contains(string(blob), "fixture-") {
				t.Error("unsupported configuration leaked values")
			}
		})
	}
	for _, field := range []string{"interface-name: fixture-interface", "routing-mark: 123", "ip-version: ipv4", "bind-address: 127.0.0.1", "dns: {enable: true}", "ipv6: false", "tls: {certificate: fixture-secret}", "future-global-route-option: fixture-secret", "metadata: {description: fixture-secret}"} {
		t.Run("root/"+strings.Split(field, ":")[0], func(t *testing.T) {
			srv, endpointHits := directTLS(t, `{"ip":"192.0.2.80"}`, 200)
			u, _ := url.Parse(srv.URL)
			p, connects := directHTTPProxy(t, srv.Listener.Addr().String(), u.Host, true)
			rep, err := nodeService().measureDirectNodes(context.Background(), field+"\n"+directYAML(p), directOptions(srv))
			if err != nil {
				t.Fatal(err)
			}
			out := directResults(t, rep)
			if rep.Verdict != "abstain" || out[0].Status != "unsupported" || out[0].Index != 1 || out[0].At != nil {
				t.Errorf("unsupported root configuration measured: %+v", rep)
			}
			blob, _ := json.Marshal(rep)
			if strings.Contains(string(blob), "fixture-") {
				t.Error("unsupported root configuration leaked values")
			}
			if connects.Load() != 0 || endpointHits.Load() != 0 {
				t.Errorf("unsupported root configuration sent CONNECT=%d endpoint=%d", connects.Load(), endpointHits.Load())
			}
		})
	}
}

func TestDirectNodesMalformedRawItemsRejectWholeBatch(t *testing.T) {
	for _, kind := range []string{"scalar", "null", "sequence", "missing_name", "missing_type", "missing_server", "missing_port", "empty_name", "bad_name", "bad_type", "bad_server", "bad_port", "fractional_port", "out_of_range_port", "bad_username", "bad_password", "bad_tls", "bad_skip_verify", "duplicate_key", "non_string_key"} {
		t.Run(kind, func(t *testing.T) {
			srv, endpointHits := directTLS(t, `{"ip":"192.0.2.81"}`, 200)
			u, _ := url.Parse(srv.URL)
			p, connects := directHTTPProxy(t, srv.Listener.Addr().String(), u.Host, true)
			entry := strings.TrimPrefix(directYAML(p), "proxies:\n")
			bad := entry
			switch kind {
			case "scalar":
				bad = "- fixture-secret-scalar\n"
			case "null":
				bad = "- null\n"
			case "sequence":
				bad = "- [fixture-secret]\n"
			case "missing_name":
				bad = strings.Replace(bad, "name: fixture-secret-name, ", "", 1)
			case "missing_type":
				bad = strings.Replace(bad, "type: http, ", "", 1)
			case "missing_server":
				bad = strings.Replace(bad, "server: 127.0.0.1, ", "", 1)
			case "missing_port":
				bad = strings.Replace(bad, fmt.Sprintf("port: %d, ", p.Port), "", 1)
			case "empty_name":
				bad = strings.Replace(bad, "name: fixture-secret-name", "name: ''", 1)
			case "bad_name":
				bad = strings.Replace(bad, "name: fixture-secret-name", "name: [fixture-secret]", 1)
			case "bad_type":
				bad = strings.Replace(bad, "type: http", "type: 123", 1)
			case "bad_server":
				bad = strings.Replace(bad, "server: 127.0.0.1", "server: [127.0.0.1]", 1)
			case "bad_port":
				bad = strings.Replace(bad, fmt.Sprintf("port: %d", p.Port), "port: fixture-secret", 1)
			case "fractional_port":
				bad = strings.Replace(bad, fmt.Sprintf("port: %d", p.Port), fmt.Sprintf("port: %d.5", p.Port), 1)
			case "out_of_range_port":
				bad = strings.Replace(bad, fmt.Sprintf("port: %d", p.Port), "port: 65536", 1)
			case "bad_username":
				bad = strings.Replace(bad, "username: fixture-user", "username: [fixture-secret]", 1)
			case "bad_password":
				bad = strings.Replace(bad, "password: fixture-secret-password", "password: null", 1)
			case "bad_tls":
				bad = strings.Replace(bad, "}\n", ", tls: fixture-secret}\n", 1)
			case "bad_skip_verify":
				bad = strings.Replace(bad, "}\n", ", skip-cert-verify: []}\n", 1)
			case "duplicate_key":
				bad = strings.Replace(bad, "}\n", ", name: fixture-secret-duplicate}\n", 1)
			case "non_string_key":
				bad = strings.Replace(bad, "}\n", ", 123: fixture-secret}\n", 1)
			}
			// A valid first item must not be sent before a later item fails validation;
			// a valid third item must never be renumbered after skipping the second.
			rep, err := nodeService().measureDirectNodes(context.Background(), "proxies:\n"+entry+bad+entry, directOptions(srv))
			if err == nil {
				t.Errorf("malformed raw list accepted/reindexed: %+v", rep)
			} else if strings.Contains(err.Error(), "fixture-") {
				t.Error("validation error leaked configuration")
			}
			if connects.Load() != 0 || endpointHits.Load() != 0 {
				t.Errorf("malformed batch sent CONNECT=%d endpoint=%d", connects.Load(), endpointHits.Load())
			}
		})
	}
}

func TestDirectNodesWhitelistKeepsOriginalPositions(t *testing.T) {
	srv, endpointHits := directTLS(t, `{"ip":"192.0.2.82"}`, 200)
	u, _ := url.Parse(srv.URL)
	p, connects := directHTTPProxy(t, srv.Listener.Addr().String(), u.Host, true)
	entry := strings.TrimPrefix(directYAML(p), "proxies:\n")
	unsupported := strings.Replace(entry, "}\n", ", dialer-proxy: fixture-chain}\n", 1)
	// name is inert metadata, even when its string mentions routing field names.
	named := strings.Replace(entry, "name: fixture-secret-name", "name: 'dialer-proxy: interface-name fixture-secret'", 1)
	text := "proxies:\n" + unsupported + named + strings.Replace(entry, "type: http", "type: vmess", 1)
	rep, err := nodeService().measureDirectNodes(context.Background(), text, directOptions(srv))
	if err != nil {
		t.Fatal(err)
	}
	out := directResults(t, rep)
	if len(out) != 3 || out[0].Index != 1 || out[0].Status != "unsupported" || out[1].Index != 2 || out[1].Status != "measured" || out[1].EgressIP != "192.0.2.82" || out[2].Index != 3 || out[2].Status != "unsupported" || rep.Verdict != "ok_with_caveats" {
		t.Fatalf("original positions or evidence lost: %+v", rep)
	}
	if connects.Load() != 1 || endpointHits.Load() != 1 {
		t.Fatalf("only supported node should connect: %d/%d", connects.Load(), endpointHits.Load())
	}
	blob, _ := json.Marshal(rep)
	if strings.Contains(string(blob), "fixture-") {
		t.Fatal("metadata/credentials leaked")
	}
}

func TestDirectNodesRejectsAdditionalYAMLDocuments(t *testing.T) {
	srv, endpointHits := directTLS(t, `{"ip":"192.0.2.83"}`, 200)
	u, _ := url.Parse(srv.URL)
	p, connects := directHTTPProxy(t, srv.Listener.Addr().String(), u.Host, true)
	if _, err := nodeService().measureDirectNodes(context.Background(), directYAML(p)+"---\n"+directYAML(p), directOptions(srv)); err == nil {
		t.Fatal("second YAML document ignored")
	}
	if connects.Load() != 0 || endpointHits.Load() != 0 {
		t.Fatal("multi-document input sent requests")
	}
}

// Exercise the production batch path, not only a parser helper: no valid peer
// before or after a malformed node may reach even the proxy TCP listener.
func TestDirectNodesYAMLStructureRejectsBeforeNetwork(t *testing.T) {
	cases := []struct {
		name  string
		build func(string) string
	}{
		{"alias_tls_key", func(e string) string {
			return "proxies:\n" + e + strings.Replace(e, "}\n", ", &k tls: fixture-secret-invalid, *k: false}\n", 1) + e
		}},
		{"alias_root_key", func(e string) string { return "&p proxies: [null]\n*p:\n" + e }},
		{"alias_first_key", func(e string) string {
			return "proxies:\n" + strings.Replace(e, "}\n", ", &k tls: fixture-secret-invalid, *k: false}\n", 1) + e
		}},
		{"alias_last_key", func(e string) string {
			return "proxies:\n" + e + strings.Replace(e, "}\n", ", &k tls: fixture-secret-invalid, *k: false}\n", 1)
		}},
		{"tagged_duplicate", func(e string) string {
			return "proxies:\n" + e + strings.Replace(e, "}\n", ", tls: fixture-secret-invalid, !!str tls: false}\n", 1) + e
		}},
		{"escaped_duplicate", func(e string) string {
			return "proxies:\n" + e + strings.Replace(e, "}\n", `, tls: fixture-secret-invalid, "t\u006cs": false}`+"\n", 1) + e
		}},
		{"duplicate_root", func(e string) string { return "proxies: [null]\n!!str proxies:\n" + e }},
		{"tagged_non_string_root", func(e string) string { return "!!int 12: fixture-secret\nproxies:\n" + e }},
		{"custom_root_key_tag", func(e string) string { return "!fixture-secret proxies:\n" + e }},
		{"custom_node_key_tag", func(e string) string {
			return "proxies:\n" + e + strings.Replace(e, "type: http", "!fixture-secret type: http", 1) + e
		}},
		{"custom_value_tag", func(e string) string {
			return "proxies:\n" + e + strings.Replace(e, "type: http", "type: !fixture-secret http", 1) + e
		}},
		{"custom_container_tag", func(e string) string {
			return "proxies:\n" + e + strings.Replace(e, "- {", "- !fixture-secret {", 1) + e
		}},
		{"merge_node", func(e string) string {
			return "proxies:\n" + e + strings.Replace(e, "}\n", ", <<: {tls: false}}\n", 1) + e
		}},
		{"merge_root", func(e string) string { return "<<: {proxies: [null]}\nproxies:\n" + e }},
		{"quoted_merge", func(e string) string {
			return "proxies:\n" + e + strings.Replace(e, "}\n", `, "<<": {tls: false}}`+"\n", 1) + e
		}},
		{"nested_alias_key", func(e string) string {
			return "proxies:\n" + e + strings.Replace(e, "}\n", ", metadata: {&k tls: fixture-secret, *k: false}}\n", 1) + e
		}},
		{"nested_duplicate", func(e string) string {
			return "proxies:\n" + e + strings.Replace(e, "}\n", ", metadata: {tls: fixture-secret, !!str tls: false}}\n", 1) + e
		}},
		{"nested_non_string", func(e string) string {
			return "proxies:\n" + e + strings.Replace(e, "}\n", ", metadata: {true: fixture-secret}}\n", 1) + e
		}},
		{"sequence_key", func(e string) string {
			return "proxies:\n" + e + strings.Replace(e, "}\n", ", ? [fixture-secret] : false}\n", 1) + e
		}},
		{"mapping_key", func(e string) string {
			return "proxies:\n" + e + strings.Replace(e, "}\n", ", ? {fixture-secret: value} : false}\n", 1) + e
		}},
		{"merge_alias", func(e string) string {
			return "proxies:\n" + strings.Replace(e, "- {", "- &node {", 1) + "- {<<: *node}\n" + e
		}},
		{"nested_sequence_duplicate", func(e string) string {
			return "proxies:\n" + e + strings.Replace(e, "}\n", ", metadata: [{tls: fixture-secret, !!str tls: false}]}\n", 1) + e
		}},
		{"binary_tag", func(e string) string {
			return "proxies:\n" + e + strings.Replace(e, "}\n", ", metadata: !!binary Zml4dHVyZS1zZWNyZXQ=}\n", 1) + e
		}},
		{"timestamp_tag", func(e string) string {
			return "proxies:\n" + e + strings.Replace(e, "}\n", ", metadata: !!timestamp 2001-01-01}\n", 1) + e
		}},
		{"value_alias", func(e string) string {
			return "proxies:\n" + e + strings.Replace(e, "name: fixture-secret-name, type: http", "name: &v http, type: *v", 1) + e
		}},
		{"cyclic_alias", func(e string) string {
			return "proxies:\n" + e + strings.Replace(e, "}\n", ", metadata: &cycle {self: *cycle}}\n", 1) + e
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, endpointHits := directTLS(t, `{"ip":"192.0.2.84"}`, 200)
			u, _ := url.Parse(srv.URL)
			accepted := new(atomic.Int32)
			p, connects := directHTTPProxy(t, srv.Listener.Addr().String(), u.Host, true, accepted)
			entry := strings.TrimPrefix(directYAML(p), "proxies:\n")
			rep, err := nodeService().measureDirectNodes(context.Background(), tc.build(entry), directOptions(srv))
			if err != errDirectNodeConfiguration {
				t.Errorf("ambiguous YAML not rejected with controlled error: err=%v verdict=%s", err, rep.Verdict)
			}
			blob, _ := json.Marshal(rep)
			if strings.Contains(string(blob), "fixture-") || (err != nil && strings.Contains(err.Error(), "fixture-")) {
				t.Error("configuration leaked into report/error")
			}
			if accepted.Load() != 0 || connects.Load() != 0 || endpointHits.Load() != 0 {
				t.Errorf("rejected batch sent TCP=%d CONNECT=%d endpoint=%d", accepted.Load(), connects.Load(), endpointHits.Load())
			}
		})
	}
}

func TestDirectNodesYAMLUnambiguousStringsKeepPositions(t *testing.T) {
	srv, endpointHits := directTLS(t, `{"ip":"192.0.2.85"}`, 200)
	u, _ := url.Parse(srv.URL)
	p, connects := directHTTPProxy(t, srv.Listener.Addr().String(), u.Host, true)
	entry := strings.TrimPrefix(directYAML(p), "proxies:\n")
	// Unreferenced anchors and standard explicit string tags do not change key
	// identity. Quoting/escapes resolve to the same supported key before decoding.
	tagged := strings.Replace(entry, "name: fixture-secret-name", `&unused !!str name: !!str fixture-secret-name`, 1)
	tagged = strings.Replace(tagged, "type: http", `"t\u0079pe": http`, 1)
	text := "!!str proxies:\n" + strings.Replace(entry, "type: http", "type: vmess", 1) + tagged + entry
	rep, err := nodeService().measureDirectNodes(context.Background(), text, directOptions(srv))
	if err != nil {
		t.Fatal(err)
	}
	out := directResults(t, rep)
	if len(out) != 3 || out[0].Index != 1 || out[0].Status != "unsupported" || out[1].Index != 2 || out[1].Status != "measured" || out[2].Index != 3 || out[2].Status != "measured" || rep.Verdict != "ok_with_caveats" {
		t.Fatalf("unambiguous input lost original positions: %+v", rep)
	}
	if connects.Load() != 2 || endpointHits.Load() != 2 {
		t.Fatalf("supported nodes not measured: %d/%d", connects.Load(), endpointHits.Load())
	}
}
