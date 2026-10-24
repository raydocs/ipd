package app

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSubscriptionRejectsInitialLoopback(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("proxies: []"))
	}))
	defer server.Close()
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	if _, err := readSource(context.Background(), server.URL, ""); err == nil {
		t.Error("loopback subscription accepted")
	}
	if hits.Load() != 0 {
		t.Error("unsafe endpoint was contacted")
	}
}

func TestSubscriptionRejectsOversizedLocalFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "subscription.yaml")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", (2<<20)+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSource(context.Background(), path, ""); err == nil {
		t.Fatal("oversized local file accepted")
	}
}

func TestSubscriptionRejectsNonSubscriptionScheme(t *testing.T) {
	if _, err := readSource(context.Background(), "ftp://example.invalid/source", ""); err == nil {
		t.Fatal("non-HTTP URL accepted as inline subscription")
	}
}

// HTTP behavior is exercised against a real loopback server using the internal
// fetch seam. The production entrypoint never accepts this client's transport.
func TestSubscriptionHTTPIntegrity(t *testing.T) {
	cases := []struct {
		name         string
		status, size int
		truncated    bool
		wantErr      bool
	}{
		{name: "small", status: 200, size: 32},
		{name: "exact_limit", status: 200, size: subscriptionLimit},
		{name: "over_limit", status: 200, size: subscriptionLimit + 1, wantErr: true},
		{name: "error_status", status: 503, size: 8, wantErr: true},
		{name: "not_modified", status: 304, wantErr: true},
		{name: "partial_body", status: 200, size: 8, truncated: true, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.truncated {
					w.Header().Set("Content-Length", "100")
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, strings.Repeat("x", tc.size))
			}))
			defer server.Close()
			body, err := fetchSubscription(context.Background(), server.URL+"/?token=fixture-secret", server.Client())
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v, want error=%v", err, tc.wantErr)
			}
			if tc.wantErr && body != "" {
				t.Fatal("partial/untrusted body returned")
			}
			if !tc.wantErr && len(body) != tc.size {
				t.Fatalf("length=%d", len(body))
			}
			if err != nil && strings.Contains(err.Error(), "fixture-secret") {
				t.Fatal("error leaked URL")
			}
		})
	}
}

func TestSubscriptionLocalAndInline(t *testing.T) {
	for _, body := range []string{"proxies: []", "ss://fixture@example.invalid:443#example", strings.Repeat("x", subscriptionLimit)} {
		path := filepath.Join(t.TempDir(), "source")
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		got, err := readSource(context.Background(), path, "unsupported-proxy")
		if err != nil || got != body {
			t.Fatalf("file: length=%d err=%v", len(got), err)
		}
		if len(body) < subscriptionLimit {
			got, err = readSource(context.Background(), body, "unsupported-proxy")
			if err != nil || got != body {
				t.Fatalf("inline: err=%v", err)
			}
		}
	}
	if _, err := readSource(context.Background(), "proxies: "+strings.Repeat("x", subscriptionLimit), ""); err == nil {
		t.Fatal("oversized inline accepted")
	}
	if _, err := readSubscriptionBody(failingSubscriptionReader{}); err == nil {
		t.Fatal("read error ignored")
	}
}

type failingSubscriptionReader struct{}

func (failingSubscriptionReader) Read([]byte) (int, error) {
	return 0, errors.New("fixture secret must not escape")
}

func TestSubscriptionURLValidation(t *testing.T) {
	invalid := []string{
		"ftp://example.invalid/source", "file:///source", "http:opaque", "http:///source", "//example.invalid/source",
		"https://fixture:fixture-secret@example.invalid/?token=fixture-secret",
		"http://example.invalid:", "http://example.invalid:0/", "http://example.invalid:65536/", "http://example.invalid:bad/",
		"http://[::1%25lo0]/", "http://[::1", "http://::1/", "http://[127.0.0.1]/", "http://[example.invalid]/",
		"http://127.1/", "http://0177.0.0.1/", "http://2130706433/", "http://0x7f000001/", "http://0x7f.0.0.1/",
		"http://%31%32%37.0.0.1/", "http://example..invalid/", "http://-example.invalid/", "http://example_.invalid/",
		"http://example.invalid\\@example.invalid/", "https://example.invalid/%zz?fixture-secret",
	}
	for _, raw := range invalid {
		t.Run(raw, func(t *testing.T) {
			if _, err := subscriptionURL(raw); err == nil {
				t.Fatal("invalid URL accepted")
			} else if strings.Contains(err.Error(), "fixture-secret") {
				t.Fatal("URL leaked")
			}
		})
	}
	for _, raw := range []string{"HTTPS://example.invalid/source", "http://example.invalid.:8080/source", "http://192.0.2.1/", "https://[2001:db8::1]:443/", "http://[::ffff:192.0.2.1]/"} {
		if _, err := subscriptionURL(raw); err != nil {
			t.Fatalf("valid syntax rejected: %v", err)
		}
	}
}

func TestSubscriptionUnsafeAddresses(t *testing.T) {
	// Prefix starts are policy definitions, not real server/visitor fixtures.
	for _, prefix := range subscriptionDenied {
		if subscriptionAddressAllowed(prefix.Addr()) {
			t.Fatalf("allowed reserved prefix %s", prefix)
		}
	}
	for _, raw := range []string{"127.0.0.1", "::1", "::", "::ffff:127.0.0.1", "::ffff:192.0.2.1", "2001:db8::1", "fe80::1%lo0"} {
		if subscriptionAddressAllowed(netip.MustParseAddr(raw)) {
			t.Fatalf("allowed %s", raw)
		}
	}
	if subscriptionAddressAllowed(netip.Addr{}) {
		t.Fatal("invalid address accepted")
	}
}

func TestSubscriptionDNSFailClosed(t *testing.T) {
	cases := []struct {
		name string
		ips  []netip.Addr
		err  error
	}{
		{name: "empty"}, {name: "lookup_error", err: errors.New("fixture-secret")},
		{name: "loopback", ips: []netip.Addr{netip.MustParseAddr("127.0.0.1")}},
		{name: "mixed_answers", ips: []netip.Addr{subscriptionIPv6Allocated[0].Addr(), netip.MustParseAddr("127.0.0.1")}},
		{name: "mixed_answers_reverse", ips: []netip.Addr{netip.MustParseAddr("127.0.0.1"), subscriptionIPv6Allocated[0].Addr()}},
		{name: "mapped", ips: []netip.Addr{netip.MustParseAddr("::ffff:127.0.0.1")}},
		{name: "IPv6", ips: []netip.Addr{netip.MustParseAddr("2001:db8::1")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lookups, dials := 0, 0
			transport := subscriptionTransport{
				lookup: func(ctx context.Context, network, host string) ([]netip.Addr, error) {
					lookups++
					if network != "ip" || host != "example.invalid" {
						t.Error("not a combined A/AAAA lookup")
					}
					return tc.ips, tc.err
				},
				dial: func(context.Context, string, string) (net.Conn, error) {
					dials++
					return nil, errors.New("unexpected dial")
				},
			}
			_, err := fetchSubscription(context.Background(), "http://example.invalid/?token=fixture-secret", &http.Client{Transport: transport})
			if err == nil || strings.Contains(err.Error(), "fixture-secret") || lookups != 1 || dials != 0 {
				t.Fatalf("err=%v lookups=%d dials=%d", err, lookups, dials)
			}
		})
	}
}

func TestSubscriptionPinnedDialNoRebindingOrEnvironmentProxy(t *testing.T) {
	for _, ip := range []string{"192.0.2.1", "2001:db8::1", "::ffff:192.0.2.1"} {
		t.Run(ip, func(t *testing.T) {
			var hits atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				if r.Host != "example.invalid:8080" {
					t.Error("original HTTP Host lost")
				}
				_, _ = io.WriteString(w, "pinned")
			}))
			defer server.Close()
			var proxyHits atomic.Int32
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxyHits.Add(1); t.Error("environment proxy contacted") }))
			defer proxy.Close()
			t.Setenv("HTTP_PROXY", proxy.URL)
			t.Setenv("HTTPS_PROXY", proxy.URL)
			t.Setenv("ALL_PROXY", proxy.URL)
			t.Setenv("NO_PROXY", "")
			// The validated-IP/socket boundary is tested with documentation addresses.
			// Dial must receive only this numeric address, never the hostname whose
			// second DNS answer could change. The fixture routes it to loopback itself.
			var dialed []string
			dial := func(ctx context.Context, network, address string) (net.Conn, error) {
				dialed = append(dialed, address)
				return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
			}
			req, _ := http.NewRequest(http.MethodGet, "http://example.invalid:8080/source", nil)
			resp, err := roundTripSubscriptionPinned(req, []netip.Addr{netip.MustParseAddr(ip)}, dial)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			want := net.JoinHostPort(netip.MustParseAddr(ip).Unmap().String(), "8080")
			if err != nil || string(body) != "pinned" || len(dialed) != 1 || dialed[0] != want || hits.Load() != 1 || proxyHits.Load() != 0 {
				t.Fatalf("err=%v dial=%v hits=%d", err, dialed, hits.Load())
			}
		})
	}
}

type subscriptionRoundTripFunc func(*http.Request) (*http.Response, error)

func (f subscriptionRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSubscriptionRedirectRevalidatesDestination(t *testing.T) {
	for _, location := range []string{"http://127.0.0.1/source", "http://[::1]/source", "http://[::ffff:127.0.0.1]/source", "http://example.invalid/next", "ftp://example.invalid/source", "http://fixture:fixture-secret@example.invalid/"} {
		t.Run(location, func(t *testing.T) {
			var hits atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				http.Redirect(w, r, location, http.StatusFound)
			}))
			defer server.Close()
			lookups, dials := 0, 0
			secure := subscriptionTransport{
				lookup: func(context.Context, string, string) ([]netip.Addr, error) {
					lookups++
					if lookups == 1 {
						return []netip.Addr{subscriptionIPv6Allocated[0].Addr()}, nil
					}
					return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
				},
				dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					dials++
					if address != net.JoinHostPort(subscriptionIPv6Allocated[0].Addr().String(), "80") {
						t.Error("dial was not pinned")
					}
					return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
				},
			}
			client := &http.Client{CheckRedirect: subscriptionRedirect, Transport: secure}
			body, err := fetchSubscription(context.Background(), "http://example.invalid/source?token=fixture-secret", client)
			if err == nil || body != "" || strings.Contains(err.Error(), "fixture-secret") || hits.Load() != 1 || dials != 1 {
				t.Fatalf("err=%v hits=%d dials=%d", err, hits.Load(), dials)
			}
			if location == "http://example.invalid/next" && lookups != 2 {
				t.Fatal("same-host redirect did not re-resolve DNS")
			}
		})
	}
}

func TestSubscriptionRedirectLimit(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, "/again", http.StatusFound)
	}))
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = subscriptionRedirect
	if _, err := fetchSubscription(context.Background(), server.URL, client); err == nil {
		t.Fatal("redirect loop accepted")
	}
	if hits.Load() != subscriptionRedirectLimit+1 {
		t.Fatalf("hits=%d", hits.Load())
	}
}

func TestSubscriptionCancellationAndDeadline(t *testing.T) {
	for _, stage := range []string{"dns", "headers", "body"} {
		t.Run(stage, func(t *testing.T) {
			started := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if stage == "body" {
					w.WriteHeader(200)
					w.(http.Flusher).Flush()
				}
				close(started)
				<-r.Context().Done()
			}))
			defer server.Close()
			client := server.Client()
			if stage == "dns" {
				client = &http.Client{Transport: subscriptionTransport{lookup: func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
					close(started)
					<-ctx.Done()
					return nil, ctx.Err()
				}}}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := fetchSubscription(ctx, "http://example.invalid/?token=fixture-secret", clientForSubscriptionFixture(client, server, stage))
				done <- err
			}()
			select {
			case <-started:
			case <-time.After(2 * time.Second):
				t.Fatal("request did not start")
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("err=%v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("cancellation blocked")
			}
		})
	}
	// A pre-expired deadline must also abort before a socket is opened.
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if _, err := readSource(ctx, "http://example.invalid/?token=fixture-secret", ""); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v", err)
	}
}

func clientForSubscriptionFixture(client *http.Client, server *httptest.Server, stage string) *http.Client {
	if stage == "dns" {
		return client
	}
	return &http.Client{Transport: subscriptionRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		return roundTripSubscriptionPinned(r, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		})
	})}
}

func TestSubscriptionSecretsAndConfiguredProxy(t *testing.T) {
	for _, source := range []string{"http://fixture:fixture-secret@example.invalid/", "https://example.invalid:bad/?token=fixture-secret", "https://example.invalid/%zz?token=fixture-secret"} {
		if _, err := readSource(context.Background(), source, ""); err == nil || strings.Contains(err.Error(), "fixture-secret") || strings.Contains(err.Error(), "example.invalid") {
			t.Fatalf("err=%v", err)
		}
	}
	if _, err := readSource(context.Background(), "https://example.invalid/?token=fixture-secret", "http://fixture:fixture-secret@example.invalid:8080"); err == nil || !strings.Contains(err.Error(), "proxy") || strings.Contains(err.Error(), "fixture-secret") {
		t.Fatalf("err=%v", err)
	}
	client := &http.Client{Transport: subscriptionRoundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("fixture-secret") })}
	if _, err := fetchSubscription(context.Background(), "https://example.invalid/?token=fixture-secret", client); err == nil || strings.Contains(err.Error(), "fixture-secret") {
		t.Fatalf("err=%v", err)
	}
}

func TestSubscriptionValidatedDNSIsPinned(t *testing.T) {
	// Use the policy's allocated global-unicast prefix anchor as a synthetic DNS answer,
	// never a real public server. The only socket endpoint is the loopback fixture.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "example.invalid" {
			t.Error("original Host lost")
		}
		_, _ = io.WriteString(w, "validated and pinned")
	}))
	defer server.Close()
	lookups, dials := 0, 0
	transport := subscriptionTransport{
		lookup: func(ctx context.Context, network, host string) ([]netip.Addr, error) {
			lookups++
			if network != "ip" || host != "example.invalid" {
				t.Error("unexpected DNS lookup")
			}
			if lookups > 1 {
				return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
			}
			return []netip.Addr{subscriptionIPv6Allocated[0].Addr()}, nil
		},
		dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dials++
			// A hostname here would trigger another lookup and could rebind to loopback.
			if address != net.JoinHostPort(subscriptionIPv6Allocated[0].Addr().String(), "80") {
				return nil, errors.New("unpinned dial")
			}
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		},
	}
	client := &http.Client{Transport: transport, CheckRedirect: subscriptionRedirect}
	body, err := fetchSubscription(context.Background(), "http://example.invalid/source", client)
	if err != nil || body != "validated and pinned" || lookups != 1 || dials != 1 {
		t.Fatalf("err=%v lookups=%d dials=%d", err, lookups, dials)
	}
	// A new request must resolve again rather than reusing an old validated socket.
	if _, err := fetchSubscription(context.Background(), "http://example.invalid/source", client); err == nil || lookups != 2 || dials != 1 {
		t.Fatalf("rebind: err=%v lookups=%d dials=%d", err, lookups, dials)
	}
}

func TestSubscriptionDNSDeadline(t *testing.T) {
	transport := subscriptionTransport{lookup: func(ctx context.Context, _, _ string) ([]netip.Addr, error) { <-ctx.Done(); return nil, ctx.Err() }}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := fetchSubscription(ctx, "https://example.invalid/?token=fixture-secret", &http.Client{Transport: transport}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v", err)
	}
}

func TestSubscriptionPinnedTLSVerification(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted TLS certificate accepted") }))
	defer server.Close()
	req, _ := http.NewRequest(http.MethodGet, "https://example.invalid/source", nil)
	resp, err := roundTripSubscriptionPinned(req, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	})
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil {
		t.Fatal("TLS verification was disabled")
	}
}

func TestSubscriptionLiteralDestinationsNeverDial(t *testing.T) {
	transport := subscriptionTransport{
		lookup: func(context.Context, string, string) ([]netip.Addr, error) {
			t.Error("literal IP sent to DNS")
			return nil, nil
		},
		dial: func(context.Context, string, string) (net.Conn, error) {
			t.Error("unsafe literal dialed")
			return nil, errors.New("unexpected dial")
		},
	}
	for _, prefix := range subscriptionDenied {
		raw := "http://" + net.JoinHostPort(prefix.Addr().String(), "80") + "/source"
		if _, err := fetchSubscription(context.Background(), raw, &http.Client{Transport: transport}); err == nil {
			t.Fatalf("allowed %s", prefix)
		}
	}
}

func TestSubscriptionUnallocatedIPv6IsReserved(t *testing.T) {
	for _, prefix := range []string{"2000::/16", "2001:1000::/23", "2d00::/8", "3000::/5", "3ffe::/16"} {
		if subscriptionAddressAllowed(netip.MustParsePrefix(prefix).Addr()) {
			t.Fatalf("allowed IANA-reserved range %s", prefix)
		}
	}
}

func TestSubscriptionRedirectDoesNotForwardQueryReferer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/first" {
			http.Redirect(w, r, "/last", http.StatusFound)
			return
		}
		if r.Referer() != "" {
			t.Error("subscription query forwarded as Referer")
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = subscriptionRedirect
	if body, err := fetchSubscription(context.Background(), server.URL+"/first?token=fixture-secret", client); err != nil || body != "ok" {
		t.Fatalf("body=%q err=%v", body, err)
	}
}
