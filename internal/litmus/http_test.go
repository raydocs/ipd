package litmus

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type trip func(*http.Request) (*http.Response, error)

func (f trip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func zipped(b string) []byte {
	var buf bytes.Buffer
	g := gzip.NewWriter(&buf)
	_, _ = g.Write([]byte(b))
	_ = g.Close()
	return buf.Bytes()
}
func TestLiveBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, encoding string
		data           []byte
		bad            bool
	}{
		{"plain", "", []byte("body"), false},
		{"gzip", "gzip", zipped("body"), false},
		{"gzip_bomb", "gzip", zipped(strings.Repeat("x", maxBody+1)), true},
		{"wire_limit", "", bytes.Repeat([]byte("x"), maxBody+1), true},
		{"truncated_gzip", "gzip", zipped("body")[:12], true},
		{"chain", "gzip,gzip", zipped("body"), true},
		{"br", "br", []byte("body"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := liveGetter{transport: trip(func(req *http.Request) (*http.Response, error) {
				if req.Header.Get("Authorization") != "" || req.Header.Get("Cookie") != "" || req.Method != "GET" || req.URL.String() != target("google_search") {
					t.Fatal("unsafe request")
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Encoding": {tc.encoding}}, Body: io.NopCloser(bytes.NewReader(tc.data)), Request: req}, nil
			})}
			r := g.Get(context.Background(), target("google_search"), map[string]string{"Authorization": "secret"})
			if (r.Err != nil) != tc.bad {
				t.Fatalf("err=%v size=%d", r.Err, len(r.Body))
			}
		})
	}
}
func TestLocalHTTPRedirectAndLimits(t *testing.T) {
	for _, mode := range []string{"redirect", "headers", "duplicate_encoding", "truncated", "timeout", "success"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				switch mode {
				case "redirect":
					w.Header().Set("Location", "http://127.0.0.1/private")
					w.WriteHeader(302)
				case "headers":
					w.Header().Set("X-Large", strings.Repeat("x", maxHeaders+1))
					_, _ = w.Write([]byte("body"))
				case "duplicate_encoding":
					w.Header().Add("Content-Encoding", "gzip")
					w.Header().Add("Content-Encoding", "gzip")
					_, _ = w.Write(zipped("body"))
				case "truncated":
					w.Header().Set("Content-Length", "100")
					_, _ = w.Write([]byte("body"))
				case "timeout":
					select {
					case <-r.Context().Done():
					case <-time.After(time.Second):
					}
				default:
					_, _ = w.Write([]byte("body"))
				}
			}))
			defer s.Close()
			local, _ := url.Parse(s.URL)
			// Fixture-only transport rewrites canonical request to a local server.
			tr := &http.Transport{DisableCompression: true, MaxResponseHeaderBytes: maxHeaders}
			defer tr.CloseIdleConnections()
			g := liveGetter{transport: trip(func(r *http.Request) (*http.Response, error) {
				c := r.Clone(r.Context())
				c.URL = local
				c.Host = local.Host
				return tr.RoundTrip(c)
			})}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			r := g.Get(ctx, target("google_search"), nil)
			if (r.Err == nil) != (mode == "success") {
				t.Fatalf("mode %s err %v", mode, r.Err)
			}
			if calls.Load() != 1 {
				t.Fatal(calls.Load())
			}
		})
	}
}
func TestLiveRejectsArbitraryURLAndTLS(t *testing.T) {
	g := liveGetter{transport: trip(func(*http.Request) (*http.Response, error) { t.Fatal("unexpected network"); return nil, nil })}
	if g.Get(context.Background(), "http://localhost/", nil).Err == nil {
		t.Fatal("accepted arbitrary URL")
	}
	// A self-signed local endpoint must not be trusted by the default transport.
	s := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("unverified TLS accepted") }))
	defer s.Close()
	tr := &http.Transport{DisableCompression: true}
	defer tr.CloseIdleConnections()
	local, _ := url.Parse(s.URL)
	g = liveGetter{transport: trip(func(r *http.Request) (*http.Response, error) {
		c := r.Clone(r.Context())
		c.URL = local
		return tr.RoundTrip(c)
	})}
	if g.Get(context.Background(), target("google_search"), nil).Err == nil {
		t.Fatal("TLS verification bypassed")
	}
}
