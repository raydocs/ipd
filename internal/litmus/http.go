package litmus

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"ipd/internal/unlock"
)

type liveGetter struct{ transport http.RoundTripper }

var errObservation = errors.New("bounded observation failed")

func (g liveGetter) Get(ctx context.Context, raw string, headers map[string]string) unlock.Response {
	allowed := false
	for _, id := range []string{"google_search", "cloudflare_home", "akamai_home"} {
		if target(id) == raw {
			allowed = true
		}
	}
	if !allowed {
		return unlock.Response{Err: errObservation}
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	transport := g.transport
	if transport == nil {
		t := &http.Transport{
			Proxy: nil, DisableCompression: true, DisableKeepAlives: true,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			DialContext:         (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
			TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 3 * time.Second,
			MaxResponseHeaderBytes: maxHeaders,
		}
		defer t.CloseIdleConnections()
		transport = t
	}
	c := &http.Client{Transport: transport, Timeout: 6 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return unlock.Response{Err: errObservation}
	}
	// Only fixed non-secret headers; never forward caller credentials or env.
	req.Header.Set("User-Agent", "ipd-litmus/1")
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := c.Do(req)
	if err != nil {
		return unlock.Response{Err: errObservation}
	}
	defer resp.Body.Close()
	r := unlock.Response{Status: resp.StatusCode, FinalURL: raw, Header: resp.Header}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		r.Err = errObservation
		return r
	}
	if !headersOK(resp.Header) || !encodingOK(resp.Header) {
		r.Err = errObservation
		return r
	}
	wire := &io.LimitedReader{R: resp.Body, N: maxBody + 1}
	var reader io.Reader = wire
	if resp.Header.Get("Content-Encoding") != "" && resp.Header.Get("Content-Encoding") != "identity" {
		gz, e := gzip.NewReader(wire)
		if e != nil {
			r.Err = errObservation
			return r
		}
		defer gz.Close()
		reader = gz
	}
	b, err := io.ReadAll(io.LimitReader(reader, maxBody+1))
	if err != nil || len(b) > maxBody || wire.N <= 0 {
		r.Err = errObservation
		return r
	}
	r.Body = string(b)
	return r
}
