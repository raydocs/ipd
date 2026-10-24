package unlock

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type brokenBody struct{ sent bool }

func (b *brokenBody) Read(p []byte) (int, error) {
	if b.sent {
		return 0, errors.New("fixture truncated response")
	}
	b.sent = true
	return copy(p, `KadabraRootContainer`), nil
}
func (*brokenBody) Close() error { return nil }

func TestLiveGetterRejectsIncompleteBodies(t *testing.T) {
	for _, tc := range []struct {
		name string
		body io.ReadCloser
	}{
		{"read_error", &brokenBody{}},
		{"oversized", io.NopCloser(strings.NewReader(`KadabraRootContainer` + strings.Repeat(" ", 256<<10)))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: tc.body, Header: http.Header{}, Request: req}, nil
			})}
			getter := LiveGetter{Client: client}
			if r := getter.Get(context.Background(), "https://www.meta.ai/", nil); r.Err == nil {
				t.Fatal("incomplete body accepted")
			}
		})
	}
}

func TestLiveGetterGzip(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write([]byte(`{"region":"US"}`))
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, encoding string
		body           []byte
		wantErr        bool
	}{
		{"valid", "gzip", buf.Bytes(), false},
		{"truncated", "gzip", buf.Bytes()[:len(buf.Bytes())-4], true},
		{"invalid", "gzip", []byte("not gzip"), true},
		{"unsupported", "br", []byte(`{"region":"US"}`), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(tc.body)), Header: http.Header{"Content-Encoding": []string{tc.encoding}}, Request: req}, nil
			})}
			getter := LiveGetter{Client: client}
			r := getter.Get(context.Background(), "https://www.tiktok.com/", map[string]string{"Accept-Encoding": "gzip"})
			if (r.Err != nil) != tc.wantErr {
				t.Fatalf("%+v", r)
			}
			if !tc.wantErr && r.Body != `{"region":"US"}` {
				t.Fatalf("%+v", r)
			}
		})
	}
}
