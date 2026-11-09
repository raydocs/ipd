package app

import (
	"context"
	"errors"
	"ipd/internal/config"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

type reviewProxyRT func(*http.Request) (*http.Response, error)

func (f reviewProxyRT) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestReviewConfiguredProxyRespected(t *testing.T) {
	var proxyCalls atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyCalls.Add(1)
		w.WriteHeader(http.StatusProxyAuthRequired)
	}))
	defer proxy.Close()
	cfg := &config.Config{Proxy: proxy.URL, ProviderKeys: map[string]string{"ipqs": "review-only", "abuseipdb": "review-only"}}
	svc := New(cfg, nil)
	old := http.DefaultClient
	defer func() { http.DefaultClient = old }()
	direct := 0
	http.DefaultClient = &http.Client{Transport: reviewProxyRT(func(*http.Request) (*http.Response, error) {
		direct++
		return nil, errors.New("blocked direct transport")
	})}
	if _, err := svc.Compare(context.Background(), "1.1.1.1", true); err != nil {
		t.Fatal(err)
	}
	if direct != 0 || proxyCalls.Load() != 2 {
		t.Fatalf("configured proxy bypassed: direct=%d proxy=%d", direct, proxyCalls.Load())
	}
}
