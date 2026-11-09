package providers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestHTTPRejectsUnsafeResponses(t *testing.T) {
	for _, body := range []string{"null", strings.Repeat(" ", (1<<20)+1) + "{}"} {
		t.Run(body[:4], func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
			defer srv.Close()
			h := HTTP{Key: "secret", Base: srv.URL, Build: func(base, key, ip string) (string, http.Header) { return base, nil }}
			if _, err := h.Lookup(context.Background(), netip.MustParseAddr("1.1.1.1")); err == nil {
				t.Fatal("unsafe response accepted")
			}
		})
	}
}
