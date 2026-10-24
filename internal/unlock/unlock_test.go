package unlock

import (
	"context"
	"strings"
	"testing"
)

type fx map[string]Response

func (f fx) Get(ctx context.Context, rawURL string, headers map[string]string) Response {
	if r, ok := f[rawURL]; ok {
		return r
	}
	body := "open"
	if strings.Contains(rawURL, "tiktok.com") {
		body = `"region":"US"`
	}
	if strings.Contains(rawURL, "gemini.google.com") {
		body = "gemini ready"
	}
	if strings.Contains(rawURL, "cdn-cgi/trace") {
		body = "ip=1.1.1.1\nloc=US\n"
	}
	return Response{Status: 200, Body: body, FinalURL: rawURL}
}

func TestCatalogueAtLeast25(t *testing.T) {
	ids := Catalogue()
	if len(ids) < 25 {
		t.Fatalf("%d", len(ids))
	}
	e := &Engine{Get: fx{}}
	res := e.Check(context.Background(), nil)
	if len(res) < 25 {
		t.Fatal(len(res))
	}
	bad := 0
	for _, r := range res {
		if r.Status == ErrStatus || r.Status == "" {
			bad++
			t.Log(r.Service, r.Status, r.Evidence)
		}
	}
	if bad > 0 {
		t.Fatalf("%d errors", bad)
	}
}

func TestClaudeBlockedAndNetflixOriginals(t *testing.T) {
	e := &Engine{Get: fx{
		"https://claude.ai/": {Status: 200, FinalURL: "https://claude.ai/app-unavailable-in-region", Body: "app-unavailable-in-region"},
	}}
	got := e.Check(context.Background(), []string{"claude"})
	if got[0].Status != No {
		t.Fatal(got[0])
	}
	e2 := &Engine{Get: fx{
		"https://www.netflix.com/title/81280792": {Status: 200, Body: "play"},
		"https://www.netflix.com/title/70143836": {Status: 200, Body: "title not available"},
	}}
	nf := e2.Check(context.Background(), []string{"netflix"})
	if nf[0].Status != OriginalsOnly {
		t.Fatal(nf[0])
	}
	e3 := &Engine{Get: fx{}, Resolve: func(ctx context.Context, host string) string { return "dns" }}
	m := e3.method(context.Background(), "claude.ai")
	if m != "dns" {
		t.Fatal(m)
	}
}

func TestTikTokIDCNeedsGzip(t *testing.T) {
	e := &Engine{Get: fx{
		"https://www.tiktok.com/": Response{Status: 200, Body: "shell"},
	}}
	// default fixture adds region only when the map misses. Force both calls empty then gzip.
	e.Get = getterFunc(func(rawURL string, headers map[string]string) Response {
		if headers["Accept-Encoding"] == "gzip" {
			return Response{Status: 200, Body: `"region":"US"`}
		}
		return Response{Status: 200, Body: "no region here"}
	})
	got := e.Check(context.Background(), []string{"tiktok"})
	if got[0].Status != IDC {
		t.Fatalf("%+v", got[0])
	}
}

type getterFunc func(rawURL string, headers map[string]string) Response

func (f getterFunc) Get(ctx context.Context, rawURL string, headers map[string]string) Response {
	return f(rawURL, headers)
}
