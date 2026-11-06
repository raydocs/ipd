package litmus

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"ipd/internal/unlock"
)

type getterFunc func(context.Context, string, map[string]string) unlock.Response

func (f getterFunc) Get(c context.Context, u string, h map[string]string) unlock.Response {
	return f(c, u, h)
}

const googleBody = `<html><body>Our systems have detected unusual traffic from your computer network.<form action="/sorry/index"><div class="g-recaptcha"></div></form></body></html>`

func TestEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, id, body    string
		h                 http.Header
		status            int
		want, cap, reason string
	}{
		{"cf", "cloudflare_home", "<html>wait</html>", http.Header{"Cf-Mitigated": {"challenge"}}, 403, Yes, Abstain, "recognized_challenge"},
		{"google", "google_search", googleBody, nil, 429, Yes, Yes, "recognized_challenge"},
		{"google_no_widget", "google_search", strings.ReplaceAll(googleBody, "g-recaptcha", "other"), nil, 429, Yes, Abstain, "recognized_challenge"},
		{"cf_presence", "cloudflare_home", "home", http.Header{"Server": {"cloudflare"}}, 200, Abstain, Abstain, "presence_only"},
		{"akamai_presence", "akamai_home", "home", http.Header{"Server": {"AkamaiGHost"}}, 403, Abstain, Abstain, "presence_only"},
		{"negative", "google_search", `<div id="search"><a href="/">result</a></div>`, nil, 200, Abstain, Abstain, "unknown_template"},
		{"unknown", "cloudflare_home", "new template", nil, 200, Abstain, Abstain, "unknown_template"},
		{"forbidden", "akamai_home", "Access denied", nil, 403, Abstain, Abstain, "unknown_template"},
		{"rate", "akamai_home", "slow down", nil, 429, Abstain, Abstain, "unknown_template"},
		{"falsepositive", "google_search", "captcha just a moment unusual traffic g-recaptcha", nil, 200, Abstain, Abstain, "unknown_template"},
		{"comment", "google_search", "<!--" + googleBody + "-->", nil, 200, Abstain, Abstain, "unknown_template"},
		{"script", "google_search", "<script>" + googleBody + "</script>", nil, 200, Abstain, Abstain, "unknown_template"},
		{"cf_google_conflict", "google_search", googleBody, http.Header{"Cf-Mitigated": {"challenge"}}, 403, Abstain, Abstain, "conflicting_markers"},
		{"provider_conflict", "cloudflare_home", "body", http.Header{"Server": {"cloudflare", "AkamaiGHost"}}, 200, Abstain, Abstain, "conflicting_markers"},
		{"header_conflict", "cloudflare_home", "body", http.Header{"Cf-Mitigated": {"challenge", "none"}}, 403, Abstain, Abstain, "conflicting_markers"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := Engine{Get: getterFunc(func(_ context.Context, u string, _ map[string]string) unlock.Response {
				h := tc.h.Clone()
				if h == nil {
					h = make(http.Header)
				}
				if h.Get("Content-Type") == "" {
					h.Set("Content-Type", "text/html")
				}
				return unlock.Response{FinalURL: u, Status: tc.status, Body: tc.body, Header: h}
			})}
			r := e.Check(context.Background(), tc.id, false)
			if r.ChallengeObserved != tc.want || r.CaptchaObserved != tc.cap || r.Reason != tc.reason {
				t.Fatalf("%+v", r)
			}
			if strings.Contains(tc.name, "conflict") && len(r.MatchedMarkers) == 0 {
				t.Fatal("lost evidence")
			}
			if r.CFBotScore != nil || r.ObservedAt.IsZero() || r.URL != target(tc.id) || r.HTTPStatus == nil {
				t.Fatal(r)
			}
		})
	}
}
func TestAbstentionAndSanitization(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*unlock.Response)
	}{
		{"error", func(r *unlock.Response) { r.Err = errors.New("secret error") }},
		{"redirect", func(r *unlock.Response) { r.FinalURL = "https://secret.invalid/" }},
		{"empty", func(r *unlock.Response) { r.Body = "" }},
		{"size", func(r *unlock.Response) { r.Body = strings.Repeat("x", maxBody+1) }},
		{"headers", func(r *unlock.Response) { r.Header.Set("X-Secret", strings.Repeat("x", maxHeaders)) }},
		{"header_count", func(r *unlock.Response) { r.Header["X-Many"] = make([]string, maxHeaderCount+1) }},
		{"encoding_chain", func(r *unlock.Response) { r.Header.Set("Content-Encoding", "gzip, gzip") }},
		{"encoding_duplicate", func(r *unlock.Response) { r.Header["Content-Encoding"] = []string{"gzip", "gzip"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := Engine{Get: getterFunc(func(_ context.Context, u string, _ map[string]string) unlock.Response {
				r := unlock.Response{FinalURL: u, Body: googleBody, Status: 429, Header: http.Header{}}
				tc.edit(&r)
				return r
			})}
			r := e.Check(context.Background(), "google_search", false)
			b, _ := json.Marshal(r)
			if r.ChallengeObserved != Abstain || r.CaptchaObserved != Abstain || len(r.MatchedMarkers) != 0 || strings.Contains(string(b), "secret") {
				t.Fatal(string(b))
			}
		})
	}
	calls := 0
	e := Engine{Get: getterFunc(func(context.Context, string, map[string]string) unlock.Response { calls++; return unlock.Response{} })}
	for _, id := range []string{"google_search", "https://localhost/", "localhost"} {
		e.Check(context.Background(), id, true)
	}
	e.Check(context.Background(), "https://localhost/", false)
	if calls != 0 {
		t.Fatal(calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := e.Check(ctx, "google_search", false)
	if r.Reason != "timeout" {
		t.Fatal(r)
	}
}

func TestErrorStatusAndSpoofedScoreAbstain(t *testing.T) {
	e := Engine{Get: getterFunc(func(_ context.Context, u string, _ map[string]string) unlock.Response {
		return unlock.Response{FinalURL: u, Body: "body", Status: 503, Header: http.Header{"Cf-Mitigated": {"challenge"}, "Cf-Bot-Score": {"99"}}}
	})}
	r := e.Check(context.Background(), "cloudflare_home", false)
	if r.ChallengeObserved != Abstain || r.CFBotScore != nil || r.Reason != "unexpected_status" {
		t.Fatal(r)
	}
}

func TestGoogleRepresentationBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, body, contentType string
		status                  int
		contentRange            string
	}{
		{"json", googleBody, "application/json", 200, ""}, {"plain", googleBody, "text/plain", 200, ""},
		{"template", "<template>" + googleBody + "</template>", "text/html", 200, ""},
		{"foreign_base", "<base href=\"https://example.invalid/\">" + googleBody, "text/html", 200, ""},
		{"partial", googleBody, "text/html", 206, "bytes 0-50/100"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := Engine{Get: getterFunc(func(_ context.Context, u string, _ map[string]string) unlock.Response {
				return unlock.Response{FinalURL: u, Status: tc.status, Body: tc.body, Header: http.Header{"Content-Type": {tc.contentType}, "Content-Range": {tc.contentRange}}}
			})}
			r := e.Check(context.Background(), "google_search", false)
			if r.ChallengeObserved == Yes || r.CaptchaObserved == Yes {
				t.Fatalf("non-active/incomplete representation voted: %+v", r)
			}
		})
	}
}

func TestGoogleDOMAndRangeAmbiguity(t *testing.T) {
	for _, body := range []string{
		`<base href="https://www.google.com/wrong/"><base href="https://www.google.com/">` + strings.ReplaceAll(googleBody, `action="/sorry/index"`, `action="sorry/index"`),
		strings.ReplaceAll(googleBody, `/sorry/index`, `/sorry%2Findex`),
		`<svg><form action="/sorry/index"></form></svg><div class="g-recaptcha"></div>Our systems have detected unusual traffic from your computer network.`,
		`<math><form action="/sorry/index"></form></math><div class="g-recaptcha"></div>Our systems have detected unusual traffic from your computer network.`,
	} {
		if m, f, w := googleMarkup(body); m && f {
			t.Fatalf("ambiguous markup voted (widget %v)", w)
		}
	}
	e := Engine{Get: getterFunc(func(_ context.Context, u string, _ map[string]string) unlock.Response {
		return unlock.Response{FinalURL: u, Status: 200, Body: googleBody, Header: http.Header{"Content-Type": {"text/html"}, "Content-Range": {"", "bytes 0-50/100"}}}
	})}
	if r := e.Check(context.Background(), "google_search", false); r.ChallengeObserved == Yes {
		t.Fatal("partial range voted")
	}
}
