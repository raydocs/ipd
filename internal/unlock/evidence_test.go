package unlock

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func responseAt(u, body string) Response { return Response{Status: 200, Body: body, FinalURL: u} }

func TestUnrecognizedResponsesAbstain(t *testing.T) {
	for _, id := range Catalogue() {
		for _, tc := range []struct {
			name     string
			response func(string) Response
		}{
			{"redesign", func(u string) Response { return responseAt(u, "new landing page") }},
			{"empty", func(u string) Response { return responseAt(u, "") }},
			{"header_challenge", func(u string) Response {
				r := responseAt(u, `KadabraRootContainer "region":"US" 45631641,null,true`)
				r.Header = http.Header{"Cf-Mitigated": []string{"challenge"}}
				return r
			}},
			{"missing_final_url", func(u string) Response {
				return Response{Status: 200, Body: `KadabraRootContainer "region":"US" 45631641,null,true`}
			}},
			{"generic_forbidden", func(u string) Response { r := responseAt(u, "Access denied"); r.Status = 403; return r }},
			{"same_host_redirect", func(u string) Response {
				r := responseAt(u, `KadabraRootContainer "region":"US" 45631641,null,true`)
				r.FinalURL = u + "/challenge"
				return r
			}},
			{"challenge", func(u string) Response {
				return responseAt(u, `Just a moment KadabraRootContainer "region":"US" 45631641,null,true <script src="/cdn-cgi/challenge-platform/x"></script>`)
			}},
			{"http_error", func(u string) Response {
				r := responseAt(u, `KadabraRootContainer "region":"US" 45631641,null,true`)
				r.Status = 503
				return r
			}},
			{"redirect", func(u string) Response {
				r := responseAt("https://example.invalid/login", `KadabraRootContainer "region":"US" 45631641,null,true`)
				return r
			}},
			{"transport", func(u string) Response { return Response{Err: errors.New("fixture timeout")} }},
		} {
			t.Run(id+"/"+tc.name, func(t *testing.T) {
				e := Engine{Get: getterFunc(func(u string, _ map[string]string) Response { return tc.response(u) })}
				got := e.Check(context.Background(), []string{id})[0]
				if got.Status != "abstain" {
					t.Fatalf("want abstain, got %+v", got)
				}
			})
		}
	}
}

func TestChatGPTRequiresBothRecognizedResponses(t *testing.T) {
	const web = "https://api.openai.com/compliance/cookie_requirements"
	const app = "https://ios.chat.openai.com/"
	yesWeb := responseAt(web, `{"requires_cookie_consent":false,"country":"US"}`)
	yesApp := responseAt(app, `<title>ChatGPT</title><a href="https://auth.openai.com/authorize">Log in</a>`)
	noWeb := responseAt(web, `{"error":{"code":"unsupported_country"}}`)
	noWeb.Status = 403
	noApp := responseAt(app, `ChatGPT is not available in your country`)
	noApp.Status = 403
	failed := Response{Err: errors.New("fixture timeout")}
	for _, tc := range []struct {
		name     string
		web, app Response
		want     string
	}{
		{"positive", yesWeb, yesApp, Yes}, {"web_failed", failed, yesApp, "abstain"}, {"app_failed", yesWeb, failed, "abstain"},
		{"both_failed", failed, failed, "abstain"}, {"blocked_and_failed", noWeb, failed, "abstain"},
		{"both_denied", noWeb, noApp, No}, {"app_only", noWeb, yesApp, AppOnly}, {"web_only", yesWeb, noApp, WebOnly},
		{"unknown", responseAt(web, "{}"), yesApp, "abstain"}, {"vpn_mention", yesWeb, responseAt(app, "VPN troubleshooting"), "abstain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := Engine{Get: fx{web: tc.web, app: tc.app}}
			if got := e.Check(context.Background(), []string{"chatgpt"})[0]; got.Status != tc.want {
				t.Fatalf("want %s, got %+v", tc.want, got)
			}
		})
	}
}

func TestExplicitEvidence(t *testing.T) {
	for _, tc := range []struct {
		id, u, body, want string
		status            int
	}{
		{"claude", "https://claude.ai/", `<h1>Log in to Claude</h1>`, Yes, 200},
		{"gemini", "https://gemini.google.com/", `45631641,null,true`, Yes, 200},
		{"meta_ai", "https://www.meta.ai/", `KadabraRootContainer`, Yes, 200},
		{"grok", "https://grok.com/", `not available in your region`, No, 403},
		{"grok", "https://grok.com/", `not available in your region`, "abstain", 503},
		{"perplexity", "https://www.perplexity.ai/", `unsupported browser`, "abstain", 200},
		{"reddit", "https://www.reddit.com/", `blocked by network security`, "abstain", 403},
		{"apple", "https://gspe1-ssl.ls.apple.com/pep/gcc", `US`, Yes, 200},
		{"apple", "https://gspe1-ssl.ls.apple.com/pep/gcc", `!!`, "abstain", 200},
		{"prime", "https://www.primevideo.com/", `{"currentTerritory":"US"}`, "abstain", 200},
		{"prime", "https://www.primevideo.com/", `{"currentTerritory":"US","isServiceRestricted":false}`, Yes, 200},
		{"prime", "https://www.primevideo.com/", `{"currentTerritory":"US","isServiceRestricted":false,"message":"not available in your country"}`, "abstain", 200},
		{"google_captcha", "https://www.google.com/search?q=ipd", `<div id="search"><a href="https://example.com">result</a></div>`, Yes, 200},
		{"google_captcha", "https://www.google.com/search?q=ipd", `unusual traffic g-recaptcha`, "abstain", 200},
	} {
		t.Run(tc.id+"/"+tc.body, func(t *testing.T) {
			r := responseAt(tc.u, tc.body)
			r.Status = tc.status
			e := Engine{Get: fx{tc.u: r}}
			if got := e.Check(context.Background(), []string{tc.id})[0]; got.Status != tc.want {
				t.Fatalf("want %s, got %+v", tc.want, got)
			}
		})
	}
}

func TestMultiRequestChecksAbstainOnPartialFailure(t *testing.T) {
	for _, id := range []string{"netflix", "tiktok", "google_region"} {
		t.Run(id, func(t *testing.T) {
			calls := 0
			e := Engine{Get: getterFunc(func(u string, _ map[string]string) Response {
				calls++
				if calls == 2 {
					return Response{Err: errors.New("fixture timeout")}
				}
				return responseAt(u, `<form action="/search"><input name="q"></form> "isPlayable":true "country":"US"`)
			})}
			if got := e.Check(context.Background(), []string{id})[0]; got.Status != "abstain" {
				t.Fatalf("%+v", got)
			}
		})
	}
}

func TestGoogleRegionEvidence(t *testing.T) {
	const google = "https://www.google.com/"
	const yt = "https://www.youtube.com/premium"
	const play = "https://play.google.com/store"
	for _, tc := range []struct{ name, final, body, want string }{
		{"positive", google, `<form action="/search"><input name="q"></form>`, Yes},
		{"china_redirect", "https://www.google.com.hk/", `Google`, No},
		{"link_is_not_redirect", google, `<a href="https://google.com.hk/">other region</a>`, "abstain"},
		{"spoof_host", "https://www.google.com.hk.example.invalid/", `Google`, "abstain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := Engine{Get: fx{google: responseAt(tc.final, tc.body), yt: responseAt(yt, `"INNERTUBE_CONTEXT_GL":"US"`), play: responseAt(play, `{"country":"US"}`)}}
			if got := e.Check(context.Background(), []string{"google_region"})[0]; got.Status != tc.want {
				t.Fatalf("want %s, got %+v", tc.want, got)
			}
		})
	}
}

func TestRegionTraceFailureAbstains(t *testing.T) {
	for _, id := range []string{"claude", "chatgpt"} {
		t.Run(id, func(t *testing.T) {
			e := Engine{Get: getterFunc(func(u string, _ map[string]string) Response {
				body := `<h1>Log in to Claude</h1>`
				switch u {
				case "https://api.openai.com/compliance/cookie_requirements":
					body = `{"requires_cookie_consent":false,"country":"US"}`
				case "https://ios.chat.openai.com/":
					body = `<title>ChatGPT</title><a href="https://auth.openai.com/authorize">Log in</a>`
				}
				if strings.Contains(u, "cdn-cgi/trace") {
					return Response{Err: errors.New("fixture trace timeout")}
				}
				return responseAt(u, body)
			})}
			if got := e.Check(context.Background(), []string{id})[0]; got.Status != "abstain" {
				t.Fatalf("%+v", got)
			}
		})
	}
}

func TestNetflixRecognizedTitles(t *testing.T) {
	const original = "https://www.netflix.com/title/81280792"
	const licensed = "https://www.netflix.com/title/70143836"
	for _, tc := range []struct{ name, orig, other, want string }{
		{"both_playable", `{"isPlayable":true}`, `{"isPlayable":true}`, Yes},
		{"both_denied", "not available in your country", "not available in your country", No},
		{"generic_unavailable", "unavailable", "unavailable", "abstain"},
		{"redesign_with_country", `{"country":"US"}`, `{"country":"US"}`, "abstain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := Engine{Get: fx{original: responseAt(original, tc.orig), licensed: responseAt(licensed, tc.other)}}
			if got := e.Check(context.Background(), []string{"netflix"})[0]; got.Status != tc.want {
				t.Fatalf("want %s, got %+v", tc.want, got)
			}
		})
	}
}
