// Package litmus observes bounded public HTTP evidence, never risk or bot scores.
package litmus

import (
	"context"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/html"
	"ipd/internal/unlock"
)

const (
	Abstain        = "abstain"
	Yes            = "yes"
	maxBody        = 256 << 10
	maxHeaders     = 16 << 10
	maxHeaderCount = 64
)

// Target URLs are immutable and never come from user input.
func target(id string) string {
	switch id {
	case "google_search":
		return "https://www.google.com/search?q=ipd"
	case "cloudflare_home":
		return "https://www.cloudflare.com/"
	case "akamai_home":
		return "https://www.akamai.com/"
	}
	return ""
}
func ValidID(id string) bool { return target(id) != "" }

// Marker contains only controlled vocabulary, never snippets.
type Marker struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Provider string `json:"provider"`
}
type Result struct {
	Source            string    `json:"source"`
	Target            string    `json:"target"`
	URL               string    `json:"url"`
	ObservedAt        time.Time `json:"observed_at"`
	HTTPStatus        *int      `json:"http_status"`
	Scope             string    `json:"scope"`
	ProviderPresence  string    `json:"provider_presence"`
	ChallengeObserved string    `json:"challenge_observed"`
	CaptchaObserved   string    `json:"captcha_observed"`
	Reason            string    `json:"reason"`
	MatchedMarkers    []Marker  `json:"matched_markers"`
	CFBotScore        *int      `json:"cf_bot_score"`
	CFBotScoreReason  string    `json:"cf_bot_score_reason"`
}

// Engine reuses unlock's Getter/Response contract, not its availability verdict:
// unlock.responseIssue intentionally abstains on challenges; captcha is an
// availability check, not affirmative challenge evidence. Neither is weakened.
type Engine struct{ Get unlock.Getter }

func (e Engine) Check(ctx context.Context, id string, offline bool) Result {
	u := target(id)
	r := Result{Source: "public_http", Target: id, URL: u, ObservedAt: time.Now().UTC(),
		Scope: "single_response_known_markers_only", ProviderPresence: Abstain, ChallengeObserved: Abstain, CaptchaObserved: Abstain,
		Reason: "unknown_template", MatchedMarkers: []Marker{}, CFBotScoreReason: "unavailable_public_observation"}
	if u == "" {
		r.Target = ""
		r.Reason = "invalid_target"
		return r
	}
	if offline {
		r.Reason = "offline"
		return r
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	g := e.Get
	if g == nil {
		g = liveGetter{}
	}
	resp := g.Get(ctx, u, map[string]string{"User-Agent": "ipd-litmus/1", "Accept-Encoding": "gzip"})
	r.ObservedAt = time.Now().UTC()
	if resp.Status >= 100 && resp.Status <= 599 {
		s := resp.Status
		r.HTTPStatus = &s
	}
	switch {
	case ctx.Err() != nil:
		r.Reason = "timeout"
	case resp.Err != nil:
		r.Reason = "request_failed"
	case resp.FinalURL != u:
		r.Reason = "unexpected_redirect"
	case !headersOK(resp.Header):
		r.Reason = "header_limit"
	case !encodingOK(resp.Header):
		r.Reason = "unsupported_encoding"
	case len(resp.Body) > maxBody:
		r.Reason = "body_limit"
	case strings.TrimSpace(resp.Body) == "":
		r.Reason = "empty_response"
	case (resp.Status < 200 || resp.Status >= 300) && resp.Status != 403 && resp.Status != 429:
		r.Reason = "unexpected_status"
	default:
		return detect(r, resp)
	}
	return r
}

func headersOK(h http.Header) bool {
	n, size := 0, 0
	for k, vs := range h {
		size += len(k)
		for _, v := range vs {
			n++
			size += len(v) + 4
		}
	}
	return n <= maxHeaderCount && size <= maxHeaders
}
func encodingOK(h http.Header) bool {
	vs := h.Values("Content-Encoding")
	if len(vs) == 0 {
		return true
	}
	if len(vs) != 1 {
		return false
	}
	v := strings.ToLower(strings.TrimSpace(vs[0]))
	return v == "" || v == "identity" || v == "gzip"
}
func detect(r Result, resp unlock.Response) Result {
	add := func(id, kind, provider string) {
		r.MatchedMarkers = append(r.MatchedMarkers, Marker{id, kind, provider})
	}

	cfServer, akServer := false, false
	for _, v := range resp.Header.Values("Server") {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "cloudflare":
			if !cfServer {
				add("cf_server", "provider_presence", "cloudflare")
			}
			cfServer = true
		case "akamaighost":
			if !akServer {
				add("akamai_server", "provider_presence", "akamai")
			}
			akServer = true
		}
	}
	cf := false
	vals := resp.Header.Values("Cf-Mitigated")
	for _, v := range vals {
		if strings.EqualFold(strings.TrimSpace(v), "challenge") {
			cf = true
		}
	}
	if cf {
		add("cf_mitigated_challenge", "challenge_observed", "cloudflare")
	}
	message, form, widget := googleMarkup(resp.Body)
	google := r.Target == "google_search" && message && form
	if google {
		add("google_unusual_traffic", "challenge_observed", "google")
	}
	captcha := google && widget
	if captcha {
		add("google_recaptcha_widget", "captcha_observed", "google")
	}
	if len(vals) > 1 || (len(vals) == 1 && !cf) || (cf && google) || (google && (cfServer || akServer)) || (cf && akServer) || (cfServer && akServer) {
		r.Reason = "conflicting_markers"
		return r
	}
	if len(r.MatchedMarkers) > 0 {
		r.ProviderPresence = Yes
		r.Reason = "presence_only"
	}
	if cf || google {
		r.ChallengeObserved = Yes
		r.Reason = "recognized_challenge"
	}
	if captcha {
		r.CaptchaObserved = Yes
	}
	// No negative inference from absence, HTTP 403/429, generic words or branding.
	return r
}

// googleMarkup ignores comments and script/style text. It requires the known
// traffic message plus an actual Google sorry form; documentation snippets and
// generic CAPTCHA widgets are not enough. Unknown templates remain unknown.
func googleMarkup(body string) (message, form, widget bool) {
	z := html.NewTokenizer(strings.NewReader(body))
	var text strings.Builder
	skip := ""
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		switch tt {
		case html.StartTagToken, html.SelfClosingTagToken:
			tok := z.Token()
			if tok.Data == "script" || tok.Data == "style" {
				skip = tok.Data
			}
			if skip != "" {
				continue
			}
			for _, a := range tok.Attr {
				if tok.Data == "form" && a.Key == "action" && (a.Val == "/sorry/index" || a.Val == "https://www.google.com/sorry/index") {
					form = true
				}
				if tok.Data == "div" && a.Key == "class" {
					for _, c := range strings.Fields(a.Val) {
						if c == "g-recaptcha" {
							widget = true
						}
					}
				}
			}
		case html.EndTagToken:
			tok := z.Token()
			if tok.Data == skip {
				skip = ""
			}
		case html.TextToken:
			if skip == "" {
				text.Write(z.Text())
			}
		}
	}
	message = strings.Contains(strings.ToLower(text.String()), "our systems have detected unusual traffic from your computer network")
	return
}
