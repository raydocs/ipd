// Package unlock checks whether an egress can use AI and streaming services.
// The decisions follow publicly documented HTTP behavior. Region Restriction
// Check is MIT and is credited in NOTICE; this package does not copy that
// program. IPQuality is not copied.
package unlock

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Status values.
const (
	Abstain       = "abstain"
	Yes           = "yes"
	No            = "no"
	Partial       = "partial"
	OriginalsOnly = "originals_only"
	AppOnly       = "app_only"
	WebOnly       = "web_only"
	IDC           = "idc"
	ErrStatus     = "error"
)

// Result is one service.
type Result struct {
	Service    string `json:"service"`
	Status     string `json:"status"`
	Region     string `json:"region,omitempty"`
	Method     string `json:"method,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
	GoogleTLD  string `json:"google_tld,omitempty"`
	YouTubeGL  string `json:"youtube_gl,omitempty"`
	PlayRegion string `json:"play_region,omitempty"`
}

// Response is what a checker sees. The live client follows redirects and
// records the final URL. Compression is not automatic, so Accept-Encoding is
// under the checker's control.
type Response struct {
	Status   int
	Body     string
	FinalURL string
	Header   http.Header
	Err      error
}

// Getter performs one HTTP GET.
type Getter interface {
	Get(ctx context.Context, rawURL string, headers map[string]string) Response
}

// Engine runs the catalogue.
type Engine struct {
	Get Getter
	// Resolve compares a name via the system resolver and via DoH.
	// It returns method "native" or "dns".
	Resolve func(ctx context.Context, host string) string
}

// Catalogue is the supported service ids, in display order.
func Catalogue() []string {
	return []string{
		"claude", "chatgpt", "gemini", "grok", "copilot", "meta_ai", "perplexity",
		"tiktok", "netflix", "disney", "youtube_premium", "youtube_cdn", "prime",
		"hbo_max", "hulu", "spotify", "reddit", "bing", "apple", "google_region",
		"google_captcha", "wikipedia", "steam", "instagram_music", "bbc_iplayer",
		"bahamut", "abema",
	}
}

// Check runs one service or all of them when ids is empty.
func (e *Engine) Check(ctx context.Context, ids []string) []Result {
	if e == nil || e.Get == nil {
		return []Result{{Service: "engine", Status: ErrStatus, Evidence: "no http client"}}
	}
	if len(ids) == 0 {
		ids = Catalogue()
	}
	out := make([]Result, 0, len(ids))
	for _, id := range ids {
		out = append(out, e.one(ctx, id))
	}
	return out
}

func (e *Engine) one(ctx context.Context, id string) Result {
	switch id {
	case "claude":
		return e.claude(ctx)
	case "chatgpt":
		return e.chatgpt(ctx)
	case "gemini":
		return e.gemini(ctx)
	case "tiktok":
		return e.tiktok(ctx)
	case "netflix":
		return e.netflix(ctx)
	case "google_region":
		return e.googleRegion(ctx)
	case "google_captcha":
		return e.captcha(ctx)
	default:
		if spec, ok := simple[id]; ok {
			return e.simple(ctx, spec)
		}
		return Result{Service: id, Status: ErrStatus, Evidence: "unknown service"}
	}
}

// assess requires recognizable evidence on an expected, non-challenge response.
// A regional denial may legitimately use 403/451; other HTTP errors cannot vote.
func assess(r Response, requested string, positive, denial bool, allowed ...string) (string, string) {
	if issue := responseIssue(r, requested, allowed...); issue != "" {
		return Abstain, issue
	}
	if positive && denial {
		return Abstain, "conflicting availability markers"
	}
	if denial {
		return No, "explicit regional denial"
	}
	if r.Status < 200 || r.Status >= 300 {
		return Abstain, fmt.Sprintf("http status %d without regional denial", r.Status)
	}
	if positive {
		return Yes, "recognized positive marker"
	}
	return Abstain, "unrecognized response; no availability evidence"
}

func responseIssue(r Response, requested string, allowed ...string) string {
	if r.Err != nil {
		return "request failed: " + r.Err.Error()
	}
	if (r.Status < 200 || r.Status >= 300) && r.Status != 403 && r.Status != 451 {
		return fmt.Sprintf("unexpected http status %d", r.Status)
	}
	final, err := url.Parse(r.FinalURL)
	if err != nil || final.Scheme != "https" || final.User != nil {
		return "missing or unexpected final URL"
	}
	expected := append([]string{requested}, allowed...)
	match := false
	for _, raw := range expected {
		u, err := url.Parse(raw)
		if err == nil && strings.EqualFold(final.Host, u.Host) && strings.TrimRight(final.EscapedPath(), "/") == strings.TrimRight(u.EscapedPath(), "/") && final.RawQuery == u.RawQuery {
			match = true
			break
		}
	}
	if !match {
		return "unexpected redirect"
	}
	if strings.TrimSpace(r.Body) == "" {
		return "empty response"
	}
	if strings.EqualFold(r.Header.Get("Cf-Mitigated"), "challenge") {
		return "captcha or challenge response"
	}
	low := strings.ToLower(r.Body)
	for _, marker := range []string{"cf-turnstile", "checking your browser", "verify your browser", "enable javascript and cookies to continue", "cf-chl-", "/cdn-cgi/challenge-platform", "just a moment", "g-recaptcha", "hcaptcha", "unusual traffic", "verify you are human", "verify that you are human", "captcha", "challenge-platform"} {
		if strings.Contains(low, marker) {
			return "captcha or challenge response"
		}
	}
	return ""
}

func regionalDenial(body string) bool {
	low := strings.ToLower(body)
	for _, marker := range []string{"not available in your country", "not available in your region", "unavailable in your region", "unsupported country", "unsupported_country", "unsupported region", "unsupported location", "not available in your location"} {
		if strings.Contains(low, marker) {
			return true
		}
	}
	return false
}

func (e *Engine) claude(ctx context.Context) Result {
	const u = "https://claude.ai/"
	r := e.Get.Get(ctx, u, browser())
	status, evidence := assess(r, u, strings.Contains(r.Body, "Log in to Claude"), strings.Contains(r.Body, "app-unavailable-in-region") || r.FinalURL == "https://claude.ai/app-unavailable-in-region", "https://claude.ai/app-unavailable-in-region")
	out := Result{Service: "claude", Status: status, Evidence: evidence}
	if status != Abstain {
		out.Method = e.method(ctx, "claude.ai")
		out.Region = e.traceRegion(ctx, "https://claude.ai/cdn-cgi/trace")
		if out.Region == "" {
			return Result{Service: "claude", Status: Abstain, Evidence: "region trace failed or was unrecognized"}
		}
	}
	return out
}

func (e *Engine) chatgpt(ctx context.Context) Result {
	const webURL = "https://api.openai.com/compliance/cookie_requirements"
	const appURL = "https://ios.chat.openai.com/"
	web := e.Get.Get(ctx, webURL, browser())
	app := e.Get.Get(ctx, appURL, browser())
	var cookie struct {
		RequiresCookieConsent *bool  `json:"requires_cookie_consent"`
		Country               string `json:"country"`
	}
	webPositive := json.Unmarshal([]byte(web.Body), &cookie) == nil && cookie.RequiresCookieConsent != nil && countryCode.MatchString(cookie.Country)
	appPositive := strings.Contains(app.Body, "ChatGPT") && strings.Contains(app.Body, `href="https://auth.openai.com/authorize`)
	ws, we := assess(web, webURL, webPositive, regionalDenial(web.Body))
	as, ae := assess(app, appURL, appPositive, regionalDenial(app.Body))
	if ws == Abstain || as == Abstain {
		return Result{Service: "chatgpt", Status: Abstain, Evidence: "web: " + we + "; app: " + ae}
	}
	status := Yes
	switch {
	case ws == No && as == No:
		status = No
	case ws == No:
		status = AppOnly
	case as == No:
		status = WebOnly
	}
	region := e.traceRegion(ctx, "https://chatgpt.com/cdn-cgi/trace")
	if region == "" {
		return Result{Service: "chatgpt", Status: Abstain, Evidence: "region trace failed or was unrecognized"}
	}
	return Result{Service: "chatgpt", Status: status, Region: region, Method: e.method(ctx, "chatgpt.com"), Evidence: "web=" + ws + " app=" + as}
}

var countryCode = regexp.MustCompile(`^[A-Z]{2}$`)

func (e *Engine) gemini(ctx context.Context) Result {
	const u = "https://gemini.google.com/"
	r := e.Get.Get(ctx, u, browser())
	status, evidence := assess(r, u, strings.Contains(r.Body, "45631641,null,true"), regionalDenial(r.Body))
	out := Result{Service: "gemini", Status: status, Evidence: evidence}
	if status != Abstain {
		out.Method = e.method(ctx, "gemini.google.com")
		if m := regexp.MustCompile(`,2,1,200,"([A-Z]{2,3})"`).FindStringSubmatch(r.Body); len(m) == 2 {
			out.Region = m[1]
		}
	}
	return out
}

func (e *Engine) tiktok(ctx context.Context) Result {
	const u = "https://www.tiktok.com/"
	h := browser()
	first := e.Get.Get(ctx, u, h)
	status, evidence := assess(first, u, regionField(first.Body) != "", regionalDenial(first.Body))
	if status != Abstain {
		return Result{Service: "tiktok", Status: status, Region: regionField(first.Body), Method: e.method(ctx, "www.tiktok.com"), Evidence: evidence}
	}
	// Only retry an otherwise healthy, unrecognized page. A failed first request
	// must not be hidden by a successful fallback.
	if issue := responseIssue(first, u); issue != "" || first.Status != http.StatusOK {
		return Result{Service: "tiktok", Status: Abstain, Evidence: evidence}
	}
	h["Accept-Encoding"] = "gzip"
	second := e.Get.Get(ctx, u, h)
	secondStatus, secondEvidence := assess(second, u, regionField(second.Body) != "", regionalDenial(second.Body))
	if secondStatus == Yes {
		return Result{Service: "tiktok", Status: IDC, Region: regionField(second.Body), Method: e.method(ctx, "www.tiktok.com"), Evidence: "region only present when gzip is requested"}
	}
	return Result{Service: "tiktok", Status: Abstain, Evidence: "first: " + evidence + "; fallback: " + secondEvidence}
}

var regionRe = regexp.MustCompile(`"region"\s*:\s*"([A-Z]{2})"`)

func regionField(body string) string {
	m := regionRe.FindStringSubmatch(body)
	if len(m) == 2 {
		return m[1]
	}
	return ""
}

func (e *Engine) netflix(ctx context.Context) Result {
	const original = "https://www.netflix.com/title/81280792"
	const licensed = "https://www.netflix.com/title/70143836"
	orig := e.Get.Get(ctx, original, browser())
	other := e.Get.Get(ctx, licensed, browser())
	os, oe := assess(orig, original, availableTitle(orig.Body), regionalDenial(orig.Body))
	ls, le := assess(other, licensed, availableTitle(other.Body), regionalDenial(other.Body))
	if os == Abstain || ls == Abstain {
		return Result{Service: "netflix", Status: Abstain, Evidence: "original: " + oe + "; licensed: " + le}
	}
	status := Partial
	switch {
	case os == Yes && ls == Yes:
		status = Yes
	case os == Yes && ls == No:
		status = OriginalsOnly
	case os == No && ls == No:
		status = No
	}
	return Result{Service: "netflix", Status: status, Region: netflixRegion(orig.Body + other.Body), Method: e.method(ctx, "www.netflix.com"), Evidence: "original=" + os + " licensed=" + ls}
}

func availableTitle(body string) bool {
	return regexp.MustCompile(`"isPlayable"\s*:\s*true`).MatchString(body)
}

func netflixRegion(body string) string {
	if m := regexp.MustCompile(`"country"\s*:\s*"([A-Z]{2})"`).FindStringSubmatch(body); len(m) == 2 {
		return m[1]
	}
	return ""
}

func (e *Engine) googleRegion(ctx context.Context) Result {
	const google = "https://www.google.com/"
	const youtube = "https://www.youtube.com/premium"
	const store = "https://play.google.com/store"
	r := e.Get.Get(ctx, google, browser())
	yt := e.Get.Get(ctx, youtube, browser())
	play := e.Get.Get(ctx, store, browser())
	for _, check := range []struct {
		r       Response
		u       string
		allowed []string
	}{
		{r, google, []string{"https://www.google.cn/", "https://google.cn/", "https://www.google.com.hk/", "https://google.com.hk/"}},
		{yt, youtube, nil}, {play, store, nil},
	} {
		if issue := responseIssue(check.r, check.u, check.allowed...); issue != "" {
			return Result{Service: "google_region", Status: Abstain, Evidence: check.u + ": " + issue}
		}
		if check.r.Status < 200 || check.r.Status >= 300 {
			return Result{Service: "google_region", Status: Abstain, Evidence: "google region request did not succeed"}
		}
	}
	final, _ := url.Parse(r.FinalURL) // validated above, exact host matching only
	tld := strings.TrimPrefix(strings.ToLower(final.Hostname()), "www.")
	sent := tld == "google.cn" || tld == "google.com.hk"
	gl, playRegion := "", ""
	if m := regexp.MustCompile(`INNERTUBE_CONTEXT_GL["']?\s*[:=]\s*["']([A-Z]{2})`).FindStringSubmatch(yt.Body); len(m) == 2 {
		gl = m[1]
	}
	if m := regexp.MustCompile(`"country"\s*:\s*"([A-Z]{2})"`).FindStringSubmatch(play.Body); len(m) == 2 {
		playRegion = m[1]
	}
	googlePositive := strings.Contains(r.Body, `name="q"`) && strings.Contains(r.Body, "/search")
	if (!sent && !googlePositive) || gl == "" || playRegion == "" {
		return Result{Service: "google_region", Status: Abstain, Evidence: "unrecognized Google, YouTube or Play region response"}
	}
	// Non-China evidence must agree; disagreement cannot establish a clean region.
	if !sent && gl != playRegion {
		return Result{Service: "google_region", Status: Abstain, Evidence: "conflicting YouTube and Play regions"}
	}
	sent = sent || gl == "CN" || playRegion == "CN"
	status := Yes
	if sent {
		status = No
	}
	return Result{Service: "google_region", Status: status, Region: gl, GoogleTLD: tld, YouTubeGL: gl, PlayRegion: playRegion, Method: "native", Evidence: "google tld " + tld + " sent_to_china=" + boolStr(sent)}
}

func (e *Engine) captcha(ctx context.Context) Result {
	const u = "https://www.google.com/search?q=ipd"
	r := e.Get.Get(ctx, u, browser())
	positive := strings.Contains(r.Body, `id="search"`) && strings.Contains(r.Body, "href=")
	status, evidence := assess(r, u, positive, false)
	return Result{Service: "google_captcha", Status: status, Evidence: evidence, Method: "native"}
}

type simpleSpec struct {
	id, url, yes, no string
	host             string
}

var simple = map[string]simpleSpec{
	"grok":            {id: "grok", url: "https://grok.com/", host: "grok.com", no: "not available in your region|unsupported region|unavailable in your region"},
	"copilot":         {id: "copilot", url: "https://copilot.microsoft.com/", host: "copilot.microsoft.com", no: "not available in your region|unavailable in your region"},
	"meta_ai":         {id: "meta_ai", url: "https://www.meta.ai/", host: "www.meta.ai", yes: "KadabraRootContainer", no: "AbraGeoBlockedErrorRoot"},
	"perplexity":      {id: "perplexity", url: "https://www.perplexity.ai/", host: "www.perplexity.ai", no: "not available in your region"},
	"disney":          {id: "disney", url: "https://www.disneyplus.com/", host: "www.disneyplus.com", no: "not available in your region|unsupported location"},
	"youtube_premium": {id: "youtube_premium", url: "https://www.youtube.com/premium", host: "www.youtube.com", no: "not available in your country"},
	"youtube_cdn":     {id: "youtube_cdn", url: "https://redirector.googlevideo.com/report_mapping?di=no", host: "redirector.googlevideo.com"},
	"prime":           {id: "prime", url: "https://www.primevideo.com/", host: "www.primevideo.com", no: "isServiceRestricted\":true|not available in your country"},
	"hbo_max":         {id: "hbo_max", url: "https://www.max.com/", host: "www.max.com", no: "not available in your region|geo-blocked"},
	"hulu":            {id: "hulu", url: "https://www.hulu.com/", host: "www.hulu.com", no: "not available in your location|not available in your region"},
	"spotify":         {id: "spotify", url: "https://open.spotify.com/", host: "open.spotify.com", no: "not available in your country"},
	"reddit":          {id: "reddit", url: "https://www.reddit.com/", host: "www.reddit.com"},
	"bing":            {id: "bing", url: "https://www.bing.com/", host: "www.bing.com"},
	"apple":           {id: "apple", url: "https://gspe1-ssl.ls.apple.com/pep/gcc", host: "gspe1-ssl.ls.apple.com"},
	"wikipedia":       {id: "wikipedia", url: "https://en.wikipedia.org/w/index.php?title=Wikipedia:Sandbox&action=edit", host: "en.wikipedia.org"},
	"steam":           {id: "steam", url: "https://store.steampowered.com/", host: "store.steampowered.com"},
	"instagram_music": {id: "instagram_music", url: "https://www.instagram.com/reels/audio/", host: "www.instagram.com", no: "not available in your country"},
	"bbc_iplayer":     {id: "bbc_iplayer", url: "https://www.bbc.co.uk/iplayer", host: "www.bbc.co.uk", no: "not available in your country|outside the uk"},
	"bahamut":         {id: "bahamut", url: "https://ani.gamer.com.tw/", host: "ani.gamer.com.tw", no: "不支援您的地區|not available in your region"},
	"abema":           {id: "abema", url: "https://abema.tv/", host: "abema.tv", no: "not available in your region|お住まいの地域ではご視聴できません"},
}

func (e *Engine) simple(ctx context.Context, spec simpleSpec) Result {
	r := e.Get.Get(ctx, spec.url, browser())
	positive := spec.yes != "" && strings.Contains(r.Body, spec.yes)
	denial := regionalDenial(r.Body)
	for _, marker := range strings.Split(spec.no, "|") {
		if marker != "" && strings.Contains(strings.ToLower(r.Body), strings.ToLower(marker)) {
			denial = true
		}
	}
	region := ""
	switch spec.id {
	case "apple":
		cc := strings.TrimSpace(r.Body)
		if countryCode.MatchString(cc) {
			positive = true
			region = cc
		}
	case "youtube_cdn":
		if m := regexp.MustCompile(`country=([A-Z]{2})\b`).FindStringSubmatch(r.Body); len(m) == 2 {
			positive = true
			region = m[1]
		}
	case "steam":
		if m := regexp.MustCompile(`"currency"\s*:\s*"([A-Z]{3})"`).FindStringSubmatch(r.Body); len(m) == 2 {
			positive = true
			region = m[1]
		}
	case "prime":
		var territory struct {
			Country    string `json:"currentTerritory"`
			Restricted *bool  `json:"isServiceRestricted"`
		}
		if json.Unmarshal([]byte(r.Body), &territory) == nil && countryCode.MatchString(territory.Country) && territory.Restricted != nil {
			positive = !*territory.Restricted
			denial = denial || *territory.Restricted
			region = territory.Country
		}
	}
	status, evidence := assess(r, spec.url, positive, denial)
	out := Result{Service: spec.id, Status: status, Evidence: evidence}
	if status != Abstain {
		out.Region = first(region, guessRegion(r.Body))
		out.Method = e.method(ctx, spec.host)
	}
	return out
}

func (e *Engine) method(ctx context.Context, host string) string {
	if e.Resolve == nil {
		return "native"
	}
	m := e.Resolve(ctx, host)
	if m == "" {
		return "native"
	}
	return m
}

func (e *Engine) traceRegion(ctx context.Context, u string) string {
	r := e.Get.Get(ctx, u, nil)
	if responseIssue(r, u) != "" || r.Status != http.StatusOK {
		return ""
	}
	for _, line := range strings.Split(r.Body, "\n") {
		if strings.HasPrefix(line, "loc=") {
			cc := strings.TrimPrefix(line, "loc=")
			if countryCode.MatchString(cc) {
				return cc
			}
		}
	}
	return ""
}

func guessRegion(body string) string {
	if m := regexp.MustCompile(`"region"\s*:\s*"([A-Z]{2})"`).FindStringSubmatch(body); len(m) == 2 {
		return m[1]
	}
	return ""
}

func browser() map[string]string {
	return map[string]string{
		"User-Agent": "Mozilla/5.0 (compatible; ipd/0.9)",
		"Accept":     "text/html,application/json",
	}
}

func first(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// LiveGetter is the production HTTP client. DisableCompression keeps
// Accept-Encoding under the checker's control.
type LiveGetter struct {
	Client *http.Client
}

func (g LiveGetter) Get(ctx context.Context, rawURL string, headers map[string]string) Response {
	c := g.Client
	if c == nil {
		c = &http.Client{Timeout: 12 * time.Second, Transport: &http.Transport{DisableCompression: true}}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return Response{Err: err}
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return Response{Err: err}
	}
	defer resp.Body.Close()
	var reader io.Reader = resp.Body
	encoding := resp.Header.Get("Content-Encoding")
	if encoding != "" && !strings.EqualFold(encoding, "identity") && !strings.EqualFold(encoding, "gzip") {
		return Response{Err: fmt.Errorf("unsupported content encoding %q", encoding)}
	}
	if strings.EqualFold(encoding, "gzip") {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return Response{Err: err}
		}
		defer gz.Close()
		reader = gz
	}
	const maxBody = 256 << 10
	b, readErr := io.ReadAll(io.LimitReader(reader, maxBody+1))
	if len(b) > maxBody {
		readErr = fmt.Errorf("response exceeds %d bytes", maxBody)
	}
	final := rawURL
	if resp.Request != nil && resp.Request.URL != nil {
		final = resp.Request.URL.String()
	}
	return Response{Status: resp.StatusCode, Body: string(b), FinalURL: final, Header: resp.Header, Err: readErr}
}

// SentToChina reads a google_region result.
func SentToChina(r Result) bool {
	return r.Service == "google_region" && r.Status == No && strings.Contains(r.Evidence, "sent_to_china=true")
}
