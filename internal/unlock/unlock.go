// Package unlock checks whether an egress can use AI and streaming services.
// The decisions follow publicly documented HTTP behavior. Region Restriction
// Check is MIT and is credited in NOTICE; this package does not copy that
// program. IPQuality is not copied.
package unlock

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Status values.
const (
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
	Service  string `json:"service"`
	Status   string `json:"status"`
	Region   string `json:"region,omitempty"`
	Method   string `json:"method,omitempty"`
	Evidence string `json:"evidence,omitempty"`
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

func (e *Engine) claude(ctx context.Context) Result {
	r := e.Get.Get(ctx, "https://claude.ai/", browser())
	if r.Err != nil {
		return Result{Service: "claude", Status: ErrStatus, Evidence: r.Err.Error()}
	}
	final := r.FinalURL
	if strings.Contains(final, "app-unavailable-in-region") || strings.Contains(r.Body, "app-unavailable-in-region") {
		return Result{Service: "claude", Status: No, Evidence: "redirected to app-unavailable-in-region", Method: e.method(ctx, "claude.ai")}
	}
	if r.Status >= 400 {
		return Result{Service: "claude", Status: No, Evidence: "http error", Method: "native"}
	}
	region := e.traceRegion(ctx, "https://claude.ai/cdn-cgi/trace")
	return Result{Service: "claude", Status: Yes, Region: region, Method: e.method(ctx, "claude.ai"), Evidence: "claude.ai stayed on claude.ai"}
}

func (e *Engine) chatgpt(ctx context.Context) Result {
	web := e.Get.Get(ctx, "https://api.openai.com/compliance/cookie_requirements", browser())
	app := e.Get.Get(ctx, "https://ios.chat.openai.com/", browser())
	if web.Err != nil && app.Err != nil {
		return Result{Service: "chatgpt", Status: ErrStatus, Evidence: web.Err.Error()}
	}
	webNo := strings.Contains(web.Body, "unsupported_country")
	appNo := strings.Contains(app.Body, "VPN") || strings.Contains(strings.ToLower(app.Body), "not available")
	region := e.traceRegion(ctx, "https://chatgpt.com/cdn-cgi/trace")
	method := e.method(ctx, "chatgpt.com")
	switch {
	case webNo && appNo:
		return Result{Service: "chatgpt", Status: No, Region: region, Method: method, Evidence: "web unsupported_country and app blocked"}
	case webNo && !appNo:
		return Result{Service: "chatgpt", Status: AppOnly, Region: region, Method: method, Evidence: "web unsupported, app open"}
	case !webNo && appNo:
		return Result{Service: "chatgpt", Status: WebOnly, Region: region, Method: method, Evidence: "app blocked, web open"}
	default:
		return Result{Service: "chatgpt", Status: Yes, Region: region, Method: method, Evidence: "web and app open"}
	}
}

func (e *Engine) gemini(ctx context.Context) Result {
	r := e.Get.Get(ctx, "https://gemini.google.com/", browser())
	if r.Err != nil {
		return Result{Service: "gemini", Status: ErrStatus, Evidence: r.Err.Error()}
	}
	if strings.Contains(r.Body, "45631641,null,true") || strings.Contains(r.Body, "gemini") && r.Status < 400 && !strings.Contains(strings.ToLower(r.Body), "not available") {
		region := ""
		if m := regexp.MustCompile(`,2,1,200,"([A-Z]{2,3})"`).FindStringSubmatch(r.Body); len(m) == 2 {
			region = m[1]
		}
		return Result{Service: "gemini", Status: Yes, Region: region, Method: e.method(ctx, "gemini.google.com"), Evidence: "gemini page available"}
	}
	return Result{Service: "gemini", Status: No, Method: e.method(ctx, "gemini.google.com"), Evidence: "gemini unavailable marker"}
}

func (e *Engine) tiktok(ctx context.Context) Result {
	h := browser()
	delete(h, "Accept-Encoding")
	first := e.Get.Get(ctx, "https://www.tiktok.com/", h)
	region := regionField(first.Body)
	if region == "" {
		h2 := browser()
		h2["Accept-Encoding"] = "gzip"
		second := e.Get.Get(ctx, "https://www.tiktok.com/", h2)
		region = regionField(second.Body)
		if region != "" {
			return Result{Service: "tiktok", Status: IDC, Region: region, Method: e.method(ctx, "www.tiktok.com"), Evidence: "region only present when gzip is requested"}
		}
		if first.Err != nil {
			return Result{Service: "tiktok", Status: ErrStatus, Evidence: first.Err.Error()}
		}
		return Result{Service: "tiktok", Status: No, Method: e.method(ctx, "www.tiktok.com"), Evidence: "no region in the page"}
	}
	return Result{Service: "tiktok", Status: Yes, Region: region, Method: e.method(ctx, "www.tiktok.com"), Evidence: "region in the first response"}
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
	orig := e.Get.Get(ctx, "https://www.netflix.com/title/81280792", browser())
	other := e.Get.Get(ctx, "https://www.netflix.com/title/70143836", browser())
	if orig.Err != nil && other.Err != nil {
		return Result{Service: "netflix", Status: ErrStatus, Evidence: orig.Err.Error()}
	}
	origOK := availableTitle(orig.Body, orig.Status)
	otherOK := availableTitle(other.Body, other.Status)
	region := netflixRegion(orig.Body + other.Body)
	method := e.method(ctx, "www.netflix.com")
	switch {
	case origOK && otherOK:
		return Result{Service: "netflix", Status: Yes, Region: region, Method: method, Evidence: "original and licensed titles play"}
	case origOK && !otherOK:
		return Result{Service: "netflix", Status: OriginalsOnly, Region: region, Method: method, Evidence: "only the Netflix original title is available"}
	default:
		return Result{Service: "netflix", Status: No, Region: region, Method: method, Evidence: "titles unavailable"}
	}
}

func availableTitle(body string, status int) bool {
	l := strings.ToLower(body)
	if strings.Contains(l, "oh no") || strings.Contains(l, "not available") || strings.Contains(l, "unavailable") {
		return false
	}
	return status > 0 && status < 400 && body != ""
}

func netflixRegion(body string) string {
	if m := regexp.MustCompile(`"country"\s*:\s*"([A-Z]{2})"`).FindStringSubmatch(body); len(m) == 2 {
		return m[1]
	}
	return ""
}

func (e *Engine) googleRegion(ctx context.Context) Result {
	r := e.Get.Get(ctx, "https://www.google.com/", browser())
	yt := e.Get.Get(ctx, "https://www.youtube.com/premium", browser())
	play := e.Get.Get(ctx, "https://play.google.com/store", browser())
	final := strings.ToLower(r.FinalURL + " " + yt.FinalURL)
	sent := strings.Contains(final, "google.cn") || strings.Contains(final, "google.com.hk") || strings.Contains(strings.ToLower(r.Body), "google.com.hk")
	tld := "google.com"
	if strings.Contains(final, "google.cn") {
		tld = "google.cn"
	} else if strings.Contains(final, "google.com.hk") {
		tld = "google.com.hk"
	}
	gl := ""
	if m := regexp.MustCompile(`INNERTUBE_CONTEXT_GL["']?\s*[:=]\s*["']([A-Z]{2})`).FindStringSubmatch(yt.Body); len(m) == 2 {
		gl = m[1]
	}
	playRegion := ""
	if m := regexp.MustCompile(`"country"\s*:\s*"([A-Z]{2})"`).FindStringSubmatch(play.Body); len(m) == 2 {
		playRegion = m[1]
	}
	status := Yes
	if sent || gl == "CN" || playRegion == "CN" {
		status = No
		sent = true
	}
	ev := "google tld " + tld
	return Result{Service: "google_region", Status: status, Region: first(gl, playRegion), Method: "native", Evidence: ev + " sent_to_china=" + boolStr(sent)}
}

func (e *Engine) captcha(ctx context.Context) Result {
	r := e.Get.Get(ctx, "https://www.google.com/search?q=ipd", browser())
	if r.Err != nil {
		return Result{Service: "google_captcha", Status: ErrStatus, Evidence: r.Err.Error()}
	}
	if strings.Contains(strings.ToLower(r.Body), "unusual traffic") || strings.Contains(r.Body, "g-recaptcha") {
		return Result{Service: "google_captcha", Status: No, Evidence: "unusual traffic interstitial", Method: "native"}
	}
	return Result{Service: "google_captcha", Status: Yes, Evidence: "no captcha interstitial", Method: "native"}
}

type simpleSpec struct {
	id, url, yes, no string
	host             string
}

var simple = map[string]simpleSpec{
	"grok":            {id: "grok", url: "https://grok.com/", host: "grok.com", no: "not available in your region|unsupported region|unavailable in your"},
	"copilot":         {id: "copilot", url: "https://copilot.microsoft.com/", host: "copilot.microsoft.com", no: "not available|unavailable in your region"},
	"meta_ai":         {id: "meta_ai", url: "https://www.meta.ai/", host: "www.meta.ai", yes: "KadabraRootContainer", no: "AbraGeoBlockedErrorRoot"},
	"perplexity":      {id: "perplexity", url: "https://www.perplexity.ai/", host: "www.perplexity.ai", no: "unsupported|not available in your region"},
	"disney":          {id: "disney", url: "https://www.disneyplus.com/", host: "www.disneyplus.com", no: "not available in your region|unsupported location"},
	"youtube_premium": {id: "youtube_premium", url: "https://www.youtube.com/premium", host: "www.youtube.com", no: "not available in your country|google.cn|google.com.hk"},
	"youtube_cdn":     {id: "youtube_cdn", url: "https://redirector.googlevideo.com/report_mapping?di=no", host: "redirector.googlevideo.com"},
	"prime":           {id: "prime", url: "https://www.primevideo.com/", host: "www.primevideo.com", no: "isServiceRestricted\":true|not available"},
	"hbo_max":         {id: "hbo_max", url: "https://www.max.com/", host: "www.max.com", no: "not available in your region|geo-blocked"},
	"hulu":            {id: "hulu", url: "https://www.hulu.com/", host: "www.hulu.com", no: "not available in your location|geographic"},
	"spotify":         {id: "spotify", url: "https://open.spotify.com/", host: "open.spotify.com", no: "not available in your country"},
	"reddit":          {id: "reddit", url: "https://www.reddit.com/", host: "www.reddit.com", no: "blocked by network security|you've been blocked"},
	"bing":            {id: "bing", url: "https://www.bing.com/", host: "www.bing.com", no: "cn.bing.com"},
	"apple":           {id: "apple", url: "https://gspe1-ssl.ls.apple.com/pep/gcc", host: "gspe1-ssl.ls.apple.com"},
	"wikipedia":       {id: "wikipedia", url: "https://en.wikipedia.org/w/index.php?title=Wikipedia:Sandbox&action=edit", host: "en.wikipedia.org", no: "editing restricted|you are not allowed"},
	"steam":           {id: "steam", url: "https://store.steampowered.com/", host: "store.steampowered.com"},
	"instagram_music": {id: "instagram_music", url: "https://www.instagram.com/reels/audio/", host: "www.instagram.com", no: "not available"},
	"bbc_iplayer":     {id: "bbc_iplayer", url: "https://www.bbc.co.uk/iplayer", host: "www.bbc.co.uk", no: "not available|outside the uk"},
	"bahamut":         {id: "bahamut", url: "https://ani.gamer.com.tw/", host: "ani.gamer.com.tw", no: "不支援您的地區|not available"},
	"abema":           {id: "abema", url: "https://abema.tv/", host: "abema.tv", no: "not available in your region|海外"},
}

func (e *Engine) simple(ctx context.Context, spec simpleSpec) Result {
	r := e.Get.Get(ctx, spec.url, browser())
	if r.Err != nil {
		return Result{Service: spec.id, Status: ErrStatus, Evidence: r.Err.Error()}
	}
	body := r.Body + " " + r.FinalURL
	low := strings.ToLower(body)
	if spec.yes != "" && strings.Contains(body, spec.yes) {
		return Result{Service: spec.id, Status: Yes, Region: guessRegion(body), Method: e.method(ctx, spec.host), Evidence: "positive marker"}
	}
	if spec.no != "" {
		for _, part := range strings.Split(spec.no, "|") {
			if part != "" && strings.Contains(low, strings.ToLower(part)) {
				return Result{Service: spec.id, Status: No, Method: e.method(ctx, spec.host), Evidence: "matched " + part}
			}
		}
	}
	if spec.id == "apple" {
		cc := strings.TrimSpace(r.Body)
		if len(cc) >= 2 && len(cc) <= 3 {
			return Result{Service: "apple", Status: Yes, Region: strings.ToUpper(cc[:2]), Method: "native", Evidence: "pep/gcc body"}
		}
	}
	if spec.id == "youtube_cdn" {
		if m := regexp.MustCompile(`country=([A-Z]{2})`).FindStringSubmatch(r.Body); len(m) == 2 {
			return Result{Service: spec.id, Status: Yes, Region: m[1], Method: "native", Evidence: "report_mapping"}
		}
	}
	if spec.id == "steam" {
		if m := regexp.MustCompile(`"currency":"([A-Z]{3})"`).FindStringSubmatch(r.Body); len(m) == 2 {
			return Result{Service: "steam", Status: Yes, Region: m[1], Method: e.method(ctx, spec.host), Evidence: "store currency"}
		}
	}
	if spec.id == "prime" {
		if m := regexp.MustCompile(`"currentTerritory"\s*:\s*"([A-Z]{2})"`).FindStringSubmatch(r.Body); len(m) == 2 {
			restricted := strings.Contains(r.Body, `"isServiceRestricted":true`)
			st := Yes
			if restricted {
				st = No
			}
			return Result{Service: "prime", Status: st, Region: m[1], Method: e.method(ctx, spec.host), Evidence: "currentTerritory"}
		}
	}
	if r.Status >= 400 {
		return Result{Service: spec.id, Status: No, Method: e.method(ctx, spec.host), Evidence: "http status"}
	}
	return Result{Service: spec.id, Status: Yes, Region: guessRegion(body), Method: e.method(ctx, spec.host), Evidence: "no block marker"}
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
	for _, line := range strings.Split(r.Body, "\n") {
		if strings.HasPrefix(line, "loc=") {
			return strings.TrimPrefix(line, "loc=")
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
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	final := rawURL
	if resp.Request != nil && resp.Request.URL != nil {
		final = resp.Request.URL.String()
	}
	return Response{Status: resp.StatusCode, Body: string(b), FinalURL: final, Header: resp.Header}
}

// SentToChina reads a google_region result.
func SentToChina(r Result) bool {
	return strings.Contains(r.Evidence, "sent_to_china=true") || r.Status == No && r.Service == "google_region"
}
