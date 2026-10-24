// Package api is the HTTP surface: content negotiation, OpenAPI, llms.txt, and /mcp.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"ipd/internal/app"
	"ipd/internal/leak"
	"ipd/internal/mcp"
	"ipd/internal/pow"
	"ipd/internal/privacy"
	"ipd/internal/route"
	"ipd/web"
)

// Server is the HTTP application.
type Server struct {
	Svc       *app.Service
	Hub       http.Handler
	lim       *limiter
	purgeMu   sync.Mutex
	lastPurge time.Time
}

// New returns a server. Limits come from configuration.
func New(svc *app.Service) *Server {
	rpm := 60
	if svc.Cfg != nil && svc.Cfg.AnonymousRPM > 0 {
		rpm = svc.Cfg.AnonymousRPM
	}
	return &Server{Svc: svc, lim: newLimiter(rpm)}
}

// Handler is the full mux.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /favicon.ico", s.favicon)
	mux.HandleFunc("GET /favicon.svg", s.favicon)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/plain")
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("GET /v1/pow", s.powChallenge)
	mux.HandleFunc("GET /metrics", s.metrics)
	mux.HandleFunc("GET /openapi.json", s.openapi)
	mux.HandleFunc("GET /llms.txt", s.llms)
	mux.HandleFunc("GET /llms-full.txt", s.llmsFull)
	mux.HandleFunc("GET /v1/methodology", s.methodology)
	mux.HandleFunc("GET /methodology", s.methodology)
	mux.HandleFunc("GET /v1/sources", s.sources)
	mux.HandleFunc("GET /v1/me", s.me)
	mux.HandleFunc("GET /v1/ip/{ip}", s.ip)
	mux.HandleFunc("GET /v1/ip/{ip}/risk", s.risk)
	mux.HandleFunc("GET /v1/ip/{ip}/history", s.history)
	mux.HandleFunc("GET /v1/asn/{asn}", s.asn)
	mux.HandleFunc("GET /v1/prefix/{cidr...}", s.prefix)
	mux.HandleFunc("POST /v1/batch", s.batch)
	mux.HandleFunc("POST /v1/gfw", s.gfw)
	mux.HandleFunc("POST /v1/route", s.route)
	mux.HandleFunc("GET /v1/route/targets", s.targets)
	mux.HandleFunc("POST /v1/latency", s.latency)
	mux.HandleFunc("GET /v1/jobs/{id}", s.job)
	mux.HandleFunc("POST /v1/dnsleak", s.dnsSessionCreate)
	mux.HandleFunc("GET /v1/dnsleak/{token}", s.dnsleak)
	mux.HandleFunc("POST /v1/report", s.report)
	mux.HandleFunc("GET /r/{id}", s.share)
	mux.HandleFunc("POST /v1/watch", s.watchCreate)
	mux.HandleFunc("GET /v1/watch/{id}", s.watchOne)
	mux.HandleFunc("DELETE /v1/watch/{id}", s.watchDelete)
	mux.HandleFunc("POST /v1/label", s.label)
	mux.HandleFunc("POST /v1/leak/webrtc", s.webrtc)
	mux.HandleFunc("GET /v1/fingerprint", s.fingerprint)
	mux.HandleFunc("GET /leak", s.page)
	mux.HandleFunc("GET /{$}", s.root)
	mux.Handle("/mcp", mcp.Handler(s.Svc))
	mux.Handle("/mcp/", mcp.Handler(s.Svc))
	if s.Hub != nil {
		mux.Handle("/agent", s.Hub)
		mux.Handle("/agent/", s.Hub)
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(web.FS))))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.Svc != nil && s.Svc.Look != nil {
			_, age := s.Svc.Look.SnapshotAge(time.Now().UTC())
			w.Header().Set("X-IPD-Snapshot-Age", strconv.FormatInt(age, 10))
		}
		s.note(r)
		if !s.allow(r) {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (s *Server) favicon(w http.ResponseWriter, r *http.Request) {
	b, err := web.FS.ReadFile("favicon.svg")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("content-type", "image/svg+xml")
	w.Header().Set("cache-control", "public, max-age=86400")
	_, _ = w.Write(b)
}

// dnsSessionPath checks every prefix, including ones later removed by "..".
// In the escaped view, clean literal dot segments before unescaping each segment,
// as ServeMux does: an encoded slash must not change how many segments ".." pops.
func dnsSessionPath(p string, escaped bool) bool {
	var stack []string
	for _, segment := range strings.Split(p, "/") {
		switch segment {
		case "", ".":
			continue
		case "..":
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		default:
			if escaped {
				// EscapedPath always supplies valid escapes. Do not split or clean
				// again after decoding: mux matching unescapes segments only once.
				segment, _ = url.PathUnescape(segment)
			}
			stack = append(stack, segment)
		}
		if len(stack) >= 2 && stack[0] == "v1" && stack[1] == "dnsleak" {
			return true
		}
	}
	return false
}

func (s *Server) note(r *http.Request) {
	// Retain the conservative decoded-path protection, and also inspect mux's
	// escaped-segment view before logging (including redirects and rejected verbs).
	if dnsSessionPath(r.URL.Path, false) || dnsSessionPath(r.URL.EscapedPath(), true) {
		return
	}

	if s.Svc.DB == nil || s.Svc.Cfg == nil {
		return
	}
	ip := clientIP(r, s.Svc.Cfg.TrustProxy)
	now := s.SvcNow()
	_ = s.Svc.DB.LogIP(ip, r.URL.Path, now)
	s.purgeMu.Lock()
	due := now.Sub(s.lastPurge) > time.Minute
	if due {
		s.lastPurge = now
	}
	s.purgeMu.Unlock()
	if due {
		_, _ = s.Svc.DB.PurgeLogs(now, s.Svc.Cfg.LogRetention)
	}
}

func (s *Server) allow(r *http.Request) bool {
	if strings.HasPrefix(r.URL.Path, "/healthz") || strings.HasPrefix(r.URL.Path, "/static/") || r.URL.Path == "/favicon.ico" || r.URL.Path == "/favicon.svg" {
		return true
	}
	ip := "anon"
	if s.Svc.Cfg != nil {
		ip = clientIP(r, s.Svc.Cfg.TrustProxy)
		if key := r.Header.Get("X-API-Key"); s.Svc.Cfg.HasAPIKey(key) {
			return s.lim.allow(key, s.Svc.Cfg.KeyedRPM)
		}
	}
	return s.lim.allow(ip, 0)
}

func (s *Server) SvcNow() time.Time { return time.Now().UTC() }

func (s *Server) write(w http.ResponseWriter, r *http.Request, status int, rep app.Report) {
	if s.Svc != nil {
		rep = s.Svc.WithSnapshot(rep)
	}
	format := negotiate(r, strings.HasPrefix(r.URL.Path, "/v1"))
	if r.URL.Query().Get("stream") == "1" {
		s.writeSSE(w, rep)
		return
	}
	body, ctype := Render(format, rep)
	w.Header().Set("content-type", ctype)
	w.Header().Set("x-ipd-verdict", rep.Verdict)
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (s *Server) writeSSE(w http.ResponseWriter, rep app.Report) {
	if s.Svc != nil {
		rep = s.Svc.WithSnapshot(rep)
	}
	w.Header().Set("content-type", "text/event-stream")
	// Session bearers require the stricter policy set by dnsSessionResponse.
	if w.Header().Get("Cache-Control") != "no-store" {
		w.Header().Set("cache-control", "no-cache")
	}
	b, _ := json.Marshal(rep)
	fmt.Fprintf(w, "event: local\ndata: %s\n\n", b)
	fmt.Fprintf(w, "event: done\ndata: {}\n\n")
}

func (s *Server) root(w http.ResponseWriter, r *http.Request) {
	if negotiate(r, false) == "html" {
		s.page(w, r)
		return
	}
	ip := clientIP(r, s.Svc.Cfg != nil && s.Svc.Cfg.TrustProxy)
	rep, err := s.Svc.WhoAmI(r.Context(), ip, "")
	if err != nil {
		rep = app.Report{Verdict: "abstain", Summary: err.Error(), Data: map[string]any{"ip": ip}, Sources: []app.Source{}}
	}
	s.write(w, r, http.StatusOK, rep)
}

func (s *Server) page(w http.ResponseWriter, r *http.Request) {
	b, err := web.FS.ReadFile("index.html")
	if err != nil {
		http.Error(w, "ui missing", 500)
		return
	}
	w.Header().Set("content-type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r, s.Svc.Cfg != nil && s.Svc.Cfg.TrustProxy)
	rep, err := s.Svc.WhoAmI(r.Context(), ip, r.URL.Query().Get("ip_version"))
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	s.write(w, r, 200, rep)
}

func (s *Server) ip(w http.ResponseWriter, r *http.Request) {
	ip := stripSuffix(r.PathValue("ip"))
	rep, err := s.Svc.LookupIP(r.Context(), ip)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	s.write(w, r, 200, rep)
}

func (s *Server) risk(w http.ResponseWriter, r *http.Request) {
	ip := stripSuffix(r.PathValue("ip"))
	live := r.URL.Query().Get("live") != "0" && (s.Svc.Cfg == nil || !s.Svc.Cfg.Offline)
	rep, err := s.Svc.Risk(r.Context(), ip, live)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	s.write(w, r, 200, rep)
}

func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	rep, err := s.Svc.History(stripSuffix(r.PathValue("ip")), days)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	s.write(w, r, 200, rep)
}

func (s *Server) asn(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(strings.TrimPrefix(stripSuffix(r.PathValue("asn")), "AS"))
	s.write(w, r, 200, s.Svc.ASN(n))
}

func (s *Server) prefix(w http.ResponseWriter, r *http.Request) {
	rep, err := s.Svc.Prefix(stripSuffix(r.PathValue("cidr")))
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	s.write(w, r, 200, rep)
}

func (s *Server) batch(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IPs []string `json:"ips"`
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if json.Unmarshal(raw, &body) != nil || len(body.IPs) == 0 {
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				body.IPs = append(body.IPs, line)
			}
		}
	}
	rep, err := s.Svc.Batch(r.Context(), body.IPs)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if strings.Contains(r.Header.Get("Accept"), "ndjson") {
		w.Header().Set("content-type", "application/x-ndjson")
		rows, _ := rep.Data.(map[string]any)["results"].([]map[string]any)
		enc := json.NewEncoder(w)
		for _, row := range rows {
			_ = enc.Encode(row)
		}
		return
	}
	s.write(w, r, 200, rep)
}

func (s *Server) gfw(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Target string `json:"target"`
		Ports  []int  `json:"ports"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Target == "" {
		http.Error(w, "target required", 400)
		return
	}
	if !s.powOK(w, r) {
		return
	}
	rep, err := s.Svc.GFW(r.Context(), body.Target, body.Ports)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	s.storeJob(w, r, "gfw", rep)
}

func (s *Server) route(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Target   string   `json:"target"`
		Carriers []string `json:"carriers"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if !s.powOK(w, r) {
		return
	}
	rep, err := s.Svc.RouteForward(r.Context(), body.Target, body.Carriers)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	s.storeJob(w, r, "route", rep)
}

func (s *Server) latency(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Target string `json:"target"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if !s.powOK(w, r) {
		return
	}
	rep, err := s.Svc.Latency(r.Context(), body.Target)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	s.storeJob(w, r, "latency", rep)
}

func (s *Server) storeJob(w http.ResponseWriter, r *http.Request, kind string, rep app.Report) {
	id := "job"
	if s.Svc.DB != nil {
		id = kind + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
		raw, _ := json.Marshal(rep)
		_ = s.Svc.DB.CreateJob(id, kind, "", time.Now().UTC())
		_ = s.Svc.DB.FinishJob(id, "done", json.RawMessage(raw), time.Now().UTC())
	}
	wrapped := app.Report{Verdict: rep.Verdict, Summary: rep.Summary, Data: map[string]any{"job_id": id, "status": "done", "result": rep.Data}, Sources: rep.Sources, CachedAt: rep.CachedAt, Attribution: rep.Attribution}
	s.write(w, r, 200, wrapped)
}

func (s *Server) job(w http.ResponseWriter, r *http.Request) {
	rep, err := s.Svc.Job(r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	s.write(w, r, 200, rep)
}

func (s *Server) targets(w http.ResponseWriter, r *http.Request) {
	scope := r.URL.Query().Get("scope")
	if scope == "" {
		scope = "core"
	}
	list := route.Targets(scope)
	rep := app.Report{Verdict: "ok", Summary: "return-path targets", Data: map[string]any{"scope": scope, "targets": list}, Sources: []app.Source{{ID: "cn_targets"}}, CachedAt: time.Now().UTC()}
	s.write(w, r, 200, rep)
}

func (s *Server) dnsSessionResponse(w http.ResponseWriter, r *http.Request, rep app.Report, err error) {
	w.Header().Set("Cache-Control", "no-store")
	if err != nil {
		status := http.StatusServiceUnavailable
		if errors.Is(err, leak.ErrNotFound) {
			status = http.StatusNotFound
		}
		if !errors.Is(err, leak.ErrNotFound) && !errors.Is(err, leak.ErrDisabled) && !errors.Is(err, leak.ErrCapacity) {
			http.Error(w, "DNS session unavailable", http.StatusInternalServerError)
			return
		}
		http.Error(w, err.Error(), status)
		return
	}
	// The generic text renderer compacts/truncates values. Session capabilities
	// and observations must remain complete, including long names and IPv6/ECS.
	// Keep this exception local to DNS; JSON/Markdown/SSE keep their wire schemas.
	if r.URL.Query().Get("stream") != "1" && negotiate(r, true) == "text" {
		rep = s.Svc.WithSnapshot(rep)
		data, _ := json.Marshal(rep.Data)
		rep.Data = nil
		header, contentType := Render("text", rep)
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("X-IPD-Verdict", rep.Verdict)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "%sdata: %s\n", header, data)
		return
	}

	s.write(w, r, http.StatusOK, rep)
}

func (s *Server) dnsSessionCreate(w http.ResponseWriter, r *http.Request) {
	rep, err := s.Svc.CreateDNSSession()
	s.dnsSessionResponse(w, r, rep, err)
}

func (s *Server) dnsleak(w http.ResponseWriter, r *http.Request) {
	rep, err := s.Svc.DNSSession(r.PathValue("token"))
	s.dnsSessionResponse(w, r, rep, err)
}

func (s *Server) sources(w http.ResponseWriter, r *http.Request) {
	s.write(w, r, 200, s.Svc.Sources())
}

func (s *Server) report(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	host, _ := osHostname()
	rep, err := s.Svc.Share(string(b), []string{host})
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	s.write(w, r, 200, rep)
}

func (s *Server) share(w http.ResponseWriter, r *http.Request) {
	if s.Svc.Cfg == nil || !s.Svc.Cfg.ShareEnabled {
		http.NotFound(w, r)
		return
	}
	body, err := s.Svc.LoadShare(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if negotiate(r, false) == "html" {
		w.Header().Set("content-type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<!doctype html><meta charset=utf-8><title>ipd report</title><pre>%s</pre>", htmlEscape(body))
		return
	}
	s.write(w, r, 200, app.Report{Verdict: "ok", Summary: "shared report", Data: map[string]any{"body": body}, Sources: []app.Source{}})
}

func (s *Server) watchCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Target  string   `json:"target"`
		Checks  []string `json:"checks"`
		Webhook string   `json:"webhook"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	rep, err := s.Svc.CreateWatch(body.Target, strings.Join(body.Checks, ","), body.Webhook)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	s.write(w, r, 200, rep)
}

func (s *Server) watchOne(w http.ResponseWriter, r *http.Request) {
	rep, err := s.Svc.ListWatches()
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	s.write(w, r, 200, rep)
}

func (s *Server) watchDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.Svc.DeleteWatch(r.PathValue("id")); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	s.write(w, r, 200, app.Report{Verdict: "ok", Summary: "deleted", Data: map[string]any{"watch_id": r.PathValue("id")}, Sources: []app.Source{}})
}

func (s *Server) label(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP, Label, Note string
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if err := s.Svc.Label(body.IP, body.Label, body.Note); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	s.write(w, r, 200, app.Report{Verdict: "ok", Summary: "label stored", Data: map[string]any{"ok": true}, Sources: []app.Source{}})
}

func (s *Server) webrtc(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	// Drop anything that is not the two allowed fields. Candidate IPs are ignored.
	var loose map[string]any
	_ = json.Unmarshal(raw, &loose)
	rep := privacy.WebRTCReport{}
	if v, ok := loose["leak"].(bool); ok {
		rep.Leak = v
	}
	switch n := loose["candidate_count"].(type) {
	case float64:
		rep.CandidateCount = int(n)
	}
	if err := s.Svc.WebRTC(rep); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.write(w, r, 200, app.Report{Verdict: "ok", Summary: "webrtc verdict stored without addresses", Data: map[string]any{"leak": rep.Leak, "candidate_count": rep.CandidateCount}, Sources: []app.Source{}})
}

func (s *Server) fingerprint(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		ip = clientIP(r, s.Svc.Cfg != nil && s.Svc.Cfg.TrustProxy)
	}
	fp, ok := s.Svc.Fingerprint(ip)
	if !ok {
		s.write(w, r, 200, app.Report{Verdict: "abstain", Summary: "no client hello recorded for this address yet", Data: map[string]any{"ip": ip}, Sources: []app.Source{{ID: "tls"}}})
		return
	}
	s.write(w, r, 200, app.Report{Verdict: "ok", Summary: "ja4 " + fp.JA4, Data: fp, Sources: []app.Source{{ID: "tls"}}})
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r, false)
	if s.Svc.Cfg != nil && !s.Svc.Cfg.MetricsPublic && !isPrivateHost(ip) && ip != "127.0.0.1" && ip != "::1" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("content-type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP ipd_up ipd is serving\nipd_up 1\n")
}

func (s *Server) methodology(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "text/markdown; charset=utf-8")
	_, _ = io.WriteString(w, mcp.Methodology())
}

func (s *Server) openapi(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")
	_, _ = w.Write(OpenAPI())
}

func (s *Server) llms(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, LLMS(s.domain()))
}

func (s *Server) llmsFull(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, LLMS(s.domain())+"\n"+mcp.Methodology())
}

func (s *Server) domain() string {
	if s.Svc.Cfg != nil && s.Svc.Cfg.Domain != "" {
		return s.Svc.Cfg.Domain
	}
	return "localhost"
}

func (s *Server) powChallenge(w http.ResponseWriter, r *http.Request) {
	bits := 12
	if s.Svc.Cfg != nil && s.Svc.Cfg.PowBits > 0 {
		bits = s.Svc.Cfg.PowBits
	}
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"challenge": pow.Issue(bits), "bits": bits})
}

func (s *Server) powOK(w http.ResponseWriter, r *http.Request) bool {
	if s.Svc.Cfg == nil || !s.Svc.Cfg.PowRequired {
		return true
	}
	if pow.Verify(r.Header.Get("X-Ipd-Pow")) {
		return true
	}
	http.Error(w, "pow required", http.StatusUnauthorized)
	return false
}

func clientIP(r *http.Request, trust bool) string {
	if trust {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func stripSuffix(s string) string {
	for _, suf := range []string{".json", ".txt", ".md"} {
		s = strings.TrimSuffix(s, suf)
	}
	return s
}

func isPrivateHost(ip string) bool {
	parsed, err := netipParse(ip)
	if err != nil {
		return false
	}
	return parsed.IsLoopback() || parsed.IsPrivate() || !privacy.IsPublic(parsed)
}

func osHostname() (string, error) {
	return os.Hostname()
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

// limiter is a fixed one-minute window.
type limiter struct {
	mu     sync.Mutex
	window map[string]int
	reset  time.Time
	perMin int
}

func newLimiter(perMin int) *limiter {
	return &limiter{window: map[string]int{}, reset: time.Now().Add(time.Minute), perMin: perMin}
}

func (l *limiter) allow(key string, override int) bool {
	limit := l.perMin
	if override > 0 {
		limit = override
	}
	if limit <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if time.Now().After(l.reset) {
		l.window = map[string]int{}
		l.reset = time.Now().Add(time.Minute)
	}
	if l.window[key] >= limit {
		return false
	}
	l.window[key]++
	return true
}
