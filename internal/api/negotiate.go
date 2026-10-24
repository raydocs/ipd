package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"ipd/internal/app"
)

// negotiate picks text, json, markdown, or html.
// Suffix and ?format= win. /v1 never returns HTML. curl, wget, and httpie
// default to text when Accept does not name a concrete type.
func negotiate(r *http.Request, api bool) string {
	if f := explicitFormat(r); f != "" {
		return coerce(f, api)
	}
	if f, ok := fromAccept(r.Header.Get("Accept")); ok {
		return coerce(f, api)
	}
	ua := strings.ToLower(r.UserAgent())
	if strings.Contains(ua, "curl") || strings.Contains(ua, "wget") || strings.Contains(ua, "httpie") {
		return "text"
	}
	if api {
		return "text"
	}
	return "html"
}

func coerce(f string, api bool) string {
	if api && f == "html" {
		return "text"
	}
	return f
}

func explicitFormat(r *http.Request) string {
	switch strings.ToLower(r.URL.Query().Get("format")) {
	case "json":
		return "json"
	case "md", "markdown":
		return "md"
	case "txt", "text", "plain":
		return "text"
	case "html":
		return "html"
	}
	path := r.URL.Path
	switch {
	case strings.HasSuffix(path, ".json"):
		return "json"
	case strings.HasSuffix(path, ".md"):
		return "md"
	case strings.HasSuffix(path, ".txt"):
		return "text"
	}
	return ""
}

func fromAccept(h string) (string, bool) {
	h = strings.TrimSpace(h)
	if h == "" {
		return "", false
	}
	type cand struct {
		kind string
		q    float64
	}
	var cs []cand
	for _, part := range strings.Split(h, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		bits := strings.Split(part, ";")
		media := strings.TrimSpace(bits[0])
		q := 1.0
		for _, p := range bits[1:] {
			p = strings.TrimSpace(p)
			if strings.HasPrefix(p, "q=") {
				if v, err := strconv.ParseFloat(strings.TrimPrefix(p, "q="), 64); err == nil {
					q = v
				}
			}
		}
		kind := ""
		switch {
		case media == "application/json" || strings.HasSuffix(media, "+json"):
			kind = "json"
		case media == "text/markdown" || media == "text/x-markdown":
			kind = "md"
		case media == "text/plain":
			kind = "text"
		case media == "text/html":
			kind = "html"
		case media == "*/*" || media == "*":
			continue
		}
		if kind != "" && q > 0 {
			cs = append(cs, cand{kind, q})
		}
	}
	if len(cs) == 0 {
		return "", false
	}
	sort.SliceStable(cs, func(i, j int) bool { return cs[i].q > cs[j].q })
	return cs[0].kind, true
}

// Render formats a report as text, json, or markdown.
func Render(format string, rep app.Report) ([]byte, string) {
	switch format {
	case "json":
		b, _ := json.MarshalIndent(rep, "", "  ")
		return append(b, '\n'), "application/json; charset=utf-8"
	case "md":
		return []byte(markdown(rep)), "text/markdown; charset=utf-8"
	default:
		return []byte(plaintext(rep)), "text/plain; charset=utf-8"
	}
}

func plaintext(rep app.Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "VERDICT: %s — %s\n", rep.Verdict, oneLine(rep.Summary))
	fmt.Fprintf(&b, "snapshot_age_seconds: %d\n", rep.SnapshotAgeSeconds)
	writeData(&b, "", rep.Data)
	if len(rep.Sources) > 0 {
		ids := make([]string, 0, len(rep.Sources))
		for _, s := range rep.Sources {
			ids = append(ids, s.ID)
		}
		fmt.Fprintf(&b, "sources: %s\n", strings.Join(ids, ", "))
	}
	if len(rep.Attribution) > 0 {
		fmt.Fprintf(&b, "attribution: %s\n", strings.Join(rep.Attribution, " | "))
	}
	return b.String()
}

func writeData(b *strings.Builder, prefix string, v any) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			key := k
			if prefix != "" {
				key = prefix + "." + k
			}
			if m, ok := t[k].(map[string]any); ok && len(m) <= 8 {
				writeData(b, key, m)
				continue
			}
			fmt.Fprintf(b, "%s: %s\n", key, compact(t[k]))
		}
	default:
		if prefix != "" {
			fmt.Fprintf(b, "%s: %s\n", prefix, compact(v))
		}
	}
}

func compact(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	s := string(b)
	if len(s) > 240 {
		s = s[:240] + "…"
	}
	return s
}

func markdown(rep app.Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# VERDICT: %s\n\n%s\n\n", rep.Verdict, rep.Summary)
	raw, _ := json.MarshalIndent(rep.Data, "", "  ")
	b.WriteString("## data\n\n```json\n")
	b.Write(raw)
	b.WriteString("\n```\n\n## sources\n\n")
	if len(rep.Sources) == 0 {
		b.WriteString("(none)\n")
	}
	for _, s := range rep.Sources {
		fmt.Fprintf(&b, "- `%s`", s.ID)
		if s.Attribution != "" {
			fmt.Fprintf(&b, " — %s", s.Attribution)
		}
		b.WriteByte('\n')
	}
	if len(rep.Attribution) > 0 {
		b.WriteString("\n## attribution\n\n")
		for _, a := range rep.Attribution {
			fmt.Fprintf(&b, "- %s\n", a)
		}
	}
	return b.String()
}

func oneLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

func netipParse(ip string) (netip.Addr, error) {
	return netip.ParseAddr(ip)
}
