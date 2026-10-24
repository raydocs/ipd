package app

import (
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"ipd/internal/unlock"
)

const (
	coreUnlockMaxIDs   = 4
	coreUnlockRequests = 12               // at most 3 per selected service, at most 4 services
	coreUnlockBody     = 256 << 10        // both wire and decompressed, per request
	coreNodeBudget     = 20 * time.Second // includes egress; batch still bounded to 45s
)

var ErrCoreNodesUnlock = errors.New("invalid node unlock selection")

// Deliberately bounded subset of the existing shared catalogue. No new verdict
// logic: other services remain unsupported until their entire path is audited.
// Exact URLs, not arbitrary hosts, authorize every request (including traces).
var coreUnlockURLs = map[string][]string{
	"apple":   {"https://gspe1-ssl.ls.apple.com/pep/gcc"},
	"meta_ai": {"https://www.meta.ai/"},
	"netflix": {"https://www.netflix.com/title/81280792", "https://www.netflix.com/title/70143836"},
	"claude":  {"https://claude.ai/", "https://claude.ai/cdn-cgi/trace"},
	"chatgpt": {"https://api.openai.com/compliance/cookie_requirements", "https://ios.chat.openai.com/", "https://chatgpt.com/cdn-cgi/trace"},
}

func validateCoreUnlockIDs(ids []string) error {
	if len(ids) > coreUnlockMaxIDs {
		return ErrCoreNodesUnlock
	}
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if _, ok := coreUnlockURLs[id]; !ok || seen[id] {
			return ErrCoreNodesUnlock
		}
		seen[id] = true
	}
	return nil
}

// Output is a projection, never engine free-form evidence or method (which may
// label nil Resolve as native). No headers, response bodies, URLs or raw errors.
type CoreNodeUnlockObservation struct {
	Service  string `json:"service"`
	Status   string `json:"status"`
	Region   string `json:"region,omitempty"`
	Evidence string `json:"evidence"`
}

var coreUnlockRegion = regexp.MustCompile(`^[A-Z]{2}$`)

func queryCoreUnlock(ctx context.Context, client *http.Client, ids []string, mapURL func(string) string, gate func() error) ([]CoreNodeUnlockObservation, error) {
	allowed := make(map[string]bool)
	for _, id := range ids {
		for _, u := range coreUnlockURLs[id] {
			allowed[u] = true
		}
	}
	getter := &coreUnlockGetter{client: client, allowed: allowed, mapURL: mapURL, gate: gate}
	engine := unlock.Engine{Get: getter, Resolve: func(context.Context, string) string { return "proxy" }}
	out := make([]CoreNodeUnlockObservation, 0, len(ids))
	for _, id := range ids {
		// A request failure in this service must not be hidden by another response.
		getter.failed = false
		result := engine.Check(ctx, []string{id})[0]
		row := CoreNodeUnlockObservation{Service: id, Status: unlock.Abstain, Evidence: "unrecognized_or_unavailable"}
		if !getter.failed && gate() == nil && ctx.Err() == nil {
			switch result.Status {
			case unlock.Yes, unlock.No, unlock.Partial, unlock.OriginalsOnly, unlock.AppOnly, unlock.WebOnly:
				row.Status = result.Status
				row.Evidence = "recognized_catalog_markers"
				if result.Status == unlock.No {
					row.Evidence = "explicit_regional_denial"
				}
				if coreUnlockRegion.MatchString(result.Region) {
					row.Region = result.Region
				}
			}
		}
		out = append(out, row)
	}
	if getter.interrupted != nil {
		return out, getter.interrupted
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if err := gate(); err != nil {
		return out, err
	}
	return out, nil
}

type coreUnlockGetter struct {
	client      *http.Client
	allowed     map[string]bool
	mapURL      func(string) string // unexported function-level fixture seam only
	gate        func() error
	calls       int
	failed      bool
	interrupted error
}

func (g *coreUnlockGetter) Get(ctx context.Context, rawURL string, headers map[string]string) (result unlock.Response) {
	fail := func() unlock.Response { g.failed = true; return unlock.Response{Err: ErrNodeMeasurementUnavailable} }
	if g.interrupted != nil || !g.allowed[rawURL] || g.calls >= coreUnlockRequests || ctx.Err() != nil || g.gate() != nil {
		return fail()
	}
	g.calls++
	// Match only the shared catalogue's fixed headers. Never forward arbitrary
	// cookies, Authorization, Proxy-Authorization or caller-supplied headers.
	for k, v := range headers {
		if (k != "User-Agent" || v != "Mozilla/5.0 (compatible; ipd/0.9)") && (k != "Accept" || v != "text/html,application/json") {
			return fail()
		}
	}
	target := rawURL
	if g.mapURL != nil {
		target = g.mapURL(rawURL)
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return fail()
	}
	ctx, cancel := context.WithTimeout(ctx, coreProbeBudget)
	defer cancel()
	defer func() {
		if err := ctx.Err(); err != nil {
			g.interrupted = err
		}
	}()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return fail()
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := g.client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			g.interrupted = context.DeadlineExceeded
		}
		return fail()
	}
	defer resp.Body.Close()
	// No redirects at all. Even an otherwise recognizable 3xx cannot vote.
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return fail()
	}
	// Read the entire bounded wire body first; no partial evidence on read errors,
	// oversized bodies, unsupported encoding or truncated/oversized gzip streams.
	body, err := io.ReadAll(io.LimitReader(resp.Body, coreUnlockBody+1))
	if err != nil || len(body) > coreUnlockBody {
		return fail()
	}
	encoding := resp.Header.Get("Content-Encoding")
	switch {
	case encoding == "" || strings.EqualFold(encoding, "identity"):
	case strings.EqualFold(encoding, "gzip"):
		gz, e := gzip.NewReader(strings.NewReader(string(body)))
		if e != nil {
			return fail()
		}
		body, err = io.ReadAll(io.LimitReader(gz, coreUnlockBody+1))
		closeErr := gz.Close()
		if err != nil || closeErr != nil || len(body) > coreUnlockBody {
			return fail()
		}
	default:
		return fail()
	}
	if ctx.Err() != nil || g.gate() != nil {
		return fail()
	}
	// Only this challenge header is needed by Engine. Nothing else leaves here.
	safeHeader := make(http.Header)
	safeHeader.Set("Cf-Mitigated", resp.Header.Get("Cf-Mitigated"))
	return unlock.Response{Status: resp.StatusCode, Body: string(body), FinalURL: rawURL, Header: safeHeader}
}
