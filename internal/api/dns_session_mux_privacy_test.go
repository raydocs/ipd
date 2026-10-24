package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"ipd/internal/app"
	"ipd/internal/config"
	"ipd/internal/store"
)

func TestDNSSessionMuxPathPrivacy(t *testing.T) {
	// Fixtures are not issued capabilities. Names, not paths or response bodies,
	// identify failures so this regression cannot itself disclose bearers.
	const fixture = "0123456789abcdef0123456789abcdef"
	cases := []struct {
		name, path string
	}{
		{"direct", "/v1/dnsleak/" + fixture},
		{"encoded-slash-upper", "/x%2Fy/../v1/dnsleak/" + fixture},
		{"encoded-slash-lower", "/x%2fy/../v1/dnsleak/" + fixture},
		{"encoded-slash-double", "/x%252Fy/../v1/dnsleak/" + fixture},
		{"encoded-slash-triple", "/x%25252fy/../v1/dnsleak/" + fixture},
		{"encoded-slash-many-segments", "/x%2fy%2Fz/../v1/dnsleak/" + fixture},
		{"encoded-dot-segment-popped", "/%2e%2E/../v1/dnsleak/" + fixture},
		{"encoded-slash-letters", "/x%2Fy/../%76%31/dns%6Ceak/" + fixture},
		{"encoded-slash-letters-lower", "/x%2fy/../%76%31/dns%6ceak/" + fixture},
		{"fully-encoded-prefix", "/x%2Fy/../%76%31/%64%6e%73%6C%65%61%6B/" + fixture},
		{"duplicate-slashes", "//x%2Fy//..//v1///dnsleak//" + fixture},
		{"removed-sensitive-prefix", "/x%2Fy/../v1/dnsleak/" + fixture + "/../../sources"},
		{"removed-entire-prefix", "/x%2Fy/../v1/dnsleak/" + fixture + "/../../../healthz"},
		{"removed-encoded-prefix", "/x%2fy/../%76%31/dns%6Ceak/" + fixture + "/../../../healthz"},
		{"removed-duplicate-prefix", "/x%2Fy/../v1//dnsleak/" + fixture + "/../../sources"},
		{"encoded-dots-after-prefix", "/x%2Fy/../v1/dnsleak/" + fixture + "/%2e%2e/%2E%2E/sources"},
		{"decoded-slashes", "/v1%2fdnsleak%2F" + fixture},
		{"decoded-slashes-removed", "/v1%2f%2Fdnsleak%2f" + fixture + "%2f..%2F..%2fsources"},
		{"decoded-dot-before-prefix", "/v1/%2e/dnsleak/" + fixture + "/../../sources"},
		{"multilayer-bearer", "/x%2Fy/../v1/dnsleak/%2530" + fixture},
	}
	for _, enabled := range []bool{false, true} {
		mode := "disabled"
		if enabled {
			mode = "enabled"
		}
		t.Run(mode, func(t *testing.T) {
			db, err := store.Open(filepath.Join(t.TempDir(), "privacy.sqlite"))
			if err != nil {
				t.Fatal("open SQLite failed")
			}
			defer db.Close()
			svc := app.New(&config.Config{Offline: true, Domain: "example.test", DNSSessionsEnabled: enabled, TrustProxy: true, AnonymousRPM: 10000, DataDir: t.TempDir()}, db)
			ts := httptest.NewServer(New(svc).Handler())
			defer ts.Close()
			client := ts.Client()
			// Observe the original request, not just the redirect destination. A
			// client following redirects would hide pre-canonicalization logging.
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			call := func(method, path string) int {
				t.Helper()
				req, err := http.NewRequest(method, ts.URL+path, nil)
				if err != nil {
					t.Fatal("construct fixture request failed")
				}
				req.Header.Set("Accept", "application/json")
				req.Header.Set("X-Forwarded-For", "192.0.2.55")
				res, err := client.Do(req)
				if err != nil {
					t.Fatal("loopback request failed")
				}
				defer res.Body.Close()
				if _, err := io.Copy(io.Discard, res.Body); err != nil {
					t.Fatal("read fixture response failed")
				}
				return res.StatusCode
			}
			for _, tc := range cases {
				for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost} {
					t.Run(tc.name+"/"+method, func(t *testing.T) {
						if status := call(method, tc.path); status == 429 || status < 200 || status >= 600 {
							t.Fatal("fixture was not dispatched to the mux")
						}
						var logs, results int
						if err := db.DB.QueryRow("SELECT count(*) FROM ip_logs").Scan(&logs); err != nil {
							t.Fatal("query request logs failed")
						}
						if err := db.DB.QueryRow("SELECT count(*) FROM results").Scan(&results); err != nil {
							t.Fatal("query stored results failed")
						}
						if logs != 0 || results != 0 {
							var bearers, callers int
							if err := db.DB.QueryRow("SELECT count(*) FROM ip_logs WHERE instr(path, ?) > 0", fixture).Scan(&bearers); err != nil {
								t.Fatal("query persisted bearer count failed")
							}
							if err := db.DB.QueryRow("SELECT count(*) FROM ip_logs WHERE ip = ?", "192.0.2.55").Scan(&callers); err != nil {
								t.Fatal("query persisted caller count failed")
							}
							t.Errorf("sensitive request persisted: log rows=%d result rows=%d bearer rows=%d caller rows=%d", logs, results, bearers, callers)
						}
						// Isolate failures without reading or printing stored secrets.
						if _, err := db.DB.Exec("DELETE FROM ip_logs"); err != nil {
							t.Fatal("reset request logs failed")
						}
					})
				}
			}
			// These do not enter the namespace in either the decoded privacy view
			// or mux's escaped-segment view. Multiple encoding is not recursively
			// decoded by ServeMux, nor are path letters case-folded.
			ordinary := []string{
				"/healthz", "/v1/sources", "/x%2Fy/../healthz",
				"/%2576%2531/dnsleak/not-a-capability", "/v1/dns%256ceak/not-a-capability",
				"/%252576%252531/dnsleak/not-a-capability", "/v1/dnsleak-extra/not-a-capability",
				"/V1/DNSLEAK/not-a-capability", "/x%2Fy/v1/dnsleak/not-a-capability",
			}
			for _, path := range ordinary {
				call(http.MethodGet, path)
			}
			rows, err := db.DB.Query("SELECT path, ip FROM ip_logs ORDER BY id")
			if err != nil {
				t.Fatal("query ordinary logs failed")
			}
			defer rows.Close()
			i := 0
			for rows.Next() {
				var path, ip string
				if err := rows.Scan(&path, &ip); err != nil {
					t.Fatal("read ordinary log failed")
				}
				if i >= len(ordinary) {
					t.Fatal("unexpected ordinary log row")
				}
				wantPath, err := url.PathUnescape(ordinary[i])
				if err != nil || path != wantPath || ip != "192.0.2.55" || strings.Contains(path, fixture) {
					t.Fatal("ordinary logging or privacy invariant changed")
				}
				i++
			}
			if rows.Err() != nil || i != len(ordinary) {
				t.Fatalf("ordinary request logs: got %d rows, want %d", i, len(ordinary))
			}
		})
	}
}

func TestDNSSessionTokenParameterDescription(t *testing.T) {
	params := operation(t, contractDoc(t), "/v1/dnsleak/{token}", "get")["parameters"].([]any)
	for _, value := range params {
		param := object(t, value)
		if param["name"] != "token" || param["in"] != "path" {
			continue
		}
		description, _ := param["description"].(string)
		if !strings.Contains(description, "short-lived bearer") || !strings.Contains(description, "lookup") || !strings.Contains(description, "not echoed") {
			t.Error("token parameter does not describe the short-lived bearer lookup")
		}
		return
	}
	t.Fatal("missing token path parameter")
}
