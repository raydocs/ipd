package app

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ipd/internal/config"
	"ipd/internal/nodes"
	"ipd/internal/unlock"
)

func unlockTarget(target coreProbeTarget) coreProbeTarget {
	target.unlockURL = func(raw string) string { return target.url + "/catalog?url=" + url.QueryEscape(raw) }
	return target
}

func assertUnlockCleared(t *testing.T, rep Report) {
	t.Helper()
	assertCoreUnknown(t, rep)
	for _, row := range egressRows(t, rep) {
		if len(row.Unlock) != 0 {
			t.Fatalf("stale service evidence: %+v", row)
		}
	}
}

// Both actual child processes read the production private runner configs and
// authenticate the real HTTP client's CONNECT. Each tunnels exclusively to its
// own HTTPS origin, so neither egress nor service evidence can cross nodes.
func TestCoreNodeUnlockTwoProcessesProductionPath(t *testing.T) {
	bin := egressFixture(t)
	var envHits, requests atomic.Int32
	env := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { envHits.Add(1) }))
	defer env.Close()
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(k, env.URL)
	}
	t.Setenv("NO_PROXY", "*")
	t.Setenv("no_proxy", "*")
	t.Setenv("UNLOCK_SECRET", "never-inherit")
	handler := func(ip, region string, denied bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			if r.Method != "GET" || r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
				t.Error("method/credential leak")
			}
			if r.URL.Path == "/" {
				fmt.Fprint(w, ip)
				return
			}
			if r.URL.Path != "/catalog" {
				t.Error("unexpected path")
				w.WriteHeader(500)
				return
			}
			raw := r.URL.Query().Get("url")
			w.Header().Set("Set-Cookie", "secret-cookie=private")
			switch raw {
			case coreUnlockURLs["apple"][0]:
				fmt.Fprint(w, region)
			case coreUnlockURLs["meta_ai"][0]:
				if denied {
					w.WriteHeader(403)
					fmt.Fprint(w, "AbraGeoBlockedErrorRoot")
				} else {
					fmt.Fprint(w, `KadabraRootContainer "region":"`+region+`"`)
				}
			case coreUnlockURLs["netflix"][0], coreUnlockURLs["netflix"][1]:
				if denied {
					w.WriteHeader(451)
					fmt.Fprint(w, "not available in your country")
				} else {
					fmt.Fprint(w, `{"isPlayable":true,"country":"`+region+`"}`)
				}
			case coreUnlockURLs["chatgpt"][0]:
				if denied {
					w.WriteHeader(403)
					fmt.Fprint(w, `{"error":{"code":"unsupported_country"}}`)
				} else {
					fmt.Fprint(w, `{"requires_cookie_consent":false,"country":"`+region+`"}`)
				}
			case coreUnlockURLs["chatgpt"][1]:
				if denied {
					w.WriteHeader(403)
					fmt.Fprint(w, "ChatGPT is not available in your country")
				} else {
					fmt.Fprint(w, `<title>ChatGPT</title><a href="https://auth.openai.com/authorize">Log in</a>`)
				}
			case coreUnlockURLs["chatgpt"][2]:
				fmt.Fprint(w, "loc="+region+"\n")
			default:
				t.Error("unexpected catalogue URL")
				w.WriteHeader(500)
			}
		}
	}
	a, target := tlsEgressOrigin(t, handler("8.8.8.8", "US", false))
	b, _ := tlsEgressOrigin(t, handler("1.1.1.1", "JP", true))
	target = unlockTarget(target)
	ids := []string{"apple", "meta_ai", "netflix", "chatgpt"}
	for _, backend := range []nodes.Backend{nodes.BackendMihomo, nodes.BackendSingBox} {
		input := nativeEgressInput(backend, []string{a.Listener.Addr().String(), b.Listener.Addr().String()})
		rep, err := New(&config.Config{Proxy: env.URL}, nil).coreNodes(context.Background(), input, CoreNodeOptions{MihomoBin: bin, SingBoxBin: bin, UnlockIDs: ids}, target)
		if err != nil {
			t.Fatal(err)
		}
		rows := egressRows(t, rep)
		if rep.Verdict != "abstain" || rep.Data.(map[string]any)["measurement_status"] != "completed" || len(rows) != 2 {
			t.Fatalf("bad report: %+v", rep)
		}
		for i, row := range rows {
			wantIP, region := "8.8.8.8", "US"
			if i == 1 {
				wantIP, region = "1.1.1.1", "JP"
			}
			if row.Index != i+1 || row.Backend != backend || row.EgressIP != wantIP || row.Status != "observed" || len(row.Unlock) != len(ids) {
				t.Fatalf("wrong ordered node: %+v", row)
			}
			for j, result := range row.Unlock {
				want := unlock.Yes
				if i == 1 && j > 0 {
					want = unlock.No
				}
				if result.Service != ids[j] || result.Status != want {
					t.Fatalf("cross-node service result: %+v", row)
				}
				if j == 0 && result.Region != region {
					t.Fatalf("cross-node region: %+v", result)
				}
			}
		}
		encoded, _ := json.Marshal(rep)
		for _, secret := range []string{"secret-name", "private", "127.0.0.1", "ipd-core-", "password", "Proxy-Authorization", "cookie", "Kadabra", "isPlayable", "native", "http"} {
			if strings.Contains(string(encoded), secret) {
				t.Fatalf("output leaks %q: %s", secret, encoded)
			}
		}
	}
	// 7 catalogue requests + 1 egress per node, no retries, two backends.
	if envHits.Load() != 0 || requests.Load() != 32 {
		t.Fatalf("fallback or request count: env=%d total=%d", envHits.Load(), requests.Load())
	}
	assertEgressReaped(t, bin, 4)
}

func TestCoreNodeUnlockMarkersAndFailureAbstention(t *testing.T) {
	bin := egressFixture(t)
	var redirects atomic.Int32
	for _, tc := range []struct {
		name, body string
		status     int
		header     string
		want       string
	}{
		{"positive", `KadabraRootContainer "region":"US"`, 200, "", unlock.Yes},
		{"denial", `AbraGeoBlockedErrorRoot`, 403, "", unlock.No},
		{"challenge", `Just a moment KadabraRootContainer`, 200, "", unlock.Abstain},
		{"header_challenge", `KadabraRootContainer`, 200, "challenge", unlock.Abstain},
		{"unknown", `new landing page`, 200, "", unlock.Abstain},
		{"http_error", `KadabraRootContainer`, 503, "", unlock.Abstain},
		{"redirect", `KadabraRootContainer`, 302, "", unlock.Abstain},
		{"too_large", `KadabraRootContainer` + strings.Repeat("x", coreUnlockBody), 200, "", unlock.Abstain},
		{"large_header", `KadabraRootContainer`, 200, "", unlock.Abstain},
		{"broken_body", `KadabraRootContainer`, 200, "", unlock.Abstain},
		{"gzip", `KadabraRootContainer`, 200, "", unlock.Yes},
		{"gzip_large", `KadabraRootContainer` + strings.Repeat("x", coreUnlockBody), 200, "", unlock.Abstain},
		{"gzip_broken", `KadabraRootContainer`, 200, "", unlock.Abstain},
		{"unsupported_encoding", `KadabraRootContainer`, 200, "", unlock.Abstain},
		{"timeout", `KadabraRootContainer`, 200, "", unlock.Abstain},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, target := tlsEgressOrigin(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/" {
					fmt.Fprint(w, "8.8.8.8")
					return
				}
				if r.URL.Path == "/unexpected" {
					redirects.Add(1)
					fmt.Fprint(w, `KadabraRootContainer`)
					return
				}
				if tc.name == "timeout" {
					<-r.Context().Done()
					return
				}
				if tc.status == 302 {
					w.Header().Set("Location", "/unexpected")
				}
				if tc.header != "" {
					w.Header().Set("Cf-Mitigated", tc.header)
				}
				if tc.name == "large_header" {
					w.Header().Set("X-Large", strings.Repeat("x", 10000))
				}
				if tc.name == "broken_body" {
					w.Header().Set("Content-Length", "9999")
				}
				if tc.name == "unsupported_encoding" {
					w.Header().Set("Content-Encoding", "br")
				}
				if strings.HasPrefix(tc.name, "gzip") {
					var b bytes.Buffer
					gz := gzip.NewWriter(&b)
					fmt.Fprint(gz, tc.body)
					gz.Close()
					body := b.Bytes()
					if tc.name == "gzip_broken" {
						body = body[:len(body)-4]
					}
					w.Header().Set("Content-Encoding", "gzip")
					w.Write(body)
					return
				}
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			})
			target = unlockTarget(target)
			rep, err := New(&config.Config{}, nil).coreNodes(context.Background(), nativeEgressInput(nodes.BackendMihomo, []string{srv.Listener.Addr().String()}), CoreNodeOptions{MihomoBin: bin, UnlockIDs: []string{"meta_ai"}}, target)
			if err != nil {
				t.Fatal(err)
			}
			if tc.name == "timeout" {
				assertUnlockCleared(t, rep)
				return
			}
			rows := egressRows(t, rep)
			if rep.Data.(map[string]any)["measurement_status"] != "completed" || len(rows[0].Unlock) != 1 || rows[0].Unlock[0].Status != tc.want || rows[0].EgressIP != "8.8.8.8" {
				t.Fatalf("wrong conservative result: %+v", rep)
			}
		})
	}
	if redirects.Load() != 0 {
		t.Fatal("redirect followed")
	}
	assertEgressReaped(t, bin, 15)
}

func TestCoreNodeUnlockSelectionOfflineAndDefault(t *testing.T) {
	bin := egressFixture(t)
	var hits atomic.Int32
	srv, target := tlsEgressOrigin(t, func(w http.ResponseWriter, r *http.Request) { hits.Add(1); fmt.Fprint(w, "8.8.8.8") })
	target = unlockTarget(target)
	input := nativeEgressInput(nodes.BackendMihomo, []string{srv.Listener.Addr().String()})
	svc := New(&config.Config{}, nil)
	for _, ids := range [][]string{{"unknown-secret"}, {"apple", "apple"}, {""}, {"apple", "meta_ai", "claude", "chatgpt", "netflix"}, {" apple"}, {"youtube_cdn"}} {
		_, err := svc.coreNodes(context.Background(), input, CoreNodeOptions{MihomoBin: bin, UnlockIDs: ids}, target)
		if !errors.Is(err, ErrCoreNodesUnlock) {
			t.Fatalf("invalid IDs accepted: %v", err)
		}
	}
	svc.Cfg.Offline = true
	rep, err := svc.coreNodes(context.Background(), input, CoreNodeOptions{MihomoBin: bin, UnlockIDs: []string{"apple"}}, target)
	if err != nil {
		t.Fatal(err)
	}
	assertUnlockCleared(t, rep)
	if hits.Load() != 0 {
		t.Fatal("invalid/offline request")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(bin), "egress-audit.jsonl")); !os.IsNotExist(err) {
		t.Fatal("invalid/offline started core")
	}
	svc.Cfg.Offline = false
	rep, err = svc.coreNodes(context.Background(), input, CoreNodeOptions{MihomoBin: bin}, target)
	if err != nil || hits.Load() != 1 || len(egressRows(t, rep)[0].Unlock) != 0 {
		t.Fatalf("default changed: %+v %v hits=%d", rep, err, hits.Load())
	}
	assertEgressReaped(t, bin, 1)
}

func TestCoreNodeUnlockRevokesWholeBatch(t *testing.T) {
	bin := egressFixture(t)
	for _, backend := range []nodes.Backend{nodes.BackendMihomo, nodes.BackendSingBox} {
		for _, mode := range []string{"cancel", "deadline", "exit-connect", "lose-owner"} {
			t.Run(string(backend)+"/"+mode, func(t *testing.T) {
				positive := make(chan struct{})
				blocked := make(chan struct{})
				var yesOnce, blockOnce sync.Once
				a, target := tlsEgressOrigin(t, func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/" {
						fmt.Fprint(w, "8.8.8.8")
						return
					}
					fmt.Fprint(w, "US")
					yesOnce.Do(func() { close(positive) })
				})
				b, _ := tlsEgressOrigin(t, func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/" {
						fmt.Fprint(w, "1.1.1.1")
						return
					}
					// Let the other node finish reading its positive before the
					// late batch invalidation, rather than only racing startup.
					select {
					case <-positive:
					case <-r.Context().Done():
						return
					}
					time.Sleep(40 * time.Millisecond)
					blockOnce.Do(func() { close(blocked) })
					if mode == "lose-owner" {
						// The established tunnel can still deliver a valid
						// positive while its listener no longer belongs to
						// any live endpoint. Do not confuse a 5s request timeout
						// with actual lifetime ownership revocation.
						ticker := time.NewTicker(5 * time.Millisecond)
						defer ticker.Stop()
						for {
							if _, err := os.Stat(filepath.Join(filepath.Dir(bin), "listener-revoked")); err == nil {
								fmt.Fprint(w, "US")
								return
							}
							select {
							case <-ticker.C:
							case <-r.Context().Done():
								return
							}
						}
					}
					<-r.Context().Done()
				})
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if mode == "deadline" {
					ctx, cancel = context.WithTimeout(context.Background(), time.Second)
					defer cancel()
				}
				if mode == "cancel" || mode == "lose-owner" || mode == "exit-connect" {
					go func() {
						select {
						case <-positive:
						case <-ctx.Done():
							return
						}
						select {
						case <-blocked:
							if mode == "lose-owner" {
								os.WriteFile(filepath.Join(filepath.Dir(bin), "revoke-listener"), []byte("ready"), 0600)
							} else if mode == "exit-connect" {
								os.WriteFile(filepath.Join(filepath.Dir(bin), "exit-core"), nil, 0600)
							} else {
								cancel()
							}
						case <-ctx.Done():
						}
					}()
				}
				badMode := "fixture-pass"
				if mode == "exit-connect" || mode == "lose-owner" {
					badMode = mode
					if mode == "exit-connect" {
						badMode = "exit-event"
					}
				}
				input := nativeEgressInput(backend, []string{a.Listener.Addr().String(), b.Listener.Addr().String()}, "fixture-pass", badMode)
				defer os.Remove(filepath.Join(filepath.Dir(bin), "revoke-listener"))
				defer os.Remove(filepath.Join(filepath.Dir(bin), "listener-revoked"))
				defer os.Remove(filepath.Join(filepath.Dir(bin), "exit-core"))
				start := time.Now()
				rep, err := New(&config.Config{}, nil).coreNodes(ctx, input, CoreNodeOptions{MihomoBin: bin, SingBoxBin: bin, UnlockIDs: []string{"apple"}}, unlockTarget(target))
				if err != nil {
					t.Fatal(err)
				}
				assertUnlockCleared(t, rep)
				select {
				case <-positive:
				default:
					t.Fatal("test never obtained positive before invalidation")
				}
				if time.Since(start) > 2*time.Second {
					t.Fatal("revocation did not promptly cancel service request")
				}
			})
		}
	}
	assertEgressReaped(t, bin, 16)
}

func TestCoreNodeUnlockNoDirectOrEnvironmentFallback(t *testing.T) {
	var originHits, envHits atomic.Int32
	_, target := tlsEgressOrigin(t, func(w http.ResponseWriter, r *http.Request) { originHits.Add(1); fmt.Fprint(w, "US") })
	env := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { envHits.Add(1) }))
	defer env.Close()
	for _, key := range []string{"HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"} {
		t.Setenv(key, env.URL)
	}
	t.Setenv("NO_PROXY", "*")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	gate := func() error { return nil }
	for _, endpoint := range []string{"", "http://127.0.0.1:1", "http://u:p@" + addr, "http://u:p@example.invalid:1"} {
		client, close, err := coreHTTPClient(endpoint, target.roots, gate)
		if err != nil {
			continue
		}
		got, _ := queryCoreUnlock(context.Background(), client, []string{"apple"}, unlockTarget(target).unlockURL, func(context.Context) error { return gate() })
		close()
		if got[0].Status != unlock.Abstain {
			t.Fatal("dead proxy accepted")
		}
	}
	if originHits.Load() != 0 || envHits.Load() != 0 {
		t.Fatal("host/env fallback")
	}
}

func TestCoreNodeUnlockRequestBudgetAndGate(t *testing.T) {
	bin := egressFixture(t)
	var hits atomic.Int32
	srv, target := tlsEgressOrigin(t, func(w http.ResponseWriter, r *http.Request) { hits.Add(1); fmt.Fprint(w, "US") })
	path := filepath.Join(t.TempDir(), "input")
	os.WriteFile(path, []byte(nativeEgressInput(nodes.BackendMihomo, []string{srv.Listener.Addr().String()})), 0600)
	runner := &nodes.ExecRunner{Bin: bin, Backend: nodes.BackendMihomo}
	defer runner.Stop()
	if _, err := runner.Start(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	ep := runner.Endpoints()["z-secret-name"]
	revoked := false
	gate := func() error {
		if revoked {
			return nodes.ErrRunnerExit
		}
		return runner.Err()
	}
	client, close, err := coreHTTPClient(ep.HTTP, target.roots, gate)
	if err != nil {
		t.Fatal(err)
	}
	defer close()
	untrusted, untrustedClose, err := coreHTTPClient(ep.HTTP, nil, gate)
	if err != nil {
		t.Fatal(err)
	}
	result, _ := queryCoreUnlock(context.Background(), untrusted, []string{"apple"}, unlockTarget(target).unlockURL, func(context.Context) error { return gate() })
	untrustedClose()
	if result[0].Status != unlock.Abstain || hits.Load() != 0 {
		t.Fatal("unlock TLS verification bypassed")
	}
	getter := &coreUnlockGetter{client: client, allowed: map[string]bool{coreUnlockURLs["apple"][0]: true}, mapURL: unlockTarget(target).unlockURL, gate: func(context.Context) error { return gate() }}
	raw := coreUnlockURLs["apple"][0]
	if getter.Get(context.Background(), "https://arbitrary.invalid/", nil).Err == nil {
		t.Fatal("arbitrary URL allowed")
	}
	if getter.Get(context.Background(), raw, map[string]string{"Cookie": "secret"}).Err == nil {
		t.Fatal("arbitrary header allowed")
	}
	// Invalid headers consume a slot as well, conservatively bounding all attempts.
	for i := getter.calls; i < coreUnlockRequests; i++ {
		if getter.Get(context.Background(), raw, nil).Err != nil {
			t.Fatal("budget request failed")
		}
	}
	before := hits.Load()
	if getter.Get(context.Background(), raw, nil).Err == nil || hits.Load() != before || before != coreUnlockRequests-1 {
		t.Fatal("request budget escaped")
	}
	getter.calls = 0
	revoked = true
	if getter.Get(context.Background(), raw, nil).Err == nil || hits.Load() != before {
		t.Fatal("revoked endpoint reused")
	}
	revoked = false
	runner.Stop()
	if getter.Get(context.Background(), raw, nil).Err == nil || hits.Load() != before {
		t.Fatal("stopped endpoint reused")
	}

}

func TestCoreNodeUnlockClaudeAndRequiredPathFailure(t *testing.T) {
	bin := egressFixture(t)
	for _, failTrace := range []bool{false, true} {
		handler := func(deny bool) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/" {
					fmt.Fprint(w, "8.8.4.4")
					return
				}
				raw := r.URL.Query().Get("url")
				switch raw {
				case coreUnlockURLs["claude"][0]:
					if deny {
						w.WriteHeader(403)
						fmt.Fprint(w, "app-unavailable-in-region")
					} else {
						fmt.Fprint(w, "Log in to Claude")
					}
				case coreUnlockURLs["claude"][1]:
					if failTrace {
						w.WriteHeader(503)
						fmt.Fprint(w, "loc=US\n")
					} else {
						fmt.Fprint(w, "loc=US\n")
					}
				case coreUnlockURLs["chatgpt"][0]:
					fmt.Fprint(w, `{"requires_cookie_consent":false,"country":"US"}`)
				case coreUnlockURLs["chatgpt"][1]:
					if deny {
						w.WriteHeader(403)
						fmt.Fprint(w, "ChatGPT is not available in your country")
					} else {
						fmt.Fprint(w, `ChatGPT <a href="https://auth.openai.com/authorize">Log in</a>`)
					}
				case coreUnlockURLs["chatgpt"][2]:
					if failTrace {
						w.WriteHeader(503)
					}
					fmt.Fprint(w, "loc=US\n")
				default:
					t.Error("unexpected path")
				}
			}
		}
		a, target := tlsEgressOrigin(t, handler(false))
		b, _ := tlsEgressOrigin(t, handler(true))
		rep, err := New(&config.Config{}, nil).coreNodes(context.Background(), nativeEgressInput(nodes.BackendMihomo, []string{a.Listener.Addr().String(), b.Listener.Addr().String()}), CoreNodeOptions{MihomoBin: bin, UnlockIDs: []string{"claude", "chatgpt"}}, unlockTarget(target))
		if err != nil {
			t.Fatal(err)
		}
		for i, row := range egressRows(t, rep) {
			if len(row.Unlock) != 2 {
				t.Fatalf("missing service results: %+v", rep)
			}
			wants := []string{unlock.Yes, unlock.Yes}
			if i == 1 {
				wants = []string{unlock.No, unlock.WebOnly}
			}
			for j, result := range row.Unlock {
				want := wants[j]
				if failTrace {
					want = unlock.Abstain
				}
				if result.Status != want {
					t.Fatalf("path failure or node attribution: %+v", rep)
				}
			}
		}
	}
	assertEgressReaped(t, bin, 4)
}

func TestCoreNodeUnlockCatalogueSubset(t *testing.T) {
	catalogue := map[string]bool{}
	for _, id := range unlock.Catalogue() {
		catalogue[id] = true
	}
	for id, urls := range coreUnlockURLs {
		if !catalogue[id] || len(urls) > 3 {
			t.Fatal("unsupported service or unbounded path")
		}
		for _, raw := range urls {
			u, err := url.Parse(raw)
			if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" {
				t.Fatal("unsafe catalogue URL")
			}
		}
	}
}

func TestCoreNodeUnlockBatchProjectionClearsExistingPositive(t *testing.T) {
	svc := New(&config.Config{}, nil)
	rows := []CoreNodeObservation{{Index: 1, Backend: nodes.BackendMihomo, EgressIP: "8.8.8.8", Status: "observed", Unlock: []CoreNodeUnlockObservation{{Service: "apple", Status: unlock.Yes, Region: "US", Evidence: "recognized_catalog_markers"}}}}
	for _, reason := range []string{"canceled", "timeout", "core_unavailable", "cleanup_incomplete", "batch_incomplete"} {
		rep := svc.coreNodeReport(rows, "unavailable", reason)
		assertUnlockCleared(t, rep)
	}
	if rows[0].EgressIP == "" || len(rows[0].Unlock) == 0 {
		t.Fatal("projection mutated source rows")
	}
}
