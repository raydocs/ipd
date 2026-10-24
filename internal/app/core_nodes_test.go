package app

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"ipd/internal/config"
	"ipd/internal/nodes"
)

// One real executable build per test tree, removed by the owning test cleanup.
func egressFixture(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "core")
	cmd := exec.Command("go", "build", "-o", bin, "./testdata/egressfixture")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fixture build: %v: %s", err, out)
	}
	return bin
}
func nativeEgressInput(backend nodes.Backend, origins []string, modes ...string) string {
	var entries []string
	for i, origin := range origins {
		host, port, _ := net.SplitHostPort(origin)
		n, _ := strconv.Atoi(port)
		mode := "fixture-pass"
		if i < len(modes) {
			mode = modes[i]
		}
		// Deliberately reverse lexical order: the original index must NOT be sorted.
		name := "z-secret-name"
		if i > 0 {
			name = "a-secret-name" + strconv.Itoa(i)
		}
		if backend == nodes.BackendMihomo {
			entries = append(entries, fmt.Sprintf("{name: %q, type: ss, server: %q, port: %d, cipher: aes-128-gcm, password: %q}", name, host, n, mode))
		} else {
			entries = append(entries, fmt.Sprintf(`{"tag":%q,"type":"shadowsocks","server":%q,"server_port":%d,"method":"aes-128-gcm","password":%q}`, name, host, n, mode))
		}
	}
	if backend == nodes.BackendMihomo {
		return "proxies: [" + strings.Join(entries, ",") + "]"
	}
	return `{"outbounds":[` + strings.Join(entries, ",") + ` ]}`
}
func tlsEgressOrigin(t *testing.T, h http.HandlerFunc) (*httptest.Server, coreProbeTarget) {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	return srv, coreProbeTarget{url: srv.URL, roots: roots}
}
func egressRows(t *testing.T, rep Report) []CoreNodeObservation {
	t.Helper()
	return rep.Data.(map[string]any)["nodes"].([]CoreNodeObservation)
}
func assertCoreUnknown(t *testing.T, rep Report) {
	t.Helper()
	if rep.Verdict != "abstain" || rep.Data.(map[string]any)["measurement_status"] != "unavailable" {
		t.Fatalf("not abstain/unavailable: %+v", rep)
	}
	for _, row := range egressRows(t, rep) {
		if row.EgressIP != "" || row.Status != "unknown" || row.Reason == "" {
			t.Fatalf("partial evidence leaked: %+v", row)
		}
	}
}
func assertEgressReaped(t *testing.T, bin string, want int) {
	t.Helper()
	b, e := os.ReadFile(filepath.Join(filepath.Dir(bin), "egress-audit.jsonl"))
	if e != nil {
		t.Fatal(e)
	}
	scanner := bufio.NewScanner(strings.NewReader(string(b)))
	n := 0
	for scanner.Scan() {
		var a struct {
			PID int      `json:"pid"`
			Dir string   `json:"dir"`
			Env []string `json:"env"`
		}
		if json.Unmarshal(scanner.Bytes(), &a) != nil {
			t.Fatal("audit parse")
		}
		n++
		if _, e := os.Stat(a.Dir); !os.IsNotExist(e) {
			t.Fatalf("owned config not cleaned: %v", e)
		}
		p, e := os.FindProcess(a.PID)
		if e == nil && p.Signal(syscall.Signal(0)) == nil {
			t.Fatalf("child %d remains", a.PID)
		}
		if len(a.Env) != 2 {
			t.Fatalf("inherited environment: %v", a.Env)
		}
	}
	if n != want {
		t.Fatalf("launch count %d want %d", n, want)
	}
}
func TestCoreNodesProductionPath(t *testing.T) {
	bin := egressFixture(t)
	var envCalls atomic.Int32
	env := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { envCalls.Add(1); fmt.Fprint(w, "9.9.9.9") }))
	defer env.Close()
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(key, env.URL)
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	t.Setenv("EGRESS_SECRET", "must-not-inherit")
	var active, maxActive atomic.Int32
	handler := func(ip string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			n := active.Add(1)
			defer active.Add(-1)
			for {
				old := maxActive.Load()
				if n <= old || maxActive.CompareAndSwap(old, n) {
					break
				}
			}
			if r.Header.Get("Proxy-Authorization") != "" {
				t.Error("proxy auth leaked through TLS")
			}
			time.Sleep(30 * time.Millisecond)
			fmt.Fprint(w, ip)
		}
	}
	a, target := tlsEgressOrigin(t, handler("8.8.8.8"))
	b, _ := tlsEgressOrigin(t, handler("1.1.1.1"))
	svc := New(&config.Config{Proxy: env.URL}, nil)
	for _, backend := range []nodes.Backend{nodes.BackendMihomo, nodes.BackendSingBox} {
		t.Run(string(backend), func(t *testing.T) {
			input := nativeEgressInput(backend, []string{a.Listener.Addr().String(), b.Listener.Addr().String()})
			if backend == nodes.BackendSingBox {
				p := filepath.Join(t.TempDir(), "nodes.json")
				os.WriteFile(p, []byte(input), 0600)
				input = p
			}
			rep, e := svc.coreNodes(context.Background(), input, CoreNodeOptions{MihomoBin: bin, SingBoxBin: bin}, target)
			if e != nil {
				t.Fatal(e)
			}
			rows := egressRows(t, rep)
			expected := []CoreNodeObservation{{Index: 1, Backend: backend, EgressIP: "8.8.8.8", Status: "observed"}, {Index: 2, Backend: backend, EgressIP: "1.1.1.1", Status: "observed"}}
			if !reflect.DeepEqual(rows, expected) || rep.Verdict != "abstain" || rep.Data.(map[string]any)["measurement_status"] != "completed" {
				t.Fatalf("wrong ordered observations: %+v", rep)
			}
			encoded, _ := json.Marshal(rep)
			for _, secret := range []string{"secret-name", "fixture-pass", "127.0.0.1", "renamed_yaml", "grade", "reachable", "socks5://", "ipd-core-", "password"} {
				if strings.Contains(string(encoded), secret) {
					t.Fatalf("public result leaks %q: %s", secret, encoded)
				}
			}
		})
	}
	if envCalls.Load() != 0 {
		t.Fatal("environment proxy used")
	}
	if maxActive.Load() < 2 || maxActive.Load() > 4 {
		t.Fatalf("bad concurrency %d", maxActive.Load())
	}
	assertEgressReaped(t, bin, 4)
}

func TestCoreNodesFailuresWithholdAndClean(t *testing.T) {
	bin := egressFixture(t)
	launches := 0
	for _, backend := range []nodes.Backend{nodes.BackendMihomo, nodes.BackendSingBox} {
		for _, mode := range []string{"partial", "reject", "exit-start", "exit-connect", "cancel"} {
			t.Run(string(backend)+"/"+mode, func(t *testing.T) {
				entered := make(chan struct{})
				var once sync.Once
				good, target := tlsEgressOrigin(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "8.8.4.4") })
				bad, _ := tlsEgressOrigin(t, func(w http.ResponseWriter, r *http.Request) {
					once.Do(func() { close(entered) })
					if mode == "cancel" || mode == "exit-connect" {
						select {
						case <-r.Context().Done():
							return
						case <-time.After(3 * time.Second):
							return
						}
					}
					fmt.Fprint(w, "not-an-IP secret-server secret-pass")
				})
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				if mode == "cancel" {
					go func() {
						select {
						case <-entered:
							cancel()
						case <-ctx.Done():
						}
					}()
				}
				badMode := "fixture-pass"
				if mode != "partial" && mode != "cancel" {
					badMode = mode
				}
				input := nativeEgressInput(backend, []string{good.Listener.Addr().String(), bad.Listener.Addr().String()}, "fixture-pass", badMode)
				start := time.Now()
				rep, e := New(&config.Config{}, nil).coreNodes(ctx, input, CoreNodeOptions{MihomoBin: bin, SingBoxBin: bin}, target)
				if e != nil {
					t.Fatal(e)
				}
				assertCoreUnknown(t, rep)
				if (mode == "cancel" || mode == "exit-connect") && time.Since(start) > 2*time.Second {
					t.Fatalf("revocation/cancel delayed: %s", time.Since(start))
				}
				launches += 2
			})
		}
	}
	assertEgressReaped(t, bin, launches)
}

func TestCoreNodesRejectsBeforeProcessAndOffline(t *testing.T) {
	bin := egressFixture(t)
	native := nativeEgressInput(nodes.BackendMihomo, []string{"127.0.0.1:1"})
	svc := New(&config.Config{}, nil)
	var network atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { network.Add(1) }))
	defer server.Close()
	file := filepath.Join(t.TempDir(), "native")
	os.WriteFile(file, []byte(native), 0600)
	link := filepath.Join(t.TempDir(), "link")
	os.Symlink(file, link)
	for _, tc := range []struct {
		source string
		opts   CoreNodeOptions
		want   error
	}{
		{server.URL, CoreNodeOptions{MihomoBin: bin}, ErrCoreNodesInput},
		{"ss://secret:password@server:443", CoreNodeOptions{MihomoBin: bin}, ErrCoreNodesInput},
		{"c3M6Ly9zZWNyZXQ=", CoreNodeOptions{MihomoBin: bin}, ErrCoreNodesInput},
		{link, CoreNodeOptions{MihomoBin: bin}, ErrCoreNodesInput},
		{t.TempDir(), CoreNodeOptions{MihomoBin: bin}, ErrCoreNodesInput},
		{strings.Repeat("x", coreSourceLimit+1), CoreNodeOptions{MihomoBin: bin}, ErrCoreNodesInput},
		{native, CoreNodeOptions{Backend: nodes.BackendSingBox, SingBoxBin: bin}, ErrCoreNodesUnsupported},
		{native + "\ndns: {enable: true}", CoreNodeOptions{MihomoBin: bin}, ErrCoreNodesUnsupported},
		{native, CoreNodeOptions{MihomoBin: "core"}, ErrCoreNodesExecutable},
		{native, CoreNodeOptions{SingBoxBin: bin}, ErrCoreNodesExecutable},
		{"proxies: [{name: x, name: y}]", CoreNodeOptions{MihomoBin: bin}, ErrCoreNodesInput},
	} {
		_, e := svc.CoreNodes(context.Background(), tc.source, tc.opts)
		if !errors.Is(e, tc.want) {
			t.Errorf("got %v want %v", e, tc.want)
		}
	}
	svc.Cfg.Offline = true
	rep, e := svc.CoreNodes(context.Background(), server.URL, CoreNodeOptions{MihomoBin: bin, SingBoxBin: bin})
	if e != nil {
		t.Fatal(e)
	}
	assertCoreUnknown(t, rep)
	if network.Load() != 0 {
		t.Fatal("source fetched")
	}
	if _, e := os.Stat(filepath.Join(filepath.Dir(bin), "egress-audit.jsonl")); !os.IsNotExist(e) {
		t.Fatal("rejection/offline launched a process")
	}
}

func TestCoreEgressHTTPSAndSOCKS(t *testing.T) {
	bin := egressFixture(t)
	var redirectHits atomic.Int32
	srv, target := tlsEgressOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/unexpected", http.StatusFound)
		case "/unexpected":
			redirectHits.Add(1)
			fmt.Fprint(w, "8.8.8.8")
		case "/large":
			fmt.Fprint(w, strings.Repeat("8", 257))
		case "/private":
			fmt.Fprint(w, "127.0.0.1")
		case "/stall":
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		default:
			fmt.Fprint(w, "8.8.8.8\n")
		}
	})
	for _, backend := range []nodes.Backend{nodes.BackendMihomo, nodes.BackendSingBox} {
		t.Run(string(backend), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input")
			os.WriteFile(path, []byte(nativeEgressInput(backend, []string{srv.Listener.Addr().String()})), 0600)
			runner := &nodes.ExecRunner{Bin: bin, Backend: backend}
			defer runner.Stop()
			if _, e := runner.Start(context.Background(), path); e != nil {
				t.Fatal(e)
			}
			ep := runner.Endpoints()["z-secret-name"]
			gate := func() error {
				if runner.Err() != nil || len(runner.Endpoints()) == 0 {
					return nodes.ErrRunnerExit
				}
				return nil
			}
			for _, endpoint := range []string{ep.HTTP, ep.SOCKS} {
				ip, e := queryCoreEgress(context.Background(), endpoint, target, gate)
				if e != nil || ip != "8.8.8.8" {
					t.Fatalf("proxy query: %q %v", ip, e)
				}
				for _, suffix := range []string{"/redirect", "/large", "/private"} {
					bad := target
					bad.url += suffix
					if ip, e := queryCoreEgress(context.Background(), endpoint, bad, gate); e == nil || ip != "" {
						t.Fatal("invalid response accepted")
					}
				}
				untrusted := target
				untrusted.roots = nil
				if _, e := queryCoreEgress(context.Background(), endpoint, untrusted, gate); e == nil {
					t.Fatal("TLS verification bypassed")
				}
				stalled := target
				stalled.url += "/stall"
				ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				if _, e := queryCoreEgress(ctx, endpoint, stalled, gate); e == nil {
					t.Fatal("body timeout ignored")
				}
				cancel()
			}
			runner.Stop()
			if _, e := queryCoreEgress(context.Background(), ep.HTTP, target, gate); e == nil {
				t.Fatal("stale endpoint accepted")
			}
			if redirectHits.Load() != 0 {
				t.Fatal("redirect followed")
			}
		})
	}
	assertEgressReaped(t, bin, 2)
}

func TestCoreEgressNoDirectOrEnvironmentFallback(t *testing.T) {
	var originHits, envHits atomic.Int32
	origin, target := tlsEgressOrigin(t, func(w http.ResponseWriter, r *http.Request) { originHits.Add(1); fmt.Fprint(w, "8.8.8.8") })
	env := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { envHits.Add(1) }))
	defer env.Close()
	for _, key := range []string{"HTTPS_PROXY", "ALL_PROXY", "https_proxy", "all_proxy"} {
		t.Setenv(key, env.URL)
	}
	t.Setenv("NO_PROXY", "*")
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	addr := ln.Addr().String()
	ln.Close()
	gate := func() error { return nil }
	for _, endpoint := range []string{"", "http://127.0.0.1:1234", "http://u:p@" + addr, "socks5://u:p@" + addr, "http://u:p@example.invalid:1"} {
		if _, e := queryCoreEgress(context.Background(), endpoint, target, gate); e == nil {
			t.Fatal("missing/dead proxy accepted")
		}
	}
	_ = origin
	if originHits.Load() != 0 || envHits.Load() != 0 {
		t.Fatal("direct or environment fallback")
	}
	// Credentials are local to one client, not forwarded or pooled across nodes.
	u, _ := url.Parse(target.url)
	if u.Scheme != "https" {
		t.Fatal("bad fixture")
	}
}
