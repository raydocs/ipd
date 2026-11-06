package nodes

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

var fixtureBuild sync.Once
var fixtureBin string
var fixtureErr error

func coreFixture(t *testing.T) string {
	t.Helper()
	fixtureBuild.Do(func() {
		dir, err := os.MkdirTemp("", "ipd-core-fixture-build-")
		if err != nil {
			fixtureErr = err
			return
		}
		fixtureBin = filepath.Join(dir, "corefixture")
		cmd := exec.Command("go", "build", "-o", fixtureBin, "./testdata/corefixture")
		output, err := cmd.CombinedOutput()
		if err != nil {
			fixtureErr = fmtBuildError{err, string(output)}
		}
	})
	if fixtureErr != nil {
		t.Fatal(fixtureErr)
	}
	return fixtureBin
}

type fmtBuildError struct {
	err    error
	output string
}

func (e fmtBuildError) Error() string { return e.err.Error() + e.output }

func runnerInputConfig(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "subscription.yaml")
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestMihomoStartsIsolatedChannels(t *testing.T) {
	m := &Mihomo{Bin: coreFixture(t)}
	defer m.Stop()
	path := runnerInputConfig(t, `proxies:
 - {name: alpha, type: ss, server: alpha.invalid, port: 443, cipher: aes-128-gcm, password: public-fixture}
 - {name: beta, type: ss, server: beta.invalid, port: 443, cipher: aes-128-gcm, password: public-fixture}
`)
	channels, err := m.Start(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if len(channels) != 2 || channels["alpha"] == "" || channels["beta"] == "" || channels["alpha"] == channels["beta"] {
		t.Fatalf("need two distinct live channels; got %#v", channels)
	}
}

func TestMain(m *testing.M) {
	code := m.Run()
	if fixtureBin != "" {
		_ = os.RemoveAll(filepath.Dir(fixtureBin))
	}
	os.Exit(code)
}

const fixtureSS = `{name: alpha, type: ss, server: alpha.invalid, port: 443, cipher: aes-128-gcm, password: public-fixture}`

func fixtureSubscription(mode string) string {
	return "proxies: [" + strings.Replace(fixtureSS, "public-fixture", mode, 1) + "]"
}

type fixtureState struct {
	PID    int      `json:"pid"`
	Env    []string `json:"env"`
	Config string   `json:"config"`
}

func fixtureStates(t *testing.T, root string, want int) []fixtureState {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		files, err := filepath.Glob(filepath.Join(root, "ipd-core-*", "*", "fixture-state.json"))
		if err != nil {
			t.Fatal(err)
		}
		if len(files) == want {
			var states []fixtureState
			for _, f := range files {
				b, err := os.ReadFile(f)
				if err != nil {
					continue
				}
				var s fixtureState
				if json.Unmarshal(b, &s) == nil {
					states = append(states, s)
				}
			}
			if len(states) == want {
				return states
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("fixture did not start expected children")
	return nil
}
func awaitRunner(t *testing.T, m *ExecRunner) {
	t.Helper()
	m.mu.Lock()
	r := m.run
	m.mu.Unlock()
	select {
	case <-r.done:
	case <-time.After(4 * time.Second):
		t.Fatal("runner failed to reap children")
	}
}
func assertReaped(t *testing.T, states []fixtureState) {
	t.Helper()
	for _, state := range states {
		p, err := os.FindProcess(state.PID)
		if err != nil {
			continue
		}
		err = p.Signal(syscall.Signal(0))
		_ = p.Release()
		if err == nil {
			t.Errorf("child %d still exists (including possible zombie)", state.PID)
		}
	}
}
func assertRootClean(t *testing.T, root string) {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "ipd-core-") {
			t.Errorf("owned private directory leaked: %s", e.Name())
		}
	}
}
func checkSOCKSMarker(t *testing.T, endpoint, marker string) {
	t.Helper()
	u, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	d, err := proxy.FromURL(u, &net.Dialer{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	c, err := d.Dial("tcp", "fixture.invalid:80")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	b, err := io.ReadAll(c)
	if err != nil || string(b) != marker {
		t.Fatalf("SOCKS wiring: got %q err %v", b, err)
	}
}
func checkHTTPMarker(t *testing.T, endpoint, marker string) {
	t.Helper()
	u, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	tr := &http.Transport{Proxy: http.ProxyURL(u)}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: time.Second}
	resp, err := client.Get("http://fixture.invalid/identity")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != 200 || string(b) != marker {
		t.Fatalf("HTTP wiring: status %d body %q err %v", resp.StatusCode, b, err)
	}
}

func TestExecRunnerFiveProtocolsAndIsolation(t *testing.T) {
	root := t.TempDir()
	sentinel := filepath.Join(root, "unowned-secret")
	if err := os.WriteFile(sentinel, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	// No inherited controller/run-script/proxy/loader variables may reach the core.
	for _, k := range []string{"CLASH_OVERRIDE_EXTERNAL_CONTROLLER", "CLASH_OVERRIDE_RUN_SCRIPT", "CLASH_CONFIG_STRING", "HTTP_PROXY", "LD_PRELOAD"} {
		t.Setenv(k, "hostile-public-fixture")
	}
	text := `metadata: {name: public-fixture, description: display-only}
proxies:
 - {name: vl, type: vless, server: vl.invalid, port: 443, uuid: 00000000-0000-4000-8000-000000000000, tls: true, flow: xtls-rprx-vision, servername: example.invalid, client-fingerprint: chrome, reality-opts: {public-key: public-fixture, short-id: abcd}}
 - {name: vm, type: vmess, server: vm.invalid, port: 443, uuid: 00000000-0000-4000-8000-000000000000, alterId: 0, cipher: auto, network: ws, ws-opts: {path: /fixture, headers: {Host: example.invalid}, max-early-data: 1024, early-data-header-name: Sec-WebSocket-Protocol}}
 - {name: tr, type: trojan, server: tr.invalid, port: 443, password: public-fixture, sni: example.invalid, network: grpc, grpc-opts: {grpc-service-name: fixture}, alpn: [h2], skip-cert-verify: true}
 - {name: hy, type: hysteria2, server: hy.invalid, port: 443, ports: '443,8443', hop-interval: 30s, password: public-fixture, obfs: salamander, obfs-password: public-obfs, up: '10 Mbps', down: '50 Mbps', sni: example.invalid}
 - {name: ss, type: ss, server: ss.invalid, port: 443, cipher: aes-128-gcm, password: public-fixture, udp: true, udp-over-tcp: true}
`
	input := runnerInputConfig(t, text)
	m := &ExecRunner{Bin: coreFixture(t), TempRoot: root}
	defer m.Stop()
	socks, err := m.Start(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	states := fixtureStates(t, root, 5)
	if len(socks) != 5 || len(m.Endpoints()) != 5 {
		t.Fatal("missing channels")
	}
	original, err := runnerDocument([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	originals := original["proxies"].([]any)
	seenAddr := map[string]bool{}
	seenPID := map[int]bool{}
	seenPassword := map[string]bool{}
	for i, state := range states {
		if seenPID[state.PID] {
			t.Fatal("nodes share process")
		}
		seenPID[state.PID] = true
		for _, path := range []string{state.Config, filepath.Dir(state.Config), filepath.Dir(filepath.Dir(state.Config))} {
			st, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			want := os.FileMode(0600)
			if st.IsDir() {
				want = 0700
			}
			if st.Mode().Perm() != want {
				t.Errorf("insecure private mode %v", st.Mode())
			}
		}
		for _, e := range state.Env {
			if !strings.HasPrefix(e, "HOME=") && !strings.HasPrefix(e, "TMPDIR=") {
				t.Errorf("inherited environment %q", e)
			}
		}
		b, err := os.ReadFile(state.Config)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := runnerDocument(b)
		if err != nil {
			t.Fatal(err)
		}
		wantProxy := maps.Clone(originals[i].(map[string]any))
		name := wantProxy["name"].(string)
		wantProxy["name"] = "ipd-node"
		gotProxy := cfg["proxies"].([]any)
		if len(gotProxy) != 1 || !reflect.DeepEqual(gotProxy[0], wantProxy) {
			t.Fatal("protocol fields lost/changed or nodes shared")
		}
		if len(cfg) != 13 || cfg["external-controller"] != nil || cfg["run-script"] != nil || cfg["proxy-providers"] != nil || cfg["mixed-port"] != nil {
			t.Fatalf("unexpected global config keys: %v", maps.Keys(cfg))
		}
		if !reflect.DeepEqual(cfg["rules"], []any{"MATCH,REJECT"}) {
			t.Fatal("non-fail-closed fallback")
		}
		l := cfg["listeners"].([]any)[0].(map[string]any)
		if l["proxy"] != "ipd-node" || l["listen"] != "127.0.0.1" || l["udp"] != false {
			t.Fatal("unsafe listener")
		}
		ep := m.Endpoints()[name]
		u, err := url.Parse(ep.SOCKS)
		if err != nil {
			t.Fatal(err)
		}
		if u.Hostname() != "127.0.0.1" || seenAddr[u.Host] {
			t.Fatal("shared or nonloopback endpoint")
		}
		seenAddr[u.Host] = true
		password, _ := u.User.Password()
		if seenPassword[password] {
			t.Fatal("shared node authentication")
		}
		seenPassword[password] = true
		if socks[name] != ep.SOCKS {
			t.Fatal("Runner map differs from endpoint API")
		}
		checkSOCKSMarker(t, ep.SOCKS, name+".invalid")
		checkHTTPMarker(t, ep.HTTP, name+".invalid")
		if probeRunnerSOCKS(context.Background(), u.Host, "ipd", "wrong-password") == nil {
			t.Fatal("accepted another node's credential")
		}
	}
	endpoints := m.Endpoints()
	delete(endpoints, "ss")
	if len(m.Endpoints()) != 5 {
		t.Fatal("endpoint map not copied")
	}
	// Cleanup must not follow a symlink into an unowned location.
	if err := os.Symlink(sentinel, filepath.Join(filepath.Dir(states[0].Config), "unowned-link")); err != nil {
		t.Fatal(err)
	}
	m.Stop()
	m.Stop()
	assertReaped(t, states)
	assertRootClean(t, root)
	if m.Endpoints() != nil {
		t.Fatal("endpoints survive Stop")
	}
	for addr := range seenAddr {
		c, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			c.Close()
			t.Error("listener survives Stop")
		}
	}
	b, err := os.ReadFile(sentinel)
	if err != nil || string(b) != "keep" {
		t.Fatal("removed unowned file")
	}
	b, err = os.ReadFile(input)
	if err != nil || string(b) != text {
		t.Fatal("modified source configuration")
	}
}

func TestExecRunnerLifecycleFailures(t *testing.T) {
	for _, tt := range []struct {
		mode string
		want error
	}{
		{"fixture-exit", ErrRunnerExit}, {"fixture-stall", ErrRunnerReadiness}, {"fixture-collision", ErrRunnerReadiness}, {"fixture-socks-only", ErrRunnerReadiness},
	} {
		t.Run(tt.mode, func(t *testing.T) {
			root := t.TempDir()
			m := &ExecRunner{Bin: coreFixture(t), TempRoot: root, StartupTimeout: 350 * time.Millisecond}
			defer m.Stop()
			result := make(chan error, 1)
			go func() {
				_, err := m.Start(context.Background(), runnerInputConfig(t, fixtureSubscription(tt.mode)))
				result <- err
			}()
			var states []fixtureState
			if tt.mode != "fixture-exit" {
				states = fixtureStates(t, root, 1)
			}
			err := <-result
			if !errors.Is(err, tt.want) {
				t.Fatalf("want %v got %v", tt.want, err)
			}
			if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), root) {
				t.Fatal("raw process error exposed")
			}
			assertReaped(t, states)
			assertRootClean(t, root)
			if m.Endpoints() != nil {
				t.Fatal("failed startup published endpoints")
			}
		})
	}
}

func TestExecRunnerCancelStopBudgetAndRestart(t *testing.T) {
	for _, mode := range []string{"cancel-start", "stop-start", "budget-start", "cancel-live", "budget-live", "stop-live"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			m := &ExecRunner{Bin: coreFixture(t), TempRoot: root, StartupTimeout: 2 * time.Second, Budget: 3 * time.Second}
			defer m.Stop()
			if strings.HasPrefix(mode, "budget") {
				m.Budget = 600 * time.Millisecond
			}
			pass := "public-fixture"
			if strings.HasSuffix(mode, "start") {
				pass = "fixture-stall"
			}
			input := runnerInputConfig(t, fixtureSubscription(pass))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() { _, err := m.Start(ctx, input); result <- err }()
			states := fixtureStates(t, root, 1)
			if !strings.HasSuffix(mode, "start") {
				if err := <-result; err != nil {
					t.Fatal(err)
				}
			}
			if _, err := m.Start(ctx, input); !errors.Is(err, ErrRunnerBusy) {
				t.Fatalf("active Start: %v", err)
			}
			switch {
			case strings.HasPrefix(mode, "cancel"):
				cancel()
			case strings.HasPrefix(mode, "stop"):
				var wg sync.WaitGroup
				for range 8 {
					wg.Go(m.Stop)
				}
				wg.Wait()
			}
			awaitRunner(t, m)
			want := context.Canceled
			if strings.HasPrefix(mode, "budget") {
				want = context.DeadlineExceeded
			}
			if strings.HasSuffix(mode, "start") {
				if err := <-result; !errors.Is(err, want) {
					t.Fatalf("Start err %v", err)
				}
			}
			if !errors.Is(m.Err(), want) {
				t.Fatalf("terminal error %v want %v", m.Err(), want)
			}
			m.Stop()
			assertReaped(t, states)
			assertRootClean(t, root)
			m.Budget = time.Second
			if _, err := m.Start(context.Background(), runnerInputConfig(t, fixtureSubscription("public-fixture"))); err != nil {
				t.Fatalf("restart: %v", err)
			}
			m.Stop()
			assertRootClean(t, root)
		})
	}
}

func TestExecRunnerPeerExitReapsBatch(t *testing.T) {
	root := t.TempDir()
	m := &ExecRunner{Bin: coreFixture(t), TempRoot: root}
	defer m.Stop()
	text := "proxies: [" + fixtureSS + ", " + strings.Replace(strings.Replace(fixtureSS, "alpha", "beta", -1), "public-fixture", "fixture-late-exit", 1) + "]"
	if _, err := m.Start(context.Background(), runnerInputConfig(t, text)); err != nil {
		t.Fatal(err)
	}
	states := fixtureStates(t, root, 2)
	awaitRunner(t, m)
	if !errors.Is(m.Err(), ErrRunnerExit) {
		t.Fatalf("peer exit: %v", m.Err())
	}
	assertReaped(t, states)
	assertRootClean(t, root)
	if m.Endpoints() != nil {
		t.Fatal("peer endpoints survive failure")
	}
}

func TestExecRunnerExecutableAndStorageErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := &ExecRunner{Bin: coreFixture(t)}
	if _, err := m.Start(ctx, "never-read"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	path := runnerInputConfig(t, fixtureSubscription("public-fixture"))
	for _, bin := range []string{"", "mihomo", "/nonexistent/credential-secret", t.TempDir(), path} {
		m := &ExecRunner{Bin: bin}
		_, err := m.Start(context.Background(), path)
		if !errors.Is(err, ErrRunnerExecutable) || strings.Contains(err.Error(), "credential-secret") {
			t.Fatalf("executable error: %v", err)
		}
	}
	root := t.TempDir()
	bad := filepath.Join(root, "invalid-program")
	if err := os.WriteFile(bad, []byte("not an executable\ncredential-secret"), 0700); err != nil {
		t.Fatal(err)
	}
	m = &ExecRunner{Bin: bad, TempRoot: root}
	_, err := m.Start(context.Background(), path)
	if !errors.Is(err, ErrRunnerStartup) {
		t.Fatalf("exec format: %v", err)
	}
	assertRootClean(t, root)
	m = &ExecRunner{Bin: coreFixture(t), TempRoot: path}
	_, err = m.Start(context.Background(), path)
	if !errors.Is(err, ErrRunnerStorage) {
		t.Fatalf("storage: %v", err)
	}
	m = &ExecRunner{Bin: coreFixture(t)}
	_, err = m.Start(context.Background(), filepath.Join(root, "secret-missing"))
	if !errors.Is(err, ErrRunnerConfig) || strings.Contains(err.Error(), "secret-missing") {
		t.Fatalf("read config: %v", err)
	}
}
