package nodes

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func backendFixtureInput(backend Backend, mode string) string {
	if backend == BackendMihomo {
		return fixtureSubscription(mode)
	}
	b, _ := json.Marshal(map[string]any{"outbounds": []any{map[string]any{"tag": "alpha", "type": "shadowsocks", "server": "alpha.invalid", "server_port": 443, "method": "aes-128-gcm", "password": mode}}})
	return string(b)
}

func TestSingBoxRunnerIsolationAndConfiguration(t *testing.T) {
	text := `{"log":{"output":"/do-not-write"},"experimental":{"clash_api":{"external_controller":"0.0.0.0:9090"}},"route":{"final":"direct","rule_set":[{"type":"remote","url":"https://do-not-fetch.invalid"}]},"inbounds":[{"type":"tun","auto_route":true}],"outbounds":[
 {"tag":"ss","type":"shadowsocks","server":"ss.invalid","server_port":443,"method":"aes-128-gcm","password":"public-fixture"},
 {"tag":"vl","type":"vless","server":"vl.invalid","server_port":443,"uuid":"00000000-0000-4000-8000-000000000000","flow":"xtls-rprx-vision","tls":{"enabled":true,"server_name":"example.invalid","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"public-fixture","short_id":"abcd"}}},
 {"tag":"vm","type":"vmess","server":"vm.invalid","server_port":443,"uuid":"00000000-0000-4000-8000-000000000000","security":"auto","alter_id":0,"transport":{"type":"ws","path":"/fixture","headers":{"Host":"example.invalid"}}},
 {"tag":"tr","type":"trojan","server":"tr.invalid","server_port":443,"password":"public-fixture","tls":{"enabled":true,"alpn":["h2"]},"transport":{"type":"grpc","service_name":"fixture"}},
 {"tag":"hy","type":"hysteria2","server":"hy.invalid","server_port":443,"password":"public-fixture","up_mbps":10,"down_mbps":50,"obfs":{"type":"salamander","password":"public-obfs"},"tls":{"enabled":true}},
 {"tag":"tu","type":"tuic","server":"tu.invalid","server_port":443,"uuid":"00000000-0000-4000-8000-000000000000","password":"public-fixture","congestion_control":"bbr","udp_relay_mode":"native","tls":{"enabled":true,"alpn":["h3"]}},
 {"tag":"an","type":"anytls","server":"an.invalid","server_port":443,"password":"public-fixture","min_idle_session":1,"tls":{"enabled":true}}
 ]}`
	root := t.TempDir()
	m := &ExecRunner{Executables: map[Backend]string{BackendSingBox: coreFixture(t)}, TempRoot: root}
	defer m.Stop()
	input := runnerInputConfig(t, text)
	socks, err := m.Start(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if m.SelectedBackend() != BackendSingBox || len(socks) != 7 {
		t.Fatal("selection identity missing")
	}
	states := fixtureStates(t, root, 7)
	original, err := runnerJSON([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	pids := map[int]bool{}
	for i, state := range states {
		if pids[state.PID] {
			t.Fatal("shared process")
		}
		pids[state.PID] = true
		b, err := os.ReadFile(state.Config)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := runnerJSON(b)
		if err != nil {
			t.Fatal(err)
		}
		want := maps.Clone(original["outbounds"].([]any)[i].(map[string]any))
		name := want["tag"].(string)
		want["tag"] = "ipd-node"
		if !reflect.DeepEqual(cfg["outbounds"], []any{want}) {
			t.Fatal("protocol parameters lost/changed")
		}
		if len(cfg) != 4 || cfg["experimental"] != nil || !reflect.DeepEqual(cfg["log"], map[string]any{"disabled": true}) {
			t.Fatal("global configuration escaped")
		}
		if !reflect.DeepEqual(cfg["route"], map[string]any{"final": "ipd-node", "auto_detect_interface": false}) {
			t.Fatal("unsafe routing")
		}
		inbound := cfg["inbounds"].([]any)[0].(map[string]any)
		if inbound["listen"] != "127.0.0.1" || inbound["set_system_proxy"] != false || inbound["type"] != "mixed" {
			t.Fatal("unsafe inbound")
		}
		ep := m.Endpoints()[name]
		if ep.Backend != BackendSingBox || ep.SOCKS != socks[name] {
			t.Fatal("wrong result backend")
		}
		u, err := url.Parse(ep.SOCKS)
		if err != nil {
			t.Fatal(err)
		}
		if seen[u.Host] {
			t.Fatal("shared socket")
		}
		seen[u.Host] = true
		checkSOCKSMarker(t, ep.SOCKS, name+".invalid")
		checkHTTPMarker(t, ep.HTTP, name+".invalid")
		for _, p := range []string{state.Config, filepath.Dir(state.Config), filepath.Dir(filepath.Dir(state.Config))} {
			st, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			want := os.FileMode(0600)
			if st.IsDir() {
				want = 0700
			}
			if st.Mode().Perm() != want {
				t.Fatal("private permissions")
			}
		}
	}
	m.Stop()
	assertReaped(t, states)
	assertRootClean(t, root)
	for addr := range seen {
		c, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			c.Close()
			t.Error("listener survives Stop")
		}
	}
	b, err := os.ReadFile(input)
	if err != nil || string(b) != text {
		t.Fatal("modified source JSON")
	}
}

func TestSingBoxRunnerFailureLifecycle(t *testing.T) {
	for _, mode := range []string{"fixture-exit", "fixture-stall", "fixture-collision", "fixture-socks-only", "cancel-start", "stop-start", "budget-start", "cancel-live", "stop-live", "budget-live", "fixture-late-exit"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			m := &ExecRunner{Bin: coreFixture(t), Backend: BackendSingBox, TempRoot: root, StartupTimeout: 350 * time.Millisecond, Budget: 3 * time.Second}
			defer m.Stop()
			pass := mode
			if strings.Contains(mode, "start") {
				pass = "fixture-stall"
			} else if strings.HasSuffix(mode, "live") {
				pass = "public-fixture"
			}
			if strings.HasPrefix(mode, "budget") {
				m.Budget = 550 * time.Millisecond
				m.StartupTimeout = 2 * time.Second
			}
			input := runnerInputConfig(t, backendFixtureInput(BackendSingBox, pass))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() { _, err := m.Start(ctx, input); result <- err }()
			var states []fixtureState
			if mode != "fixture-exit" {
				states = fixtureStates(t, root, 1)
			}
			live := strings.HasSuffix(mode, "live") || mode == "fixture-late-exit"
			if live {
				if err := <-result; err != nil {
					t.Fatal(err)
				}
			}
			switch {
			case strings.HasPrefix(mode, "cancel"):
				cancel()
			case strings.HasPrefix(mode, "stop"):
				m.Stop()
			}
			want := ErrRunnerReadiness
			switch {
			case strings.Contains(mode, "exit"):
				want = ErrRunnerExit
			case strings.HasPrefix(mode, "budget"):
				want = context.DeadlineExceeded
			case strings.HasPrefix(mode, "cancel") || strings.HasPrefix(mode, "stop"):
				want = context.Canceled
			}
			if !live {
				if err := <-result; !errors.Is(err, want) {
					t.Fatalf("Start: %v want %v", err, want)
				}
			}
			awaitRunner(t, m)
			if !errors.Is(m.Err(), want) {
				t.Fatalf("Err: %v want %v", m.Err(), want)
			}
			if m.Endpoints() != nil {
				t.Fatal("stale endpoints")
			}
			m.Stop()
			assertReaped(t, states)
			assertRootClean(t, root)
		})
	}
}

func TestRunnerBackendSelectionAndForce(t *testing.T) {
	yamlInput := []byte(fixtureSubscription("public-fixture"))
	jsonInput := []byte(backendFixtureInput(BackendSingBox, "public-fixture"))
	for _, tt := range []struct {
		input         []byte
		request, want Backend
		err           error
	}{
		{yamlInput, BackendAuto, BackendMihomo, nil}, {jsonInput, BackendAuto, BackendSingBox, nil},
		{yamlInput, BackendMihomo, BackendMihomo, nil}, {jsonInput, BackendSingBox, BackendSingBox, nil},
		{yamlInput, BackendSingBox, BackendAuto, ErrRunnerUnsupported}, {jsonInput, BackendMihomo, BackendAuto, ErrRunnerUnsupported},
		{yamlInput, Backend("unknown"), BackendAuto, ErrRunnerUnsupported},
	} {
		got, err := SelectBackend(tt.input, tt.request)
		if got != tt.want || !errors.Is(err, tt.err) {
			t.Fatalf("selection: %s %v", got, err)
		}
	}
	// A missing selected binary cannot silently select the other executable.
	root := t.TempDir()
	m := &ExecRunner{Executables: map[Backend]string{BackendMihomo: coreFixture(t)}, TempRoot: root}
	_, err := m.Start(context.Background(), runnerInputConfig(t, string(jsonInput)))
	if !errors.Is(err, ErrRunnerExecutable) || m.SelectedBackend() != BackendSingBox {
		t.Fatal("executable failure changed selection")
	}
	assertRootClean(t, root)
	// Runtime failure also preserves selected identity, even with both paths set.
	m = &ExecRunner{Executables: map[Backend]string{BackendMihomo: coreFixture(t), BackendSingBox: coreFixture(t)}, TempRoot: root}
	_, err = m.Start(context.Background(), runnerInputConfig(t, backendFixtureInput(BackendSingBox, "fixture-exit")))
	if !errors.Is(err, ErrRunnerExit) || m.SelectedBackend() != BackendSingBox {
		t.Fatal("runtime fallback")
	}
	assertRootClean(t, root)
}

func TestRunnerActualPortCollisionFailsClosed(t *testing.T) {
	for _, backend := range []Backend{BackendMihomo, BackendSingBox} {
		t.Run(string(backend), func(t *testing.T) {
			root := t.TempDir()
			m := &ExecRunner{Bin: coreFixture(t), TempRoot: root, StartupTimeout: 2 * time.Second}
			defer m.Stop()
			input := runnerInputConfig(t, backendFixtureInput(backend, "fixture-delay-bind"))
			result := make(chan error, 1)
			go func() { _, err := m.Start(context.Background(), input); result <- err }()
			states := fixtureStates(t, root, 1)
			b, err := os.ReadFile(states[0].Config)
			if err != nil {
				t.Fatal(err)
			}
			var port int
			if backend == BackendMihomo {
				cfg, err := runnerDocument(b)
				if err != nil {
					t.Fatal(err)
				}
				port = cfg["listeners"].([]any)[0].(map[string]any)["port"].(int)
			} else {
				cfg, err := runnerJSON(b)
				if err != nil {
					t.Fatal(err)
				}
				port = cfg["inbounds"].([]any)[0].(map[string]any)["listen_port"].(int)
			}
			foreign, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
			if err != nil {
				t.Fatal(err)
			}
			defer foreign.Close()
			go func() {
				for {
					c, err := foreign.Accept()
					if err != nil {
						return
					}
					_, _ = c.Write([]byte{5, 0})
					c.Close()
				}
			}()
			if err := <-result; !errors.Is(err, ErrRunnerExit) {
				t.Fatalf("collision must fail without another backend/port: %v", err)
			}
			if m.Endpoints() != nil {
				t.Fatal("foreign listener published")
			}
			assertReaped(t, states)
			assertRootClean(t, root)
			c, err := net.DialTimeout("tcp", foreign.Addr().String(), time.Second)
			if err != nil {
				t.Fatal("closed unowned listener")
			}
			c.Close()
		})
	}
}

func TestRunnerExecutablePathIsNotAShell(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "core fixture; false")
	if err := os.Symlink(coreFixture(t), bin); err != nil {
		t.Fatal(err)
	}
	for _, backend := range []Backend{BackendMihomo, BackendSingBox} {
		m := &ExecRunner{Bin: bin}
		_, err := m.Start(context.Background(), runnerInputConfig(t, backendFixtureInput(backend, "public-fixture")))
		if err != nil {
			t.Fatal(err)
		}
		if m.SelectedBackend() != backend {
			t.Fatal("wrong backend")
		}
		m.Stop()
	}
}

type runnerUnreachable struct{}

func (runnerUnreachable) Check(context.Context, string, string) (string, string, string, string, error) {
	return "", "", "", "", errDown
}
func TestRunIncludesBackendIdentity(t *testing.T) {
	f, err := Parse(fixtureSubscription("public-fixture"))
	if err != nil {
		t.Fatal(err)
	}
	m := &ExecRunner{Bin: coreFixture(t)}
	defer m.Stop()
	outcomes, _, err := Run(context.Background(), f, runnerUnreachable{}, m, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(outcomes) != 1 || outcomes[0].Backend != BackendMihomo {
		t.Fatal("Run lost backend identity")
	}
	if m.Endpoints() != nil {
		t.Fatal("Run failed to Stop")
	}
}
