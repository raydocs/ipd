package nodes

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// This unrelated server learns credentials only after the client sends them.
// Client authentication success is deliberately NOT server authentication.
func acceptAnyRunnerCredential(c net.Conn, received *atomic.Int64) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	r := bufio.NewReader(c)
	first, err := r.Peek(1)
	if err != nil {
		return
	}
	received.Add(1)
	if first[0] != 5 {
		req, err := http.ReadRequest(r)
		if err != nil {
			return
		}
		req.Body.Close()
		_, _ = io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	var h [2]byte
	if _, err = io.ReadFull(r, h[:]); err != nil {
		return
	}
	if _, err = io.CopyN(io.Discard, r, int64(h[1])); err != nil {
		return
	}
	_, _ = c.Write([]byte{5, 2})
	if _, err = io.ReadFull(r, h[:]); err != nil {
		return
	}
	if _, err = io.CopyN(io.Discard, r, int64(h[1])); err != nil {
		return
	}
	n, err := r.ReadByte()
	if err != nil {
		return
	}
	if _, err = io.CopyN(io.Discard, r, int64(n)); err != nil {
		return
	}
	_, _ = c.Write([]byte{1, 0})
}

func TestRunnerRejectsAcceptAnyPortImpostor(t *testing.T) {
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
			ln, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			var received atomic.Int64
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					go acceptAnyRunnerCredential(c, &received)
				}
			}()
			if err := <-result; !errors.Is(err, ErrRunnerOwnership) {
				t.Fatalf("impostor was not rejected using kernel ownership: %v", err)
			}
			if m.Endpoints() != nil {
				t.Fatal("published foreign endpoints")
			}
			if received.Load() != 0 {
				t.Fatal("sent authentication/protocol bytes before establishing child ownership")
			}
			assertReaped(t, states)
			assertRootClean(t, root)
		})
	}
}

func fixtureLaunches(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(filepath.Dir(coreFixture(t)), "fixture-starts"))
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRunnerGlobalsRejectedBeforeAnyChildOrPacket(t *testing.T) {
	for _, backend := range []Backend{BackendMihomo, BackendSingBox} {
		t.Run(string(backend), func(t *testing.T) {
			var base map[string]any
			var err error
			if backend == BackendMihomo {
				base, err = runnerDocument([]byte(backendFixtureInput(backend, "public-fixture")))
			} else {
				base, err = runnerJSON([]byte(backendFixtureInput(backend, "public-fixture")))
			}
			if err != nil {
				t.Fatal(err)
			}
			policies := map[string]any{}
			if backend == BackendMihomo {
				policies = map[string]any{
					"interface-name": "fixture-required", "routing-mark": 4242, "hosts": map[string]any{"alpha.invalid": "localhost"},
					"dns": map[string]any{"enable": false}, "tls": map[string]any{"custom-certificates": []any{"/do-not-read/fixture.pem"}},
					"global-client-fingerprint": "fixture-required", "certificate": map[string]any{"store": "none"},
					"external-controller": "127.0.0.1:9090", "proxy-providers": map[string]any{}, "rules": []any{"MATCH,DIRECT"},
					"profile": map[string]any{}, "tun": map[string]any{}, "mixed-port": 7890, "mode": "direct", "run-script": map[string]any{},
				}
			} else {
				policies = map[string]any{
					"certificate": map[string]any{"store": "none", "certificate_path": []any{"/do-not-read/fixture.pem"}},
					"route":       map[string]any{"default_interface": "fixture-required", "default_mark": 4242},
					"dns":         map[string]any{"hosts": map[string]any{"alpha.invalid": "localhost"}},
					"ntp":         map[string]any{"enabled": true}, "experimental": map[string]any{}, "inbounds": []any{}, "endpoints": []any{}, "log": map[string]any{"output": "/do-not-write"},
				}
			}
			policies["unknown-future-policy"] = map[string]any{}
			policies["description"] = "top-level presentation is not implicitly trusted"
			policies["metadata"] = map[string]any{"name": "display", "hidden-policy": "not-allowed"}
			root := t.TempDir()
			before := fixtureLaunches(t)
			for key, value := range policies {
				var data []byte
				doc := map[string]any{}
				for k, v := range base {
					doc[k] = v
				}
				doc[key] = value
				if backend == BackendMihomo {
					data, err = yaml.Marshal(doc)
				} else {
					data, err = json.Marshal(doc)
				}
				if err != nil {
					t.Fatal(err)
				}
				m := &ExecRunner{Bin: coreFixture(t), TempRoot: root}
				if _, err := m.Start(context.Background(), runnerInputConfig(t, string(data))); !errors.Is(err, ErrRunnerUnsupported) {
					t.Errorf("policy %s: %v", key, err)
				}
				if m.Endpoints() != nil {
					t.Errorf("policy %s published endpoints", key)
				}
				entries, err := os.ReadDir(root)
				if err != nil {
					t.Fatal(err)
				}
				if len(entries) != 0 {
					t.Fatal("allocated private storage before rejecting globals")
				}
			}
			if fixtureLaunches(t) != before {
				t.Fatal("started a child for unsupported global policy")
			}
			// A closed, presentation-only metadata object remains accepted on each core.
			base["metadata"] = map[string]any{"name": "display-only", "description": "no effect on upstream"}
			var data []byte
			if backend == BackendMihomo {
				data, err = yaml.Marshal(base)
			} else {
				data, err = json.Marshal(base)
			}
			if err != nil {
				t.Fatal(err)
			}
			m := &ExecRunner{Bin: coreFixture(t), TempRoot: root}
			defer m.Stop()
			if _, err := m.Start(context.Background(), runnerInputConfig(t, string(data))); err != nil {
				t.Fatal(err)
			}
			if fixtureLaunches(t) == before {
				t.Fatal("positive control did not actually launch fixture")
			}
			m.Stop()
			assertRootClean(t, root)
		})
	}
}

func TestRunnerActualCleanupPermissionFailureIsReported(t *testing.T) {
	for _, backend := range []Backend{BackendMihomo, BackendSingBox} {
		t.Run(string(backend), func(t *testing.T) {
			root := t.TempDir()
			m := &ExecRunner{Bin: coreFixture(t), TempRoot: root}
			defer m.Stop()
			if _, err := m.Start(context.Background(), runnerInputConfig(t, backendFixtureInput(backend, "public-fixture"))); err != nil {
				t.Fatal(err)
			}
			states := fixtureStates(t, root, 1)
			config, err := os.ReadFile(states[0].Config)
			if err != nil {
				t.Fatal(err)
			}
			blocked := filepath.Join(filepath.Dir(states[0].Config), "private-state-secret")
			if err := os.Mkdir(blocked, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(blocked, "credential-copy"), config, 0600); err != nil {
				t.Fatal(err)
			}
			defer os.Chmod(blocked, 0700)
			if err := os.Chmod(blocked, 0000); err != nil {
				t.Fatal(err)
			}
			m.Stop()
			assertReaped(t, states)
			if _, err := os.Stat(blocked); err != nil {
				t.Fatalf("test requires actual OS permission-denied cleanup (run as non-root): %v", err)
			}
			terminal := m.Err()
			for _, want := range []error{context.Canceled, ErrRunnerStorage, ErrRunnerCleanup} {
				if !errors.Is(terminal, want) {
					t.Errorf("lost terminal identity %v: %v", want, terminal)
				}
			}
			if strings.Contains(terminal.Error(), root) || strings.Contains(terminal.Error(), "private-state-secret") || strings.Contains(terminal.Error(), "public-fixture") {
				t.Fatal("cleanup error exposed path/config")
			}
			m.Stop()
			if !errors.Is(m.Err(), ErrRunnerCleanup) {
				t.Fatal("repeated Stop lost retained-resource warning")
			}
		})
	}
}

func TestRunnerKernelEvidenceParsers(t *testing.T) {
	valid := "p123\x00R456\x00\nf7\x00tIPv4\x00PTCP\x00n127.0.0.1:7890\x00TST=LISTEN\x00\n"
	if owned, err := runnerLsofOwns([]byte(valid), 123, 456, 7890); !owned || err != nil {
		t.Fatalf("valid kernel evidence: %v %v", owned, err)
	}
	for _, bad := range []string{
		strings.Replace(valid, "p123", "p999", 1), strings.Replace(valid, "R456", "R999", 1), strings.Replace(valid, "R456\x00", "", 1),
		strings.Replace(valid, "tIPv4", "tIPv6", 1), strings.Replace(valid, "127.0.0.1", "*", 1), strings.Replace(valid, "LISTEN", "ESTABLISHED", 1),
		valid + valid, strings.Replace(valid, "TST=LISTEN\x00", "", 1), strings.Replace(valid, "f7", "funknown", 1),
	} {
		if owned, err := runnerLsofOwns([]byte(bad), 123, 456, 7890); owned || err == nil {
			t.Fatal("accepted missing/foreign/ambiguous kernel evidence")
		}
	}
	if owned, err := runnerLsofOwns(nil, 123, 456, 7890); owned || err != nil {
		t.Fatal("no kernel record must remain not-ready")
	}
	proc := []byte(" sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n 0: 0100007F:1ED2 00000000:0000 0A 00000000:00000000 00:00000000 00000000 501 0 1234 1\n")
	sockets, err := runnerTCPListeners(proc, 7890)
	if err != nil || len(sockets) != 1 || sockets[0].inode != "1234" {
		t.Fatalf("proc kernel evidence: %v %v", sockets, err)
	}
	for _, bad := range []string{"", "not a table", string(proc) + "corrupted row\n", strings.Replace(string(proc), "501 0 1234", "501 0 not-inode", 1)} {
		if _, err := runnerTCPListeners([]byte(bad), 7890); !errors.Is(err, ErrRunnerUnsupported) {
			t.Fatal("unverifiable proc data must fail closed")
		}
	}
}
