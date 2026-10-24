package nodes

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func liveInput(backend Backend, count int) string {
	var items []string
	for i := 0; i < count; i++ {
		name := string(rune('a' + i))
		if backend == BackendMihomo {
			items = append(items, strings.Replace(strings.Replace(fixtureSS, "alpha", name, 1), "public-fixture", "fixture-live", 1))
		} else {
			items = append(items, `{"tag":"`+name+`","type":"shadowsocks","server":"fixture.invalid","server_port":443,"method":"aes-128-gcm","password":"fixture-live"}`)
		}
	}
	if backend == BackendMihomo {
		return "proxies: [" + strings.Join(items, ",") + "]"
	}
	return `{"outbounds":[` + strings.Join(items, ",") + `]}`
}
func liveCommand(t *testing.T, state fixtureState, cmd string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(filepath.Dir(state.Config), cmd), nil, 0600); err != nil {
		t.Fatal(err)
	}
}
func liveTunnel(t *testing.T, ep Endpoint, state fixtureState) (net.Conn, *bufio.Reader) {
	t.Helper()
	u, err := url.Parse(ep.HTTP)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.DialTimeout("tcp4", u.Host, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	pass, _ := u.User.Password()
	auth := base64.StdEncoding.EncodeToString([]byte(u.User.Username() + ":" + pass))
	if _, err = io.WriteString(c, "CONNECT fixture.invalid:443 HTTP/1.1\r\nHost: fixture.invalid:443\r\nProxy-Authorization: Basic "+auth+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(c)
	resp, err := http.ReadResponse(r, &http.Request{Method: "CONNECT"})
	if err != nil || resp.StatusCode != 200 {
		t.Fatal("tunnel not established", err)
	}
	awaitRunnerMarker(t, filepath.Join(filepath.Dir(state.Config), "tunnel-open"))
	return c, r
}

// This uses only PR23's public API so the original defect can run, not just fail
// compilation for the absent new handle. The helper preserves PID and an already
// authenticated blocked tunnel while acknowledging closure of its listener.
func TestRunnerLivePIDListenerLossRevokes(t *testing.T) {
	for _, backend := range []Backend{BackendMihomo, BackendSingBox} {
		t.Run(string(backend), func(t *testing.T) {
			root := t.TempDir()
			m := &ExecRunner{Bin: coreFixture(t), TempRoot: root}
			defer m.Stop()
			if _, err := m.Start(context.Background(), runnerInputConfig(t, liveInput(backend, 2))); err != nil {
				t.Fatal(err)
			}
			states := fixtureStates(t, root, 2)
			c, r := liveTunnel(t, m.Endpoints()["a"], states[0])
			liveCommand(t, states[0], "close-listener")
			awaitRunnerMarker(t, filepath.Join(filepath.Dir(states[0].Config), "listener-closed"))
			if err := syscall.Kill(states[0].PID, 0); err != nil {
				t.Fatal("helper PID must remain alive", err)
			}
			// In the old implementation a recognizable positive still arrives through
			// the old tunnel, while the old public endpoint map remains valid.
			liveCommand(t, states[0], "release-tunnel")
			_ = c.SetReadDeadline(time.Now().Add(time.Second))
			body, _ := io.ReadAll(r) // Monitor may kill/revoke before this old positive arrives.
			if m.Endpoints() != nil && string(body) != "fixture-positive" {
				t.Fatal("old live tunnel did not return its positive")
			}
			t.Logf("existing authenticated tunnel returned %q; PID alive at close marker", body)
			deadline := time.NewTimer(2 * time.Second)
			defer deadline.Stop()
			tick := time.NewTicker(time.Millisecond)
			defer tick.Stop()
			for m.Endpoints() != nil {
				select {
				case <-deadline.C:
					t.Fatal("live PID lost listener but whole batch endpoints remain valid")
				case <-tick.C:
				}
			}
			if !errors.Is(m.Err(), ErrRunnerOwnership) {
				t.Fatalf("lost ownership reason: %v", m.Err())
			}
		})
	}
}
