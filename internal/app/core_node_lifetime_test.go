package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"ipd/internal/config"
	"ipd/internal/nodes"
)

func startAppHandle(t *testing.T, bin string, backend nodes.Backend, origins, modes []string) (*nodes.ExecRunner, *nodes.RunHandle, map[string]nodes.Endpoint, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(path, []byte(nativeEgressInput(backend, origins, modes...)), 0600); err != nil {
		t.Fatal(err)
	}
	runner := &nodes.ExecRunner{Bin: bin, Backend: backend, Budget: 20 * time.Second}
	t.Cleanup(runner.Stop)
	_, handle, err := runner.StartWithHandle(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	return runner, handle, runner.Endpoints(), path
}

func waitAppMarker(t *testing.T, path string) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("fixture acknowledgement missing")
		case <-tick.C:
		}
	}
}
func closeAppListener(t *testing.T, bin, mode string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(filepath.Dir(bin), mode+".close"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	waitAppMarker(t, filepath.Join(filepath.Dir(bin), mode+".closed"))
}
func waitAppDone(t *testing.T, h *nodes.RunHandle) {
	t.Helper()
	select {
	case <-h.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("run did not revoke")
	}
}

func TestCoreHandleOldRunCannotAuthorizeRestartedClient(t *testing.T) {
	bin := egressFixture(t)
	for _, backend := range []nodes.Backend{nodes.BackendMihomo, nodes.BackendSingBox} {
		t.Run(string(backend), func(t *testing.T) {
			var hits atomic.Int32
			srv, target := tlsEgressOrigin(t, func(w http.ResponseWriter, r *http.Request) { hits.Add(1); fmt.Fprint(w, "8.8.8.8") })
			runner, old, eps, path := startAppHandle(t, bin, backend, []string{srv.Listener.Addr().String()}, nil)
			ep := eps["z-secret-name"]
			oldClient, closeOld, err := newCoreHTTPClient(context.Background(), ep.HTTP, target.roots, coreRunGate(old, "z-secret-name", ep), old.Err)
			if err != nil {
				t.Fatal(err)
			}
			defer closeOld()
			runner.Stop()
			waitAppDone(t, old)
			if !errors.Is(old.Err(), nodes.ErrRunnerStopped) {
				t.Fatal("normal Stop identity lost")
			}
			_, next, err := runner.StartWithHandle(context.Background(), path)
			if err != nil {
				t.Fatal(err)
			}
			if next == old || next.Done() == old.Done() {
				t.Fatal("handle followed restart")
			}
			if _, err := queryCoreEgressClient(context.Background(), oldClient, target.url, coreRunGate(old, "z-secret-name", ep)); err == nil || hits.Load() != 0 {
				t.Fatal("stale client authorized a request")
			}
			if err := next.CheckAll(context.Background()); err != nil {
				t.Fatal("old handle revoked replacement")
			}
			nextEP := runner.Endpoints()["z-secret-name"]
			client, closeNext, err := newCoreHTTPClient(context.Background(), nextEP.HTTP, target.roots, coreRunGate(next, "z-secret-name", nextEP), next.Err)
			if err != nil {
				t.Fatal(err)
			}
			defer closeNext()
			ip, err := queryCoreEgressClient(context.Background(), client, target.url, coreRunGate(next, "z-secret-name", nextEP))
			if err != nil || ip != "8.8.8.8" || hits.Load() != 1 {
				t.Fatal("replacement did not retain independent client capability")
			}
		})
	}
	assertEgressReaped(t, bin, 4)
}

// Fault ordered by a real established socket, not a sleep or mocked OS query.
// The private factory seam directs the client at an independent loopback peer
// so runner teardown cannot manufacture success by closing that peer itself.
func TestCoreHandlePostDialKnownLossSendsNoAuthentication(t *testing.T) {
	bin := egressFixture(t)
	for _, backend := range []nodes.Backend{nodes.BackendMihomo, nodes.BackendSingBox} {
		t.Run(string(backend), func(t *testing.T) {
			_, h, eps, _ := startAppHandle(t, bin, backend, []string{"127.0.0.1:1"}, nil)
			ep := eps["z-secret-name"]
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			received := make(chan int, 1)
			go func() {
				c, err := ln.Accept()
				if err != nil {
					received <- -1
					return
				}
				defer c.Close()
				c.SetReadDeadline(time.Now().Add(3 * time.Second))
				b, _ := io.ReadAll(c)
				received <- len(b)
			}()
			var client *http.Client
			gate := func(ctx context.Context) error {
				if client != nil {
					registry := client.Transport.(*coreHTTPRoundTripper).connections
					registry.mu.Lock()
					connected := len(registry.active) > 0
					registry.mu.Unlock()
					if connected {
						return h.Check(ctx, "wrong-node", ep)
					} // known whole-run revocation before any proxy write
				}
				return h.Check(ctx, "z-secret-name", ep)
			}
			client, cleanup, err := newCoreHTTPClient(context.Background(), "http://fixture-user:fixture-pass@"+ln.Addr().String(), nil, gate, h.Err)
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup()
			req, _ := http.NewRequest(http.MethodGet, coreEgressURL, nil)
			if _, err := client.Do(req); err == nil {
				t.Fatal("known-invalid post-dial result accepted")
			}
			waitAppDone(t, h)
			select {
			case n := <-received:
				if n != 0 {
					t.Fatalf("sent %d bytes to peer after known loss", n)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("post-dial connection not actively closed")
			}
		})
	}
	assertEgressReaped(t, bin, 2)
}

func TestCoreHandleKnownListenerLossNoAuthSend(t *testing.T) {
	bin := egressFixture(t)
	for _, backend := range []nodes.Backend{nodes.BackendMihomo, nodes.BackendSingBox} {
		t.Run(string(backend), func(t *testing.T) {
			_, h, eps, _ := startAppHandle(t, bin, backend, []string{"127.0.0.1:1"}, []string{"control-owner-a"})
			ep := eps["z-secret-name"]
			client, cleanup, err := newCoreHTTPClient(context.Background(), ep.HTTP, nil, coreRunGate(h, "z-secret-name", ep), h.Err)
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup()
			closeAppListener(t, bin, "control-owner-a")
			// Same port, external accept-any listener, not the original live child.
			proxy, _ := url.Parse(ep.HTTP)
			foreign, err := net.Listen("tcp", proxy.Host)
			if err != nil {
				t.Fatal(err)
			}
			var bytes atomic.Int32
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				for {
					c, e := foreign.Accept()
					if e != nil {
						return
					}
					c.SetReadDeadline(time.Now().Add(time.Second))
					b, _ := io.ReadAll(c)
					bytes.Add(int32(len(b)))
					c.Close()
				}
			}()
			if err := h.Check(context.Background(), "z-secret-name", ep); err == nil {
				t.Fatal("foreign listener accepted")
			}
			waitAppDone(t, h)
			req, _ := http.NewRequest(http.MethodGet, coreEgressURL, nil)
			if _, err := client.Do(req); err == nil {
				t.Fatal("known-lost owner authorized")
			}
			foreign.Close()
			<-finished
			if bytes.Load() != 0 {
				t.Fatal("credentials/protocol bytes sent after known loss")
			}
			for _, suffix := range []string{".close", ".closed"} {
				if err := os.Remove(filepath.Join(filepath.Dir(bin), "control-owner-a"+suffix)); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	assertEgressReaped(t, bin, 2)
}

func TestCoreHandleDoneCancelsBlockedTunnelAndConnections(t *testing.T) {
	bin := egressFixture(t)
	for _, backend := range []nodes.Backend{nodes.BackendMihomo, nodes.BackendSingBox} {
		t.Run(string(backend), func(t *testing.T) {
			_, h, eps, _ := startAppHandle(t, bin, backend, []string{"127.0.0.1:1"}, []string{"control-owner-b"})
			ep := eps["z-secret-name"]
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			entered, closed := make(chan struct{}), make(chan struct{})
			go func() {
				c, e := ln.Accept()
				if e != nil {
					return
				}
				defer c.Close()
				defer close(closed)
				buffer := make([]byte, 8192)
				if n, _ := c.Read(buffer); n > 0 {
					close(entered)
				}
				io.Copy(io.Discard, c)
			}()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stopWatch := watchCoreRun(ctx, h, cancel)
			defer stopWatch()
			client, cleanup, err := newCoreHTTPClient(ctx, "http://fixture-user:fixture-pass@"+ln.Addr().String(), nil, coreRunGate(h, "z-secret-name", ep), h.Err)
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup()
			requestDone := make(chan error, 1)
			go func() {
				req, _ := http.NewRequestWithContext(ctx, http.MethodGet, coreEgressURL, nil)
				_, e := client.Do(req)
				requestDone <- e
			}()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("authenticated CONNECT never blocked")
			}
			closeAppListener(t, bin, "control-owner-b")
			// No further Check or CheckAll: the production runner sampler observes loss;
			// Done must cancel the batch and close an unrelated, still-open tunnel.
			waitAppDone(t, h)
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
				t.Fatal("Done did not cancel app batch")
			}
			select {
			case e := <-requestDone:
				if e == nil {
					t.Fatal("blocked request succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("request waited for its 5s timeout instead of Done")
			}
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("active connection remained open after Done")
			}
			for _, suffix := range []string{".close", ".closed"} {
				if err := os.Remove(filepath.Join(filepath.Dir(bin), "control-owner-b"+suffix)); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	assertEgressReaped(t, bin, 2)
}

func TestCoreHandleCheckAllOtherNodeClearsEveryPositive(t *testing.T) {
	bin := egressFixture(t)
	for _, backend := range []nodes.Backend{nodes.BackendMihomo, nodes.BackendSingBox} {
		t.Run(string(backend), func(t *testing.T) {
			srv, target := tlsEgressOrigin(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/" {
					fmt.Fprint(w, "8.8.8.8")
				} else {
					fmt.Fprint(w, "US")
				}
			})
			_, h, eps, _ := startAppHandle(t, bin, backend, []string{srv.Listener.Addr().String(), srv.Listener.Addr().String()}, []string{"fixture-pass", "control-owner-c"})
			ep := eps["z-secret-name"]
			gate := coreRunGate(h, "z-secret-name", ep)
			client, cleanup, err := newCoreHTTPClient(context.Background(), ep.HTTP, target.roots, gate, h.Err)
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup()
			ip, err := queryCoreEgressClient(context.Background(), client, target.url, gate)
			if err != nil {
				t.Fatal(err)
			}
			result, err := queryCoreUnlock(context.Background(), client, []string{"apple"}, unlockTarget(target).unlockURL, gate)
			if err != nil || len(result) != 1 || result[0].Status != "yes" {
				t.Fatal("real provisional positive not obtained")
			}
			rows := []CoreNodeObservation{{Index: 1, Backend: backend, EgressIP: ip, Status: "observed", Unlock: result}, {Index: 2, Backend: backend, EgressIP: ip, Status: "observed", Unlock: result}}
			closeAppListener(t, bin, "control-owner-c")
			rep := New(&config.Config{}, nil).publishCoreNodes(context.Background(), h, rows)
			assertUnlockCleared(t, rep)
			waitAppDone(t, h)
			for _, suffix := range []string{".close", ".closed"} {
				if err := os.Remove(filepath.Join(filepath.Dir(bin), "control-owner-c"+suffix)); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	assertEgressReaped(t, bin, 4)
}

func TestCoreClientChecksKeepRequestDeadline(t *testing.T) {
	srv, target := tlsEgressOrigin(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "8.8.8.8") })
	bin := egressFixture(t)
	_, h, eps, _ := startAppHandle(t, bin, nodes.BackendMihomo, []string{srv.Listener.Addr().String()}, nil)
	nodeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	nodeDeadline, _ := nodeCtx.Deadline()
	requestCtx, requestCancel := context.WithTimeout(nodeCtx, 500*time.Millisecond)
	defer requestCancel()
	requestDeadline, _ := requestCtx.Deadline()
	var requestStarted atomic.Bool
	var checks atomic.Int32
	gate := func(ctx context.Context) error {
		latest := nodeDeadline
		if requestStarted.Load() {
			latest = requestDeadline
		}
		d, ok := ctx.Deadline()
		if !ok || d.After(latest) {
			t.Error("ownership gate lost earliest request/node deadline")
		}
		checks.Add(1)
		return ctx.Err()
	}
	ep := eps["z-secret-name"]
	client, cleanup, err := newCoreHTTPClient(nodeCtx, ep.HTTP, target.roots, gate, h.Err)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	requestStarted.Store(true)
	if _, err := queryCoreEgressClient(requestCtx, client, target.url, gate); err != nil {
		t.Fatal(err)
	}
	if checks.Load() < 6 {
		t.Fatal("request/dial/header/body gates were not exercised")
	}
}
