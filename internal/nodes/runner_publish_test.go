package nodes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func awaitRunnerMarker(t *testing.T, path string) {
	t.Helper()
	deadline := time.NewTimer(4 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("fixture marker was not reached")
		case <-tick.C:
		}
	}
}
func firstFixtureState(t *testing.T, root string) fixtureState {
	t.Helper()
	deadline := time.NewTimer(4 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		files, err := filepath.Glob(filepath.Join(root, "ipd-core-*", "0", "fixture-state.json"))
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range files {
			data, err := os.ReadFile(file)
			if err != nil {
				continue
			}
			var state fixtureState
			if json.Unmarshal(data, &state) == nil {
				return state
			}
		}
		select {
		case <-deadline.C:
			t.Fatal("first real child did not start")
		case <-tick.C:
		}
	}
}

// This retains the reviewer's 24-node/15s startup/20s lifetime scenario. The
// marker and 60ms schedule select its final-sweep window, not a safety mechanism.
// A bounded, real owned filesystem tree also makes teardown observably pending;
// no ownership/cleanup mock or production-only test switch is involved.
func TestRunnerExitDuringOwnerSweepRevokesBeforeSlowCleanup(t *testing.T) {
	for _, backend := range []Backend{BackendMihomo, BackendSingBox} {
		t.Run(string(backend), func(t *testing.T) {
			const count = 24
			items := make([]string, 0, count)
			for i := range count {
				if backend == BackendMihomo {
					items = append(items, strings.Replace(fixtureSS, "name: alpha", fmt.Sprintf("name: node%d", i), 1))
				} else {
					items = append(items, fmt.Sprintf(`{"tag":"node%d","type":"shadowsocks","server":"alpha.invalid","server_port":443,"method":"aes-128-gcm","password":"public-fixture"}`, i))
				}
			}
			input := "proxies: [" + strings.Join(items, ",") + "]"
			if backend == BackendSingBox {
				input = `{"outbounds":[` + strings.Join(items, ",") + `]}`
			}
			root := t.TempDir()
			m := &ExecRunner{Bin: coreFixture(t), TempRoot: root, StartupTimeout: 15 * time.Second, Budget: 20 * time.Second}
			defer m.Stop()
			type result struct {
				socks map[string]string
				err   error
			}
			results := make(chan result, 1)
			path := runnerInputConfig(t, input)
			go func() { socks, err := m.Start(context.Background(), path); results <- result{socks, err} }()
			first := firstFixtureState(t, root)
			batchDir := filepath.Dir(filepath.Dir(first.Config))
			slowDir := filepath.Join(batchDir, "owned-teardown-work")
			if err := os.Mkdir(slowDir, 0700); err != nil {
				t.Fatal(err)
			}
			for i := range 4096 {
				if err := os.WriteFile(filepath.Join(slowDir, strconv.Itoa(i)), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			states := fixtureStates(t, root, count)
			var last fixtureState
			for _, state := range states {
				if filepath.Base(filepath.Dir(state.Config)) == strconv.Itoa(count-1) {
					last = state
				}
			}
			awaitRunnerMarker(t, filepath.Join(filepath.Dir(last.Config), "r2-http-probed"))
			time.Sleep(60 * time.Millisecond) // Original review's attack schedule only.
			data, err := os.ReadFile(first.Config)
			if err != nil {
				t.Fatal(err)
			}
			var port int
			if backend == BackendMihomo {
				cfg, err := runnerDocument(data)
				if err != nil {
					t.Fatal(err)
				}
				port = cfg["listeners"].([]any)[0].(map[string]any)["port"].(int)
			} else {
				cfg, err := runnerJSON(data)
				if err != nil {
					t.Fatal(err)
				}
				port = cfg["inbounds"].([]any)[0].(map[string]any)["listen_port"].(int)
			}
			m.mu.Lock()
			run := m.run
			m.mu.Unlock()
			if err := syscall.Kill(first.PID, syscall.SIGKILL); err != nil {
				t.Fatal(err)
			}
			select {
			case <-run.invalid:
			case <-time.After(time.Second):
				t.Fatal("exit notification did not promptly revoke the batch")
			}
			// Revocation precedes reaping of peers/storage cleanup, not merely Start's
			// eventual error. Read both public observers while actual teardown is pending.
			select {
			case <-run.done:
				t.Fatal("test missed the actual slow-cleanup window")
			default:
			}
			if _, err := os.Stat(slowDir); err != nil {
				t.Fatal("owned cleanup tree already gone before observation")
			}
			if m.Endpoints() != nil || !errors.Is(m.Err(), ErrRunnerExit) {
				t.Fatal("failed batch remained public before teardown completed")
			}
			deadline := time.Now().Add(time.Second)
			for {
				if err := syscall.Kill(first.PID, 0); errors.Is(err, syscall.ESRCH) {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("killed child was not reaped")
				}
				time.Sleep(time.Millisecond)
			}
			foreign, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
			if err != nil {
				t.Fatal(err)
			}
			defer foreign.Close()
			var received atomic.Int64
			go func() {
				for {
					c, err := foreign.Accept()
					if err != nil {
						return
					}
					go acceptAnyRunnerCredential(c, &received)
				}
			}()
			got := <-results
			if !errors.Is(got.err, ErrRunnerExit) || got.socks != nil {
				t.Fatalf("returned stale success: endpoints=%d err=%v", len(got.socks), got.err)
			}
			if m.Endpoints() != nil || received.Load() != 0 {
				t.Fatal("foreign endpoint became public or received a request")
			}
			m.Stop()
			assertReaped(t, states)
			assertRootClean(t, root)
		})
	}
}

func stateRun(t *testing.T) *execRun {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &execRun{ctx: ctx, cancel: cancel, done: make(chan struct{}), ready: make(chan startResult, 1), invalid: make(chan struct{}), starting: true}
}
func stateEndpoint() map[string]Endpoint {
	return map[string]Endpoint{"fixture": {SOCKS: "socks5://127.0.0.1:12345", HTTP: "http://127.0.0.1:12345", Backend: BackendMihomo}}
}

func TestRunnerQueuedSuccessCannotSurviveInvalidation(t *testing.T) {
	for _, cause := range []error{ErrRunnerExit, context.Canceled, context.DeadlineExceeded} {
		r := stateRun(t)
		if err := r.publish(stateEndpoint()); err != nil {
			t.Fatal(err)
		}
		r.invalidate(cause)
		<-r.ready // The old success notice is deliberately still queued.
		if socks, err := r.acceptReady(); socks != nil || !errors.Is(err, cause) {
			t.Fatalf("accepted invalid queued success: %v", err)
		}
		if r.liveEndpoints() != nil || !errors.Is(r.terminalError(), cause) {
			t.Fatal("observer lost immediate failure")
		}
		select {
		case <-r.done:
			t.Fatal("test must not depend on cleanup completion")
		default:
		}
		r.finish(errors.Join(cause, ErrRunnerStorage, ErrRunnerCleanup))
		for _, want := range []error{cause, ErrRunnerStorage, ErrRunnerCleanup} {
			if !errors.Is(r.terminalError(), want) {
				t.Fatal("lost logical/cleanup error identity")
			}
		}
	}
}
func TestRunnerPublicationAndChildExitShareOneGate(t *testing.T) {
	for range 100 {
		r := stateRun(t)
		child := coreProcess{done: make(chan struct{})}
		begin := make(chan struct{})
		var wg sync.WaitGroup
		wg.Go(func() { <-begin; _ = r.publish(stateEndpoint()) })
		wg.Go(func() { <-begin; r.childExited(child) })
		close(begin)
		wg.Wait()
		if r.liveEndpoints() != nil {
			t.Fatal("exit transition was overwritten by publication")
		}
		if socks, err := r.acceptReady(); socks != nil || !errors.Is(err, ErrRunnerExit) {
			t.Fatal("published a known-dead batch")
		}
		r.finish(ErrRunnerExit)
	}
}

// State-only contexts test the synchronous deadline gates without waiting for
// callback scheduling. Integration above keeps the review's original budgets.
func TestRunnerPublicationAndReturnCheckDeadlineState(t *testing.T) {
	for _, stage := range []string{"publish", "queued-return", "read"} {
		t.Run(stage, func(t *testing.T) {
			r := stateRun(t)
			startup, cancel := context.WithCancel(context.Background())
			defer cancel()
			r.mu.Lock()
			r.startup = startup
			r.mu.Unlock()
			if stage != "publish" {
				if err := r.publish(stateEndpoint()); err != nil {
					t.Fatal(err)
				}
			}
			cancel()
			switch stage {
			case "publish":
				if err := r.publish(stateEndpoint()); !errors.Is(err, ErrRunnerReadiness) {
					t.Fatal("published after startup expired")
				}
			case "queued-return":
				<-r.ready
				if socks, err := r.acceptReady(); socks != nil || !errors.Is(err, ErrRunnerReadiness) {
					t.Fatal("accepted success after startup expired")
				}
			case "read":
				if r.liveEndpoints() != nil {
					t.Fatal("read after startup expired")
				}
			}
			if !errors.Is(r.terminalError(), ErrRunnerReadiness) {
				t.Fatal("lost startup deadline classification")
			}
			r.finish(r.failure())
		})
	}
	r := stateRun(t)
	startup, cancel := context.WithCancel(context.Background())
	stop := r.watchStartup(startup)
	defer stop()
	defer cancel()
	if err := r.publish(stateEndpoint()); err != nil {
		t.Fatal(err)
	}
	<-r.ready
	if _, err := r.acceptReady(); err != nil {
		t.Fatal(err)
	}
	cancel() // A startup deadline must not revoke an already accepted live batch.
	if len(r.liveEndpoints()) != 1 {
		t.Fatal("startup cancellation affected active lifetime")
	}
	r.invalidate(context.Canceled)
	r.finish(context.Canceled)
}

func TestRunnerLifetimeCancelGatesQueuedSuccess(t *testing.T) {
	r := stateRun(t)
	if err := r.publish(stateEndpoint()); err != nil {
		t.Fatal(err)
	}
	r.cancel() // No registered callback in this state-only test: readers must check.
	<-r.ready
	if socks, err := r.acceptReady(); socks != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("accepted success after lifetime cancellation")
	}
	if r.liveEndpoints() != nil {
		t.Fatal("read after lifetime cancellation")
	}
	r.finish(r.failure())
	// An already expired lifetime must also gate publication synchronously.
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	r = stateRun(t)
	r.ctx = expired
	if err := r.publish(stateEndpoint()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("published after lifetime deadline")
	}
	r.finish(r.failure())
}
