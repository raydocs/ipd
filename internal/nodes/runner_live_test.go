package nodes

import (
	"context"
	"errors"
	"io"
	"net"
	"net/url"
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

type liveCheckKey struct{}

func startLiveFixture(t *testing.T, backend Backend, count int, query ownerQuery, parent context.Context) (*ExecRunner, *RunHandle, []fixtureState) {
	t.Helper()
	root := t.TempDir()
	m := &ExecRunner{Bin: coreFixture(t), TempRoot: root, StartupTimeout: 15 * time.Second, Budget: 30 * time.Second}
	t.Cleanup(m.Stop)
	input := liveInput(backend, count)
	var h *RunHandle
	var err error
	if query == nil {
		_, h, err = m.StartWithHandle(parent, runnerInputConfig(t, input))
	} else {
		// Only latency/event ordering is wrapped; unchanged execute/readiness and
		// actual kernel ownership queries still attest the real helper children.
		_, h, err = m.startWithHandle(parent, func() ([]byte, error) { return []byte(input), nil }, query)
	}
	if err != nil {
		t.Fatal(err)
	}
	return m, h, fixtureStates(t, root, count)
}
func awaitLiveDone(t *testing.T, h *RunHandle) {
	t.Helper()
	select {
	case <-h.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("logical revocation was not prompt")
	}
}
func assertLiveRevoked(t *testing.T, m *ExecRunner, h *RunHandle, want error) {
	t.Helper()
	awaitLiveDone(t, h)
	h.run.mu.RLock()
	generation := h.run.generation
	h.run.mu.RUnlock()
	if generation != 1 {
		t.Fatal("batch invalidated more than once", generation)
	}
	if m.Endpoints() != nil || !errors.Is(h.Err(), want) || !errors.Is(m.Err(), want) {
		t.Fatalf("missing whole-batch revocation/reason: %v", h.Err())
	}
	if err := h.CheckAll(context.Background()); !errors.Is(err, want) {
		t.Fatalf("revoked handle revived: %v", err)
	}
}

func TestLiveHandleBindingAndRestart(t *testing.T) {
	for _, backend := range []Backend{BackendMihomo, BackendSingBox} {
		t.Run(string(backend), func(t *testing.T) {
			m, h, states := startLiveFixture(t, backend, 2, nil, context.Background())
			old := m.Endpoints()
			if err := h.Check(context.Background(), "a", old["a"]); err != nil {
				t.Fatal(err)
			}
			if err := h.CheckAll(context.Background()); err != nil {
				t.Fatal(err)
			}
			m.Stop()
			assertLiveRevoked(t, m, h, ErrRunnerStopped)
			if !errors.Is(h.Err(), context.Canceled) || errors.Is(h.Err(), ErrRunnerExit) || errors.Is(h.Err(), ErrRunnerOwnership) || errors.Is(h.Err(), ErrRunnerCleanup) {
				t.Fatal("Stop confused with failure", h.Err())
			}
			assertReaped(t, states)
			input := runnerInputConfig(t, liveInput(backend, 2))
			_, next, err := m.StartWithHandle(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			if next == h || next.Done() == h.Done() {
				t.Fatal("handle reused across runs")
			}
			if err := h.Check(context.Background(), "a", m.Endpoints()["a"]); !errors.Is(err, ErrRunnerStopped) {
				t.Fatal("old handle followed new run", err)
			}
			if err := next.CheckAll(context.Background()); err != nil {
				t.Fatal("old handle invalidated new run", err)
			}
			if h.Err() == nil {
				t.Fatal("old cause lost after restart")
			}
		})
	}
}
func TestLiveHandleRejectsChangedBinding(t *testing.T) {
	for _, backend := range []Backend{BackendMihomo, BackendSingBox} {
		for _, field := range []string{"name", "socks", "http", "backend", "other-node", "old-run"} {
			t.Run(string(backend)+"/"+field, func(t *testing.T) {
				m, h, _ := startLiveFixture(t, backend, 2, nil, context.Background())
				if field == "old-run" {
					ep := m.Endpoints()["a"]
					m.Stop()
					_, h2, err := m.StartWithHandle(context.Background(), runnerInputConfig(t, liveInput(backend, 2)))
					if err != nil {
						t.Fatal(err)
					}
					if err = h2.Check(context.Background(), "a", ep); !errors.Is(err, ErrRunnerOwnership) {
						t.Fatal("accepted old endpoint", err)
					}
					assertLiveRevoked(t, m, h2, ErrRunnerOwnership)
					return
				}
				ep := m.Endpoints()["a"]
				name := "a"
				switch field {
				case "name":
					name = "unknown"
				case "socks":
					ep.SOCKS += "changed"
				case "http":
					ep.HTTP += "changed"
				case "backend":
					ep.Backend = BackendAuto
				case "other-node":
					ep = m.Endpoints()["b"]
				}
				err := h.Check(context.Background(), name, ep)
				if !errors.Is(err, ErrRunnerOwnership) {
					t.Fatal("accepted changed binding", err)
				}
				if strings.Contains(err.Error(), ep.HTTP) || strings.Contains(err.Error(), ep.SOCKS) {
					t.Fatal("credential-bearing error")
				}
				assertLiveRevoked(t, m, h, ErrRunnerOwnership)
			})
		}
	}
}

func TestLiveMonitorInterruptsOldBlockedTunnel(t *testing.T) {
	for _, backend := range []Backend{BackendMihomo, BackendSingBox} {
		t.Run(string(backend), func(t *testing.T) {
			m, h, states := startLiveFixture(t, backend, 2, nil, context.Background())
			c, reader := liveTunnel(t, m.Endpoints()["a"], states[0])
			// Consumer pattern: Done cancels an in-flight client, without another Check.
			interrupted := make(chan struct{})
			go func() {
				select {
				case <-h.Done():
					c.Close()
				case <-interrupted:
				}
			}()
			readDone := make(chan struct{})
			go func() { _, _ = io.ReadAll(reader); close(readDone) }()
			liveCommand(t, states[0], "close-listener")
			awaitLiveDone(t, h) // Deliberately do not call Check/CheckAll.
			select {
			case <-readDone:
			case <-time.After(time.Second):
				t.Fatal("client remained blocked after Done")
			}
			close(interrupted)
			assertLiveRevoked(t, m, h, ErrRunnerOwnership)
		})
	}
}

func TestLiveCheckKnownTakeoverSendsNoCredentials(t *testing.T) {
	for _, backend := range []Backend{BackendMihomo, BackendSingBox} {
		t.Run(string(backend), func(t *testing.T) {
			m, h, states := startLiveFixture(t, backend, 2, nil, context.Background())
			ep := m.Endpoints()["a"]
			liveCommand(t, states[0], "close-listener")
			awaitRunnerMarker(t, filepath.Join(filepath.Dir(states[0].Config), "listener-closed"))
			u, _ := url.Parse(ep.HTTP)
			ln, err := net.Listen("tcp4", u.Host)
			if err != nil {
				t.Fatal(err)
			}
			var received, accepted atomic.Int64
			stopped := make(chan struct{})
			go func() {
				defer close(stopped)
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					accepted.Add(1)
					go acceptAnyRunnerCredential(c, &received)
				}
			}()
			defer func() { ln.Close(); <-stopped }()
			if err := h.Check(context.Background(), "a", ep); !errors.Is(err, ErrRunnerOwnership) {
				t.Fatal("known takeover accepted", err)
			}
			assertLiveRevoked(t, m, h, ErrRunnerOwnership)
			// Barrier ends the external accept loop, rather than sleeping to sample it.
			ln.Close()
			<-stopped
			if accepted.Load() != 0 || received.Load() != 0 {
				t.Fatal("known foreign owner received authentication/protocol bytes")
			}
		})
	}
}

// Retain 24 nodes, rather than reducing the sweep to evade the publication bug.
// The final query's real positive is held behind an event; an earlier node is
// closed and freshly observed invalid while that sweep is still in progress.
func TestLiveSweepEarlierNodeInvalidatesBeforeLateSuccessAndCleanup(t *testing.T) {
	for _, backend := range []Backend{BackendMihomo, BackendSingBox} {
		t.Run(string(backend), func(t *testing.T) {
			entered := make(chan struct{})
			release := make(chan struct{})
			returned := make(chan struct{})
			var unblock sync.Once
			t.Cleanup(func() { unblock.Do(func() { close(release) }) })
			var finalPID atomic.Int64
			query := func(ctx context.Context, pid, port int) (bool, error) {
				owned, err := runnerOwnsListener(ctx, pid, port)
				if ctx.Value(liveCheckKey{}) == "sweep" && pid == int(finalPID.Load()) {
					close(entered)
					<-release
					close(returned) // Ignores cancellation to model slow OS evidence.
				}
				return owned, err
			}
			m, h, states := startLiveFixture(t, backend, 24, query, context.Background())
			for _, state := range states {
				if filepath.Base(filepath.Dir(state.Config)) == "23" {
					finalPID.Store(int64(state.PID))
				}
			}
			if finalPID.Load() == 0 {
				t.Fatal("final ordered node missing")
			}
			slowDir := filepath.Join(filepath.Dir(filepath.Dir(states[0].Config)), "live-cleanup-tree")
			if err := os.Mkdir(slowDir, 0700); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 8192; i++ {
				if err := os.WriteFile(filepath.Join(slowDir, strconv.Itoa(i)), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			ep := m.Endpoints()["a"]
			result := make(chan error, 1)
			go func() { result <- h.CheckAll(context.WithValue(context.Background(), liveCheckKey{}, "sweep")) }()
			select {
			case <-entered:
			case <-time.After(4 * time.Second):
				t.Fatal("last query event not reached")
			}
			if err := syscall.Kill(states[0].PID, 0); err != nil {
				t.Fatal(err)
			}
			liveCommand(t, states[0], "close-listener")
			awaitRunnerMarker(t, filepath.Join(filepath.Dir(states[0].Config), "listener-closed"))
			if err := h.Check(context.Background(), "a", ep); !errors.Is(err, ErrRunnerOwnership) {
				t.Fatal(err)
			}
			assertLiveRevoked(t, m, h, ErrRunnerOwnership)
			// Neither the held query nor teardown may delay the logical transition.
			select {
			case <-returned:
				t.Fatal("test missed slow query window")
			default:
			}
			select {
			case <-h.run.done:
				t.Fatal("test missed real slow cleanup window")
			default:
			}
			if _, err := os.Stat(slowDir); err != nil {
				t.Fatal("cleanup already finished", err)
			}
			select {
			case err := <-result:
				if !errors.Is(err, ErrRunnerOwnership) {
					t.Fatal("sweep accepted stale positive", err)
				}
			case <-time.After(time.Second):
				t.Fatal("sweep waited on slow query after invalidation")
			}
			unblock.Do(func() { close(release) })
			<-returned
			if m.Endpoints() != nil || h.Err() == nil {
				t.Fatal("late positive resurrected run")
			}
			m.Stop()
			assertReaped(t, states)
			assertRootClean(t, m.TempRoot)
		})
	}
}

func TestLiveCheckCancellationAndSlowQuery(t *testing.T) {
	for _, backend := range []Backend{BackendMihomo, BackendSingBox} {
		for _, mode := range []string{"call-cancel", "node-deadline", "query-timeout", "batch-cancel"} {
			t.Run(string(backend)+"/"+mode, func(t *testing.T) {
				entered := make(chan time.Time, 1)
				release := make(chan struct{})
				returned := make(chan struct{})
				var unblock sync.Once
				t.Cleanup(func() { unblock.Do(func() { close(release) }) })
				query := func(ctx context.Context, pid, port int) (bool, error) {
					owned, err := runnerOwnsListener(ctx, pid, port)
					if ctx.Value(liveCheckKey{}) == mode {
						d, _ := ctx.Deadline()
						entered <- d
						<-release
						close(returned)
					}
					return owned, err
				}
				parent, cancelBatch := context.WithCancel(context.Background())
				defer cancelBatch()
				m, h, _ := startLiveFixture(t, backend, 2, query, parent)
				ctx, cancel := context.WithCancel(context.WithValue(context.Background(), liveCheckKey{}, mode))
				defer cancel()
				var deadline time.Time
				if mode == "node-deadline" {
					var c context.CancelFunc
					deadline = time.Now().Add(200 * time.Millisecond)
					ctx, c = context.WithDeadline(ctx, deadline)
					defer c()
				}
				result := make(chan error, 1)
				ep := m.Endpoints()["a"]

				go func() { result <- h.Check(ctx, "a", ep) }()
				var queryDeadline time.Time
				select {
				case queryDeadline = <-entered:
				case <-time.After(time.Second):
					t.Fatal("slow query not entered")
				}
				if queryDeadline.After(time.Now().Add(ownerQueryBudget)) || queryDeadline.IsZero() {
					t.Fatal("query has no bounded earliest deadline")
				}
				if !deadline.IsZero() && !queryDeadline.Equal(deadline) {
					t.Fatal("node deadline not passed to kernel query")
				}
				want := context.Canceled
				switch mode {
				case "call-cancel":
					cancel()
				case "batch-cancel":
					cancelBatch()
				default:
					want = context.DeadlineExceeded
				}
				assertLiveRevoked(t, m, h, want)
				select {
				case <-returned:
					t.Fatal("revocation waited for slow query")
				default:
				}
				if errors.Is(h.Err(), ErrRunnerStopped) {
					t.Fatal("cancellation misclassified as ordinary Stop")
				}
				select {
				case err := <-result:
					if !errors.Is(err, want) {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("Check waited on stalled evidence")
				}
				unblock.Do(func() { close(release) })
				<-returned
				if m.Endpoints() != nil {
					t.Fatal("late query restored endpoint")
				}
			})
		}
	}
}

func TestLiveHandleExitDeadlineAndCleanupReasons(t *testing.T) {
	for _, backend := range []Backend{BackendMihomo, BackendSingBox} {
		for _, mode := range []string{"exit", "deadline", "cleanup"} {
			t.Run(string(backend)+"/"+mode, func(t *testing.T) {
				parent := context.Background()
				var cancel context.CancelFunc
				if mode == "deadline" {
					parent, cancel = context.WithTimeout(parent, 1500*time.Millisecond)
					defer cancel()
				}
				m, h, states := startLiveFixture(t, backend, 2, nil, parent)
				want := ErrRunnerExit
				switch mode {
				case "exit":
					if err := syscall.Kill(states[0].PID, syscall.SIGKILL); err != nil {
						t.Fatal(err)
					}
				case "deadline":
					want = context.DeadlineExceeded
				case "cleanup":
					blocked := filepath.Join(filepath.Dir(states[0].Config), "live-private-cleanup")
					if err := os.Mkdir(blocked, 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(blocked, "private-copy"), nil, 0600); err != nil {
						t.Fatal(err)
					}
					defer os.Chmod(blocked, 0700)
					if err := os.Chmod(blocked, 0); err != nil {
						t.Fatal(err)
					}
					m.Stop()
					want = ErrRunnerStopped
					if !errors.Is(h.Err(), ErrRunnerCleanup) || !errors.Is(h.Err(), ErrRunnerStorage) {
						t.Fatal("cleanup error lost", h.Err())
					}
				}
				assertLiveRevoked(t, m, h, want)
				if mode != "cleanup" && errors.Is(h.Err(), ErrRunnerStopped) {
					t.Fatal("real failure marked normal Stop")
				}
				m.Stop()
				assertReaped(t, states)
			})
		}
	}
}

func TestLiveAmbiguousAndUnavailableEvidence(t *testing.T) {
	for _, backend := range []Backend{BackendMihomo, BackendSingBox} {
		for _, mode := range []string{"ambiguous", "query-error", "unavailable"} {
			t.Run(string(backend)+"/"+mode, func(t *testing.T) {
				query := func(ctx context.Context, pid, port int) (bool, error) {
					if ctx.Value(liveCheckKey{}) == mode {
						if mode == "query-error" {
							return true, errors.New("raw-secret-path-and-output")
						}
						if mode == "unavailable" {
							return false, ErrRunnerUnsupported
						}
					}
					return runnerOwnsListener(ctx, pid, port)
				}
				m, h, _ := startLiveFixture(t, backend, 2, query, context.Background())
				ep := m.Endpoints()["a"]
				if mode == "ambiguous" {
					u, _ := url.Parse(ep.HTTP)
					// The real child retains IPv4 ownership; another real listener in the
					// other family at the same port must not be hidden by PID/family filters.
					ln, err := net.Listen("tcp6", net.JoinHostPort("::1", u.Port()))
					if err != nil {
						t.Fatal("IPv6 ambiguity fixture unavailable", err)
					}
					defer ln.Close()
				}
				err := h.Check(context.WithValue(context.Background(), liveCheckKey{}, mode), "a", ep)
				if !errors.Is(err, ErrRunnerOwnership) {
					t.Fatal("accepted unavailable/ambiguous evidence", err)
				}
				if mode == "unavailable" && !errors.Is(err, ErrRunnerUnsupported) {
					t.Fatal("unsupported evidence reason lost", err)
				}
				if strings.Contains(err.Error(), "raw-secret") {
					t.Fatal("raw query error leaked")
				}
				assertLiveRevoked(t, m, h, ErrRunnerOwnership)
			})
		}
	}
}

func TestLiveFileHandleAndFailedStart(t *testing.T) {
	m := &ExecRunner{Bin: coreFixture(t)}
	defer m.Stop()
	if socks, h, err := m.StartWithHandle(context.Background(), "/nonexistent-fixture"); !errors.Is(err, ErrRunnerConfig) || socks != nil || h != nil {
		t.Fatal("failed start returned a capability", err)
	}
	f, err := Parse(liveInput(BackendMihomo, 2))
	if err != nil {
		t.Fatal(err)
	}
	socks, h, err := m.StartFileWithHandle(context.Background(), f)
	if err != nil || len(socks) != 2 {
		t.Fatal(err)
	}
	if err := h.CheckAll(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestLiveStopCannotHidePendingLifetimeFailure(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		r := stateRun(t)
		if deadline {
			ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			defer cancel()
			r.ctx = ctx
		} else {
			r.cancel()
		}
		r.stop() // No lifetime callback: the Stop gate must observe context state.
		want := context.Canceled
		if deadline {
			want = context.DeadlineExceeded
		}
		if !errors.Is(r.failure(), want) || errors.Is(r.failure(), ErrRunnerStopped) {
			t.Fatal("Stop hid a pending real failure", r.failure())
		}
	}
}

func TestLiveQueryUsesEarlierBatchDeadline(t *testing.T) {
	for _, backend := range []Backend{BackendMihomo, BackendSingBox} {
		t.Run(string(backend), func(t *testing.T) {
			m, actual, _ := startLiveFixture(t, backend, 2, nil, context.Background())
			// A focused state fixture uses the real run's immutable child/endpoint
			// bindings but an earlier batch deadline, without startup consuming it.
			r := stateRun(t)
			r.starting = false
			r.owners = actual.run.owners
			r.endpoints = m.Endpoints()
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			r.ctx = ctx
			batchDeadline, _ := ctx.Deadline()
			entered := make(chan time.Time, 1)
			release := make(chan struct{})
			defer close(release)
			r.query = func(ctx context.Context, pid, port int) (bool, error) {
				owned, err := runnerOwnsListener(ctx, pid, port)
				d, _ := ctx.Deadline()
				entered <- d
				<-release
				return owned, err
			}
			h := &RunHandle{run: r}
			result := make(chan error, 1)
			call, c := context.WithTimeout(context.Background(), time.Second)
			defer c()
			go func() { result <- h.Check(call, "a", m.Endpoints()["a"]) }()
			if d := <-entered; !d.Equal(batchDeadline) {
				t.Fatal("batch deadline was not the earliest query deadline")
			}
			if err := <-result; !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal(err)
			}
			awaitLiveDone(t, h)
			if r.liveEndpoints() != nil {
				t.Fatal("batch timeout kept endpoints")
			}
		})
	}
}
