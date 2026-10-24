package nodes

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

var (
	ErrRunnerExecutable = errors.New("runner requires an explicit absolute executable path")
	ErrRunnerBusy       = errors.New("runner already active")
	ErrRunnerStartup    = errors.New("runner process could not start")
	ErrRunnerExit       = errors.New("runner process exited")
	ErrRunnerReadiness  = errors.New("runner listener readiness timed out")
	ErrRunnerStorage    = errors.New("runner private storage unavailable")
	ErrRunnerCleanup    = errors.New("runner private cleanup incomplete; retained resources require local attention")
	ErrRunnerOwnership  = errors.New("runner listener ownership could not be verified")
)

// Endpoint contains credential-bearing URLs. Never log or expose them publicly.
// Both protocols use the same private mixed listener; UDP is not enabled.
type Endpoint struct {
	SOCKS   string
	HTTP    string
	Backend Backend
}

// ExecRunner launches one external core per node. Configure before first use;
// do not copy it or mutate its options while active. No shell, PATH search,
// download, linked core, caller environment, or caller core config is used.
// The executable is trusted code, NOT an OS-sandboxed untrusted program.
type ExecRunner struct {
	Bin            string             // explicit executable for selected backend, if Executables is nil
	Backend        Backend            // auto by input format unless forced
	Executables    map[Backend]string // optional explicit path per backend; no PATH fallback
	StartupTimeout time.Duration      // whole batch; default 10 seconds
	Budget         time.Duration      // whole lifetime including startup; default 3 minutes
	TempRoot       string             // trusted parent only; default os.TempDir()
	mu             sync.Mutex
	run            *execRun
}

// Mihomo preserves the existing Runner implementation name.
type Mihomo = ExecRunner

var _ Runner = (*ExecRunner)(nil)

type execRun struct {
	ctx       context.Context
	cancel    context.CancelFunc
	done      chan struct{}
	ready     chan startResult
	mu        sync.RWMutex
	backend   Backend
	endpoints map[string]Endpoint
	err       error
}
type startResult struct {
	socks map[string]string
	err   error
}
type coreProcess struct {
	cmd  *exec.Cmd
	done chan struct{}
}

func (m *ExecRunner) Start(ctx context.Context, configPath string) (map[string]string, error) {
	return m.start(ctx, func() ([]byte, error) {
		st, err := os.Stat(configPath)
		if err != nil || !st.Mode().IsRegular() {
			return nil, ErrRunnerConfig
		}
		f, err := os.Open(configPath)
		if err != nil {
			return nil, ErrRunnerConfig
		}
		defer f.Close()
		b, err := io.ReadAll(io.LimitReader(f, maxRunnerConfig+1))
		if err != nil {
			return nil, ErrRunnerConfig
		}
		return b, nil
	})
}

// StartFile preserves original-YAML validation when Run has parsed a File. It
// does not change the Runner interface; custom runners retain the old path API.
func (m *ExecRunner) StartFile(ctx context.Context, f File) (map[string]string, error) {
	return m.start(ctx, func() ([]byte, error) {
		if f.runnerURI {
			return nil, ErrRunnerUnsupported
		}
		if f.runnerYAMLInvalid {
			return nil, ErrRunnerConfig
		}
		b, err := yaml.Marshal(f.Raw)
		if err != nil {
			return nil, ErrRunnerConfig
		}
		return b, nil
	})
}

func (m *ExecRunner) start(ctx context.Context, load func() ([]byte, error)) (map[string]string, error) {
	m.mu.Lock()
	if m.run != nil {
		select {
		case <-m.run.done:
		default:
			m.mu.Unlock()
			return nil, ErrRunnerBusy
		}
	}
	budget, startup := m.Budget, m.StartupTimeout
	if budget <= 0 {
		budget = 3 * time.Minute
	}
	if startup <= 0 {
		startup = 10 * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, budget)
	r := &execRun{ctx: runCtx, cancel: cancel, done: make(chan struct{}), ready: make(chan startResult, 1)}
	m.run = r
	bin, root, backend, executables := m.Bin, m.TempRoot, m.Backend, maps.Clone(m.Executables)
	m.mu.Unlock()
	go func() {
		err := r.execute(bin, root, backend, executables, startup, load)
		r.cancel()
		r.mu.Lock()
		r.err = err
		r.endpoints = nil
		r.mu.Unlock()
		// Buffered: on failure Start waits for all child Wait calls and cleanup.
		if err != nil {
			select {
			case r.ready <- startResult{err: err}:
			default:
			}
		}
		close(r.done)
	}()
	result := <-r.ready
	if result.err != nil {
		<-r.done
		return nil, result.err
	}
	if err := r.ctx.Err(); err != nil {
		<-r.done
		r.mu.RLock()
		terminal := r.err
		r.mu.RUnlock()
		if terminal != nil {
			return nil, terminal
		}
		return nil, err
	}
	return result.socks, nil
}

// Stop cancels startup or an active batch, reaps every child, and waits until
// owned storage cleanup has been attempted. Inspect Err for cleanup failure.
// Concurrent/repeated Stop calls are safe.
func (m *ExecRunner) Stop() {
	m.mu.Lock()
	r := m.run
	m.mu.Unlock()
	if r != nil {
		r.cancel()
		<-r.done
	}
}

// Endpoints returns a copy only while the batch is live. A child exit revokes
// all endpoints and tears down its peers; callers must not retain stale URLs.
func (m *ExecRunner) Endpoints() map[string]Endpoint {
	m.mu.Lock()
	r := m.run
	m.mu.Unlock()
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.ctx.Err() != nil {
		return nil
	}
	return maps.Clone(r.endpoints)
}

// SelectedBackend remains available after teardown, including startup failure.
func (m *ExecRunner) SelectedBackend() Backend {
	m.mu.Lock()
	r := m.run
	m.mu.Unlock()
	if r == nil {
		return BackendAuto
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.backend
}

// Err reports a sanitized terminal error after teardown (nil while active).
func (m *ExecRunner) Err() error {
	m.mu.Lock()
	r := m.run
	m.mu.Unlock()
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.err
}

func (r *execRun) execute(bin, root string, requested Backend, executables map[Backend]string, startup time.Duration, load func() ([]byte, error)) (resultErr error) {
	if err := r.ctx.Err(); err != nil {
		return err
	}
	data, err := load()
	if err != nil {
		return err
	}
	driver, proxies, names, err := prepareRunner(data, requested)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.backend = driver.ID()
	r.mu.Unlock()
	if err := runnerOwnershipAvailable(); err != nil {
		return err
	}
	if executables != nil {
		bin = executables[driver.ID()]
	}
	if !filepath.IsAbs(bin) {
		return ErrRunnerExecutable
	}
	st, err := os.Stat(bin)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0111 == 0 {
		return ErrRunnerExecutable
	}
	if root != "" && !filepath.IsAbs(root) {
		return ErrRunnerStorage
	}
	if err := r.ctx.Err(); err != nil {
		return err
	}
	dir, err := os.MkdirTemp(root, "ipd-core-")
	if err != nil {
		return ErrRunnerStorage
	}
	// Only remove the fresh private directory, never the input or TempRoot.
	defer func() {
		if os.RemoveAll(dir) != nil {
			resultErr = errors.Join(resultErr, ErrRunnerStorage, ErrRunnerCleanup)
		}
	}()
	var processes []coreProcess
	defer func() {
		for _, p := range processes {
			_ = p.cmd.Process.Kill()
		}
		for _, p := range processes {
			<-p.done
		}
	}()
	startupCtx, cancel := context.WithTimeout(r.ctx, startup)
	defer cancel()
	exits := make(chan struct{}, len(proxies))
	endpoints := map[string]Endpoint{}
	socks := map[string]string{}
	for i, proxy := range proxies {
		if err := startupCtx.Err(); err != nil {
			return readinessError(r.ctx)
		}
		nodeDir := filepath.Join(dir, strconv.Itoa(i))
		if os.Mkdir(nodeDir, 0700) != nil {
			return ErrRunnerStorage
		}
		reservation, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return ErrRunnerStartup
		}
		port := reservation.Addr().(*net.TCPAddr).Port
		var token [32]byte
		if _, err := rand.Read(token[:]); err != nil {
			reservation.Close()
			return ErrRunnerStartup
		}
		user, password := "ipd", hex.EncodeToString(token[:])
		config, err := driver.Config(proxy, port, user, password)
		if err != nil {
			reservation.Close()
			return ErrRunnerConfig
		}
		configPath := filepath.Join(nodeDir, "config"+driver.Extension())
		if os.WriteFile(configPath, config, 0600) != nil {
			reservation.Close()
			return ErrRunnerStorage
		}
		cmd := exec.CommandContext(r.ctx, bin, driver.Args(nodeDir, configPath)...)
		cmd.Dir = nodeDir
		// mihomo accepts CLASH_* overrides and run scripts via environment. Do not
		// inherit any variables, proxy settings, credentials, loader or Go hooks.
		cmd.Env = []string{"HOME=" + nodeDir, "TMPDIR=" + nodeDir}
		// Nil stdout/stderr go to the null device; raw core errors can contain secrets.
		reservation.Close() // no socket inheritance; kernel ownership is required below.
		if cmd.Start() != nil {
			return ErrRunnerStartup
		}
		p := coreProcess{cmd: cmd, done: make(chan struct{})}
		processes = append(processes, p)
		go func() { _ = p.cmd.Wait(); close(p.done); exits <- struct{}{} }()
		addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		if err := waitRunnerReady(startupCtx, r.ctx, addr, user, password, p, exits); err != nil {
			return err
		}
		credentials := url.UserPassword(user, password)
		endpoints[names[i]] = Endpoint{Backend: driver.ID(), SOCKS: (&url.URL{Scheme: "socks5", Host: addr, User: credentials}).String(), HTTP: (&url.URL{Scheme: "http", Host: addr, User: credentials}).String()}
		socks[names[i]] = endpoints[names[i]].SOCKS
	}
	select {
	case <-exits:
		return ErrRunnerExit
	case <-r.ctx.Done():
		return r.ctx.Err()
	default:
	}
	// Recheck every live child's listener immediately before publishing the batch.
	for i, p := range processes {
		u, _ := url.Parse(endpoints[names[i]].SOCKS)
		port, _ := strconv.Atoi(u.Port())
		if err := runnerRequireOwner(startupCtx, p, port); err != nil {
			if startupCtx.Err() != nil {
				return readinessError(r.ctx)
			}
			return err
		}
	}
	r.mu.Lock()
	r.endpoints = endpoints
	r.mu.Unlock()
	r.ready <- startResult{socks: socks}
	select {
	case <-r.ctx.Done():
		return r.ctx.Err()
	case <-exits:
		return ErrRunnerExit
	}
}

func readinessError(lifetime context.Context) error {
	if err := lifetime.Err(); err != nil {
		return err
	}
	return ErrRunnerReadiness
}
func waitRunnerReady(ctx, lifetime context.Context, addr, user, password string, child coreProcess, exits <-chan struct{}) error {
	_, portText, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portText)
	timer := time.NewTicker(20 * time.Millisecond)
	defer timer.Stop()
	for {
		select {
		case <-exits:
			return ErrRunnerExit
		case <-ctx.Done():
			return readinessError(lifetime)
		default:
		}
		owned, err := runnerOwnsListener(ctx, child.cmd.Process.Pid, port)
		if ctx.Err() != nil {
			return readinessError(lifetime)
		}
		select {
		case <-child.done:
			return ErrRunnerExit
		default:
		}
		if err != nil {
			return err
		}
		if owned {
			if err := runnerRequireOwner(ctx, child, port); err != nil {
				if ctx.Err() != nil {
					return readinessError(lifetime)
				}
				return err
			}
			if probeRunnerSOCKS(ctx, addr, user, password) == nil && probeRunnerHTTP(ctx, addr) == nil {
				err := runnerRequireOwner(ctx, child, port)
				if ctx.Err() != nil {
					return readinessError(lifetime)
				}
				return err
			}
		}
		select {
		case <-exits:
			return ErrRunnerExit
		case <-ctx.Done():
			return readinessError(lifetime)
		case <-timer.C:
		}
	}
}

func runnerRequireOwner(ctx context.Context, child coreProcess, port int) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	select {
	case <-child.done:
		return ErrRunnerExit
	default:
	}
	owned, err := runnerOwnsListener(ctx, child.cmd.Process.Pid, port)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	select {
	case <-child.done:
		return ErrRunnerExit
	default:
	}
	if err != nil {
		return err
	}
	if !owned {
		return ErrRunnerOwnership
	}
	return nil
}

func runnerProbeConn(ctx context.Context, addr string) (net.Conn, error) {
	c, err := (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(ctx, "tcp4", addr)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(150 * time.Millisecond)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.SetDeadline(deadline)
	return c, nil
}

// Readiness never sends a target CONNECT and never makes an upstream request.
// These are protocol/authentication checks only, NOT proof of server identity.
// Kernel ownership must be established independently before probing/publishing.
func probeRunnerSOCKS(ctx context.Context, addr, user, password string) error {
	c, err := runnerProbeConn(ctx, addr)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err = c.Write([]byte{5, 1, 2}); err != nil {
		return err
	}
	var reply [2]byte
	if _, err = io.ReadFull(c, reply[:]); err != nil {
		return err
	}
	if reply != [2]byte{5, 2} {
		return ErrRunnerReadiness
	}
	msg := append([]byte{1, byte(len(user))}, user...)
	msg = append(msg, byte(len(password)))
	msg = append(msg, password...)
	if _, err = c.Write(msg); err != nil {
		return err
	}
	if _, err = io.ReadFull(c, reply[:]); err != nil {
		return err
	}
	if reply != [2]byte{1, 0} {
		return ErrRunnerReadiness
	}
	return nil
}
func probeRunnerHTTP(ctx context.Context, addr string) error {
	c, err := runnerProbeConn(ctx, addr)
	if err != nil {
		return err
	}
	defer c.Close()
	// No credentials: both cores return 407 before routing any request.
	// Listener ownership is established separately through kernel evidence.
	req := "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
	if _, err = io.WriteString(c, req); err != nil {
		return err
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		return ErrRunnerReadiness
	}
	return nil
}
