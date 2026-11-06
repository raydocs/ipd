package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"ipd/internal/app"
	"ipd/internal/config"
)

// This must reject the incompatible forced backend before launching anything,
// not treat --measure as the old source or leak source text into an error.
func TestCoreNodesForcedBackendRegression(t *testing.T) {
	cfg := &config.Config{}
	svc := app.New(cfg, nil)
	source := "proxies:\n  - {name: secret-name, type: ss, server: secret-server, port: 443, cipher: aes-128-gcm, password: secret-pass}\n"
	_, err := dispatch(context.Background(), svc, cfg, globals{lang: "en"}, "nodes", []string{"--measure", "--backend", "sing-box", "--sing-box-bin", "/does/not/exist", source})
	if err == nil || !strings.Contains(locale("en").error(err), "unsupported") {
		t.Fatalf("want controlled unsupported before launch, got %v", err)
	}
	if strings.Contains(err.Error(), "secret-") {
		t.Fatal("input leaked")
	}
}

func TestCoreNodesCLIParametersAndLanguage(t *testing.T) {
	cfg := &config.Config{Offline: true}
	svc := app.New(cfg, nil)
	source := "proxies: [{name: secret-node, type: ss, server: secret-server, port: 443, cipher: aes-128-gcm, password: secret-pass}]"
	for _, args := range [][]string{
		nil, {"--measure"}, {"--measure=secret"}, {"--measure", "--measure", source},
		{"--measure", "--backend=garbage-secret", source}, {"--measure", "--backend"},
		{"--mihomo-bin", "/secret/path", source}, {"--measure", "--mihomo-bin=", source},
		{"--measure", "--backend=auto", "--backend=mihomo", source}, {"--unknown-secret", source},
		{"--measure", source, "another-secret"},
	} {
		_, err := dispatch(context.Background(), svc, cfg, globals{}, "nodes", args)
		if err == nil {
			t.Errorf("accepted bad arguments")
			continue
		}
		en, zh := locale("en").error(err), locale("zh").error(err)
		if !strings.Contains(en, "Invalid node measurement") || !strings.Contains(en, "Usage:") || !strings.Contains(zh, "用法：") {
			t.Fatalf("owned error not localized: %s / %s", en, zh)
		}
		if strings.Contains(en, "secret") || strings.Contains(zh, "secret") {
			t.Fatal("argument leaked")
		}
	}
	for _, args := range [][]string{{source}, {"--measure", "--backend=auto", "--mihomo-bin=/not/executed", source}} {
		rep, err := dispatch(context.Background(), svc, cfg, globals{}, "nodes", args)
		if err != nil || rep.Verdict != "abstain" {
			t.Fatalf("default/offline: %+v %v", rep, err)
		}
		b, _ := json.Marshal(rep)
		if strings.Contains(string(b), "secret") || strings.Contains(string(b), "renamed_yaml") {
			t.Fatal("default/offline leaked input")
		}
	}
	for _, lang := range []string{"en", "zh"} {
		out, code := captureLatencyMain(t, []string{"--lang", lang, "nodes", "--help"})
		if code != 0 || !strings.Contains(out, "--measure") || (lang == "en" && !strings.Contains(out, "Usage:")) || (lang == "zh" && !strings.Contains(out, "用法：")) {
			t.Fatalf("bad nodes help: %s", out)
		}
	}
}

func TestCoreNodesCLISignalHelper(t *testing.T) {
	if os.Getenv("IPD_CORE_SIGNAL_HELPER") != "1" {
		return
	}
	os.Exit(Main(strings.Split(os.Getenv("IPD_CORE_SIGNAL_ARGS"), "\x1f")))
}

func TestCoreNodesCLISignalCleansRealChildren(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "core")
	if out, err := exec.Command("go", "build", "-o", bin, "../app/testdata/egressfixture").CombinedOutput(); err != nil {
		t.Fatalf("fixture: %v %s", err, out)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	// No HTTP origin or public service is contacted; the helper stalls the CONNECT
	// tunnel after opening only this configured local TCP listener.
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	source := fmt.Sprintf("proxies: [{name: private-name, type: ss, server: %q, port: %s, cipher: aes-128-gcm, password: stall-connect}]", host, port)
	args := []string{"--json", "--lang=en", "nodes", "--measure", "--mihomo-bin", bin, source}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestCoreNodesCLISignalHelper$")
	cmd.Env = append(os.Environ(), "IPD_CORE_SIGNAL_HELPER=1", "IPD_CORE_SIGNAL_ARGS="+strings.Join(args, "\x1f"), "IPD_DATA_DIR="+t.TempDir(), "IPD_OFFLINE=false")
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			<-done
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "connected")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no real CONNECT before signal")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil || cmd.ProcessState.ExitCode() != 10 {
			t.Fatalf("signal exit: %v %s", err, output.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("signal cleanup timeout")
	}
	var rep app.Report
	if err := json.Unmarshal(output.Bytes(), &rep); err != nil {
		t.Fatalf("result: %v %s", err, output.String())
	}
	if rep.Verdict != "abstain" || strings.Contains(output.String(), "stall-connect") || strings.Contains(output.String(), "private-name") {
		t.Fatal("unsafe signal result")
	}
	audit, err := os.ReadFile(filepath.Join(dir, "egress-audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var state struct {
		PID int    `json:"pid"`
		Dir string `json:"dir"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(audit), &state); err != nil {
		t.Fatal(err)
	}
	if p, err := os.FindProcess(state.PID); err == nil && p.Signal(syscall.Signal(0)) == nil {
		t.Fatal("core remains after CLI cancellation")
	}
	if _, err := os.Stat(state.Dir); !os.IsNotExist(err) {
		t.Fatal("private config remains")
	}
}
