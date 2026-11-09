package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"ipd/internal/evaluation"
)

const fixturePath = "../../internal/evaluation/testdata/synthetic-v1.json"

func TestRun(t *testing.T) {
	for _, tc := range []struct {
		args []string
		code int
	}{
		{nil, 2}, {[]string{"-help"}, 0}, {[]string{"-bad"}, 2},
		{[]string{"-dataset", fixturePath, "extra"}, 2},
		{[]string{"-dataset", "does-not-exist"}, 1},
		{[]string{"-dataset", fixturePath, "-split", "train"}, 1},
		{[]string{"-dataset", fixturePath, "-split", "bad"}, 1},
		{[]string{"-dataset", fixturePath}, 0},
	} {
		var out, err bytes.Buffer
		if got := run(tc.args, &out, &err); got != tc.code {
			t.Fatalf("%v: code %d want %d stderr %s", tc.args, got, tc.code, &err)
		}
		if tc.code != 0 && out.Len() != 0 {
			t.Fatal("failure emitted partial report")
		}
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(bad, []byte(`{"schema_version":"wrong"}`), 0600)
	var out, stderr bytes.Buffer
	if run([]string{"-dataset", bad}, &out, &stderr) != 1 {
		t.Fatal("invalid input accepted")
	}
	if run([]string{"-dataset", fixturePath}, brokenWriter{}, &stderr) != 1 {
		t.Fatal("write failure ignored")
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

// Build and execute the real CLI with dependency downloads explicitly disabled.
func TestOfflineBinary(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "ipd-eval")
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	var previous []byte
	for range 2 {
		cmd := exec.Command(binary, "-dataset", fixturePath)
		cmd.Env = []string{"HTTP_PROXY=http://127.0.0.1:1", "HTTPS_PROXY=http://127.0.0.1:1", "HOME=" + t.TempDir()}
		raw, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		var report evaluation.Report
		if err := json.Unmarshal(raw, &report); err != nil {
			t.Fatal(err)
		}
		if report.Total != 4 || report.Correct != 2 || report.Abstained != 1 {
			t.Fatalf("wrong report: %+v", report)
		}
		if previous != nil && !bytes.Equal(previous, raw) {
			t.Fatal("CLI output not reproducible")
		}
		previous = raw
	}
	cmd := exec.Command(binary, "-dataset", fixturePath, "-split", "unknown")
	if err := cmd.Run(); err == nil {
		t.Fatal("binary accepted invalid split")
	}
}
