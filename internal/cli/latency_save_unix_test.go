//go:build darwin || linux

package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"ipd/internal/app"
	"ipd/internal/probe"
)

// RLIMIT_FSIZE and SIGXFSZ affect the whole process. Run each case in an
// isolated test subprocess, only on the platforms whose behavior we exercise.
func TestLatencySaveWriteFailure(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, lang := range []string{"zh", "en"} {
		for _, mode := range []string{"replacement_file", "replacement_directory", "replacement_symlink", "own_partial", "own_empty", "main_empty"} {
			t.Run(lang+"/"+mode, func(t *testing.T) {
				cmd := exec.Command(binary, "-test.run=^TestLatencySaveWriteFailureProcess$", "-test.v")
				cmd.Env = append(os.Environ(), "IPD_LANG="+lang, "IPD_LATENCY_WRITE_FAILURE_FIXTURE="+mode, "IPD_LATENCY_WRITE_FAILURE_DIR="+t.TempDir())
				output, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("isolated write-failure regression: %v\n%s", err, output)
				}
				if mode == "main_empty" {
					prefix := "保存 SVG: "
					if lang == "en" {
						prefix = "Save SVG: "
					}
					if !strings.Contains(string(output), prefix) || !strings.Contains(string(output), "empty/partial export may remain") {
						t.Fatalf("CLI did not localize/warn about the failed artifact:\n%s", output)
					}
				}
			})
		}
	}
}

func TestLatencySaveWriteFailureProcess(t *testing.T) {
	mode := os.Getenv("IPD_LATENCY_WRITE_FAILURE_FIXTURE")
	if mode == "" {
		return
	}
	dir := os.Getenv("IPD_LATENCY_WRITE_FAILURE_DIR")
	if dir == "" {
		t.Fatal("missing isolated fixture directory")
	}
	var original syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &original); err != nil {
		t.Fatal(err)
	}
	const partialLimit = 512
	if original.Max < partialLimit {
		t.Fatal("fixture requires a hard file-size limit of at least 512 bytes")
	}
	signal.Ignore(syscall.SIGXFSZ)
	defer signal.Reset(syscall.SIGXFSZ)
	defer func() {
		if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &original); err != nil {
			t.Error(err)
		}
	}()
	limit := uint64(partialLimit)
	if mode == "own_empty" || mode == "main_empty" {
		limit = 0
	}
	restrict := func() {
		capped := original
		capped.Cur = limit
		if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &capped); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "card.svg")
	const replacement = "replacement owned by a different exporter"
	target := filepath.Join(dir, "replacement-target")
	if mode == "main_empty" {
		t.Setenv("IPD_DATA_DIR", filepath.Join(dir, "data"))
		t.Setenv("IPD_OFFLINE", "true")
		t.Setenv("IPD_VANTAGE", "self")
		restrict()
		if code := Main([]string{"latency", "192.0.2.10", "--svg", path}); code != 2 {
			t.Fatalf("write failure exit=%d, want 2", code)
		}
	} else {
		svc := &app.Service{Vantage: probe.Globalping{Runner: func(context.Context, probe.Query) ([]probe.Sample, error) {
			if strings.HasPrefix(mode, "replacement_") {
				// Keep the reserved inode accessible to prove that the failed write
				// targets the original fd, while the pathname belongs to someone else.
				if err := os.Rename(path, path+".reserved"); err != nil {
					t.Fatal(err)
				}
				switch mode {
				case "replacement_file":
					if err := os.WriteFile(path, []byte(replacement), 0640); err != nil {
						t.Fatal(err)
					}
				case "replacement_directory":
					if err := os.Mkdir(path, 0750); err != nil {
						t.Fatal(err)
					}
				case "replacement_symlink":
					if err := os.WriteFile(target, []byte(replacement), 0640); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(target, path); err != nil {
						t.Fatal(err)
					}
				default:
					t.Fatalf("unknown replacement mode %s", mode)
				}
			}
			restrict()
			return []probe.Sample{{Provider: "fixture", Healthy: true, ICMP: "ok", RTTMS: 12}}, nil
		}}}
		_, err := latencyCmd(context.Background(), svc, []string{"192.0.2.10", "--svg", path})
		if err == nil || !(errors.Is(err, syscall.EFBIG) || errors.Is(err, io.ErrShortWrite)) {
			t.Fatalf("expected size-limited SVG write failure, got %v", err)
		}
		cause := errors.Unwrap(err)
		if cause == nil {
			t.Fatal("save wrapper lost its original cause")
		}
		prefix := "保存 SVG: "
		if os.Getenv("IPD_LANG") == "en" {
			prefix = "Save SVG: "
		}
		if got := locale(os.Getenv("IPD_LANG")).error(err); got != prefix+cause.Error()+"; empty/partial export may remain (no path cleanup attempted)" {
			t.Fatalf("localized write error changed cause/warning: %q", got)
		}
		info, statErr := os.Lstat(path)
		if statErr != nil {
			t.Fatalf("failed export deleted a pathname it must leave alone: %v", statErr)
		}
		switch mode {
		case "replacement_file", "replacement_symlink":
			b, err := os.ReadFile(path)
			if err != nil || string(b) != replacement {
				t.Fatalf("replacement changed: %q, %v", b, err)
			}
			if mode == "replacement_symlink" && info.Mode()&os.ModeSymlink == 0 {
				t.Fatal("replacement symlink changed")
			}
			if mode == "replacement_file" && info.Mode().Perm() != 0640 {
				t.Fatal("replacement permissions changed")
			}
		case "replacement_directory":
			if !info.IsDir() || info.Mode().Perm() != 0750 {
				t.Fatal("replacement directory changed")
			}
		case "own_partial", "own_empty":
			if info.Mode().Perm() != 0600 || info.Size() > int64(limit) {
				t.Fatalf("unexpected failed artifact: mode=%o size=%d", info.Mode().Perm(), info.Size())
			}
			if mode == "own_partial" && info.Size() == 0 {
				t.Fatal("fixture did not exercise a partial write")
			}
		default:
			t.Fatalf("unknown fixture mode %s", mode)
		}
		if !strings.Contains(err.Error(), "empty/partial export may remain") {
			t.Fatal("save error omitted failed-artifact warning")
		}
	}
	if mode == "main_empty" {
		info, err := os.Stat(path)
		if err != nil || info.Size() != 0 || info.Mode().Perm() != 0600 {
			t.Fatalf("empty failed artifact not retained: %v %v", info, err)
		}
	}
}
