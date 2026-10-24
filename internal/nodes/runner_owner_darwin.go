//go:build darwin

package nodes

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

const runnerLsof = "/usr/sbin/lsof"

func runnerOwnershipAvailable() error {
	st, err := os.Stat(runnerLsof)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0111 == 0 || st.Mode().Perm()&0022 != 0 {
		return ErrRunnerUnsupported
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return ErrRunnerUnsupported
	}
	return nil
}

func runnerOwnsListener(ctx context.Context, pid, port int) (bool, error) {
	// No PID filter: multiple listeners (including wildcard/IPv6 and reuse-port
	// groups) at this port are ambiguous and must not be accepted as our child.
	cmd := exec.CommandContext(ctx, runnerLsof, "-nP", "-iTCP:"+strconv.Itoa(port), "-sTCP:LISTEN", "-F0pRftPnT")
	cmd.Env = []string{"LC_ALL=C"}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 1 && len(out) == 0 && stderr.Len() == 0 {
			return false, nil
		}
		return false, ErrRunnerUnsupported
	}
	if stderr.Len() != 0 {
		return false, ErrRunnerUnsupported
	}
	return runnerLsofOwns(out, pid, os.Getpid(), port)
}
