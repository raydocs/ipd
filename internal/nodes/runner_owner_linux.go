//go:build linux

package nodes

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func runnerOwnershipAvailable() error {
	for _, path := range []string{"/proc/self/net/tcp", "/proc/self/net/tcp6", "/proc/self/fd", "/proc/self/ns/net"} {
		if _, err := os.Stat(path); err != nil {
			return ErrRunnerUnsupported
		}
	}
	return nil
}

func runnerOwnsListener(ctx context.Context, pid, port int) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	base := filepath.Join("/proc", strconv.Itoa(pid))
	selfNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return false, ErrRunnerUnsupported
	}
	childNS, err := os.Readlink(filepath.Join(base, "ns/net"))
	if err != nil {
		if os.IsNotExist(err) {
			return false, ErrRunnerExit
		}
		return false, ErrRunnerUnsupported
	}
	if selfNS != childNS {
		return false, ErrRunnerUnsupported
	}
	// A live direct child anchors the PID; an unrelated reused PID is not accepted.
	stat, err := os.ReadFile(filepath.Join(base, "stat"))
	if err != nil {
		if os.IsNotExist(err) {
			return false, ErrRunnerExit
		}
		return false, ErrRunnerUnsupported
	}
	end := strings.LastIndex(string(stat), ") ")
	if end < 0 {
		return false, ErrRunnerUnsupported
	}
	fields := strings.Fields(string(stat)[end+2:])
	if len(fields) >= 1 && fields[0] == "Z" {
		return false, ErrRunnerExit
	}
	if len(fields) < 2 || fields[1] != strconv.Itoa(os.Getpid()) {
		return false, ErrRunnerOwnership
	}
	var listeners []runnerTCPSocket
	for _, name := range []string{"tcp", "tcp6"} {
		data, err := os.ReadFile("/proc/self/net/" + name)
		if err != nil {
			return false, ErrRunnerUnsupported
		}
		found, err := runnerTCPListeners(data, port)
		if err != nil {
			return false, err
		}
		listeners = append(listeners, found...)
	}
	if len(listeners) == 0 {
		return false, nil
	}
	loopback := fmt.Sprintf("%08X:%04X", binary.NativeEndian.Uint32([]byte{127, 0, 0, 1}), port)
	if len(listeners) != 1 || listeners[0].local != loopback || listeners[0].inode == "0" {
		return false, ErrRunnerOwnership
	}
	fds, err := os.ReadDir(filepath.Join(base, "fd"))
	if err != nil {
		return false, ErrRunnerUnsupported
	}
	socket := "socket:[" + listeners[0].inode + "]"
	for _, fd := range fds {
		link, err := os.Readlink(filepath.Join(base, "fd", fd.Name()))
		if os.IsNotExist(err) {
			continue
		} // Unrelated fds may close during the snapshot.
		if err != nil {
			return false, ErrRunnerUnsupported
		}
		if link == socket {
			return true, nil
		}
	}
	return false, ErrRunnerOwnership
}
