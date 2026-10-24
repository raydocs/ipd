package nodes

import (
	"bytes"
	"strconv"
	"strings"
)

type runnerTCPSocket struct{ local, inode string }

// Linux's proc TCP tables expose LISTEN (0A), local address and socket inode.
// Inspect all addresses/families at the chosen port; do not overlook wildcard
// listeners or a second SO_REUSEPORT listener with a different inode.
func runnerTCPListeners(data []byte, port int) ([]runnerTCPSocket, error) {
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 || !strings.Contains(lines[0], "local_address") {
		return nil, ErrRunnerUnsupported
	}
	var sockets []runnerTCPSocket
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) < 10 {
			return nil, ErrRunnerUnsupported
		}
		local := strings.Split(f[1], ":")
		if len(local) != 2 {
			return nil, ErrRunnerUnsupported
		}
		p, err := strconv.ParseUint(local[1], 16, 16)
		if err != nil {
			return nil, ErrRunnerUnsupported
		}
		if f[3] != "0A" || int(p) != port {
			continue
		}
		if _, err := strconv.ParseUint(f[9], 10, 64); err != nil {
			return nil, ErrRunnerUnsupported
		}
		sockets = append(sockets, runnerTCPSocket{f[1], f[9]})
	}
	return sockets, nil
}

// Parse lsof's NUL-delimited machine format, not human tables or command names.
// Every selected listening fd must be the one exact IPv4 loopback listener in
// the live direct child. R (parent PID) also prevents accepting an unrelated
// process after PID reuse. Missing/ambiguous kernel evidence is never success.
func runnerLsofOwns(data []byte, pid, parent, port int) (bool, error) {
	if len(data) == 0 {
		return false, nil
	}
	type socket struct{ pid, parent, fd, family, protocol, name, state string }
	var current socket
	var sockets []socket
	owner, ppid := "", ""
	flush := func() {
		if current.fd != "" {
			sockets = append(sockets, current)
		}
		current = socket{}
	}
	for _, raw := range bytes.Split(data, []byte{0}) {
		field := strings.TrimLeft(string(raw), "\n")
		if field == "" {
			continue
		}
		switch field[0] {
		case 'p':
			flush()
			owner = field[1:]
			ppid = ""
		case 'R':
			ppid = field[1:]
		case 'f':
			flush()
			current = socket{pid: owner, parent: ppid, fd: field[1:]}
		case 't':
			current.family = field[1:]
		case 'P':
			current.protocol = field[1:]
		case 'n':
			current.name = field[1:]
		case 'T':
			if strings.HasPrefix(field, "TST=") {
				current.state = strings.TrimPrefix(field, "TST=")
			}
		default:
			return false, ErrRunnerUnsupported
		}
	}
	flush()
	if len(sockets) != 1 {
		return false, ErrRunnerOwnership
	}
	s := sockets[0]
	if s.pid != strconv.Itoa(pid) || s.parent != strconv.Itoa(parent) || s.family != "IPv4" || s.protocol != "TCP" || s.name != "127.0.0.1:"+strconv.Itoa(port) || s.state != "LISTEN" {
		return false, ErrRunnerOwnership
	}
	if _, err := strconv.ParseUint(strings.TrimRight(s.fd, "rwu"), 10, 32); err != nil {
		return false, ErrRunnerUnsupported
	}
	return true, nil
}
