//go:build linux

package listen

import (
	"net"

	"golang.org/x/sys/unix"
)

func peerMSS(c net.Conn) int {
	tcp, ok := underlyingTCP(c)
	if !ok {
		return 0
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return 0
	}
	var mss int
	_ = raw.Control(func(fd uintptr) {
		info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		if err == nil && info != nil && info.Snd_mss > 0 {
			mss = int(info.Snd_mss)
		}
	})
	return mss
}

func underlyingTCP(c net.Conn) (*net.TCPConn, bool) {
	for {
		if tcp, ok := c.(*net.TCPConn); ok {
			return tcp, true
		}
		type unwrapper interface{ NetConn() net.Conn }
		u, ok := c.(unwrapper)
		if !ok {
			return nil, false
		}
		c = u.NetConn()
	}
}
