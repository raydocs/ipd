//go:build linux

package route

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

func platformTrace(ctx context.Context, dst netip.Addr, maxHops int) ([]Hop, error) {
	var notes []string
	hops, err := udpTrace(ctx, dst, maxHops)
	if err != nil {
		notes = append(notes, "udp: "+err.Error())
	}
	if realHops(hops) > 0 {
		return hops, err
	}
	ihops, ierr := icmpTrace(ctx, dst, maxHops)
	if ierr != nil {
		notes = append(notes, "icmp: "+ierr.Error())
	}
	if realHops(ihops) > realHops(hops) {
		return ihops, ierr
	}
	thops, terr := tcpTrace(ctx, dst, maxHops)
	if terr != nil {
		notes = append(notes, "tcp: "+terr.Error())
	}
	if realHops(thops) > 0 {
		return thops, terr
	}
	if realHops(hops) > 0 {
		return hops, err
	}
	if len(notes) == 0 {
		notes = append(notes, "no icmp time-exceeded")
	}
	if len(ihops) > len(hops) {
		hops = ihops
	}
	if len(thops) > len(hops) {
		hops = thops
	}
	return hops, fmt.Errorf("%s", joinNotes(notes))
}

func joinNotes(n []string) string {
	out := n[0]
	for _, s := range n[1:] {
		out += "; " + s
	}
	return out
}

var errUDPTimeout = errors.New("UDP reply timeout")

func udpTrace(ctx context.Context, dst netip.Addr, maxHops int) ([]Hop, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVERR, 1); err != nil {
		return nil, fmt.Errorf("IP_RECVERR: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrInet4{}); err != nil {
		return nil, err
	}
	ip := dst.As4()
	var hops []Hop
	stars := 0
	for ttl := 1; ttl <= maxHops; ttl++ {
		if ctx.Err() != nil {
			return hops, ctx.Err()
		}
		drainErr(fd)
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TTL, ttl); err != nil {
			return hops, err
		}
		sa := &unix.SockaddrInet4{Port: 33434 + ttl, Addr: ip}
		start := time.Now()
		if err := unix.Sendto(fd, []byte{0}, 0, sa); err != nil {
			return hops, fmt.Errorf("%w", err)
		}
		hop, done, err := recvErr(fd, dst, 450*time.Millisecond)
		if err != nil {
			if hop.IP == "" {
				hop.IP = "*"
			}
			hop.RTTMS = float64(time.Since(start).Microseconds()) / 1000
			hops = append(hops, hop)
			if !errors.Is(err, errUDPTimeout) {
				return hops, err
			}
			stars++
			if stars >= 4 && realHops(hops) == 0 {
				return hops, fmt.Errorf("no icmp time-exceeded (udp)")
			}
			continue
		}
		hop.RTTMS = float64(time.Since(start).Microseconds()) / 1000
		hops = append(hops, hop)
		if hop.IP != "*" {
			stars = 0
		}
		if done {
			return hops, nil
		}
	}
	return hops, fmt.Errorf("hop limit reached before destination")
}

func drainErr(fd int) {
	var buf [1500]byte
	var oob [512]byte
	for {
		_, _, _, _, err := unix.Recvmsg(fd, buf[:], oob[:], unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
		if err != nil {
			return
		}
	}
}

func recvErr(fd int, dst netip.Addr, wait time.Duration) (Hop, bool, error) {
	// MSG_ERRQUEUE does not block. POLLERR is the signal that an ICMP error is queued.
	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLERR}}
	n, err := unix.Poll(pfd, int(wait.Milliseconds()))
	if err != nil {
		return Hop{}, false, err
	}
	if n == 0 {
		return Hop{}, false, errUDPTimeout
	}
	var buf [1500]byte
	var oob [512]byte
	_, oobn, _, _, err := unix.Recvmsg(fd, buf[:], oob[:], unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
	if err != nil {
		return Hop{}, false, err
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return Hop{}, false, err
	}
	for _, m := range msgs {
		if m.Header.Level == unix.IPPROTO_IP && m.Header.Type == unix.IP_RECVERR {
			return parseUDPExtendedError(m.Data, dst)
		}
	}
	return Hop{}, false, fmt.Errorf("missing UDP extended error")
}

func icmpTrace(ctx context.Context, dst netip.Addr, maxHops int) ([]Hop, error) {
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("%w (CAP_NET_RAW or ping_group_range)", err)
	}
	defer c.Close()
	p := ipv4.NewPacketConn(c)
	id := os.Getpid() & 0xffff
	var hops []Hop
	for ttl := 1; ttl <= maxHops; ttl++ {
		if ctx.Err() != nil {
			return hops, ctx.Err()
		}
		if err := p.SetTTL(ttl); err != nil {
			return hops, err
		}
		msg := icmp.Message{
			Type: ipv4.ICMPTypeEcho, Code: 0,
			Body: &icmp.Echo{ID: id, Seq: ttl, Data: []byte("ipd-trace")},
		}
		b, err := msg.Marshal(nil)
		if err != nil {
			return hops, err
		}
		start := time.Now()
		if _, err := c.WriteTo(b, &net.IPAddr{IP: dst.AsSlice()}); err != nil {
			return hops, err
		}
		_ = c.SetReadDeadline(time.Now().Add(450 * time.Millisecond))
		buf := make([]byte, 1500)
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			hops = append(hops, Hop{IP: "*"})
			if realHops(hops) == 0 && ttl >= 4 {
				return hops, fmt.Errorf("no icmp reply")
			}
			continue
		}
		peer, _, _ := net.SplitHostPort(from.String())
		if peer == "" {
			peer = from.String()
		}
		rm, err := icmp.ParseMessage(1, buf[:n])
		done := false
		if err == nil && rm.Type == ipv4.ICMPTypeEchoReply {
			done = true
		}
		hops = append(hops, Hop{IP: peer, RTTMS: float64(time.Since(start).Microseconds()) / 1000})
		if done || peer == dst.String() {
			return hops, nil
		}
	}
	return hops, fmt.Errorf("hop limit reached before destination")
}

func tcpTrace(ctx context.Context, dst netip.Addr, maxHops int) ([]Hop, error) {
	icmpFD, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
	if err != nil {
		return nil, fmt.Errorf("raw icmp: %w", err)
	}
	defer unix.Close(icmpFD)
	tcpFD, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("raw tcp: %w", err)
	}
	defer unix.Close(tcpFD)
	var hops []Hop
	ip := dst.As4()
	for ttl := 1; ttl <= maxHops; ttl++ {
		if ctx.Err() != nil {
			return hops, ctx.Err()
		}
		if err := unix.SetsockoptInt(tcpFD, unix.IPPROTO_IP, unix.IP_TTL, ttl); err != nil {
			return hops, err
		}
		pkt := synPacket(ip, 443, 40000+ttl)
		start := time.Now()
		if err := unix.Sendto(tcpFD, pkt, 0, &unix.SockaddrInet4{Port: 443, Addr: ip}); err != nil {
			return hops, err
		}
		hop, done, err := readRawICMP(icmpFD, dst, 450*time.Millisecond)
		if err != nil {
			hops = append(hops, Hop{IP: "*"})
			if realHops(hops) == 0 && ttl >= 3 {
				return hops, fmt.Errorf("tcp traceroute got no icmp")
			}
			continue
		}
		hop.RTTMS = float64(time.Since(start).Microseconds()) / 1000
		hops = append(hops, hop)
		if done {
			return hops, nil
		}
	}
	return hops, fmt.Errorf("hop limit reached before destination")
}

func synPacket(dst [4]byte, dport, sport int) []byte {
	hdr := make([]byte, 20)
	binary.BigEndian.PutUint16(hdr[0:2], uint16(sport))
	binary.BigEndian.PutUint16(hdr[2:4], uint16(dport))
	binary.BigEndian.PutUint32(hdr[4:8], uint32(sport*17+dport))
	hdr[12] = 5 << 4
	hdr[13] = 0x02
	binary.BigEndian.PutUint16(hdr[14:16], 65535)
	sum := tcpChecksum(dst, hdr)
	binary.BigEndian.PutUint16(hdr[16:18], sum)
	return hdr
}

func tcpChecksum(dst [4]byte, tcp []byte) uint16 {
	src := localV4()
	var sum uint32
	sum += uint32(src[0])<<8 | uint32(src[1])
	sum += uint32(src[2])<<8 | uint32(src[3])
	sum += uint32(dst[0])<<8 | uint32(dst[1])
	sum += uint32(dst[2])<<8 | uint32(dst[3])
	sum += uint32(unix.IPPROTO_TCP)
	sum += uint32(len(tcp))
	for i := 0; i+1 < len(tcp); i += 2 {
		sum += uint32(tcp[i])<<8 | uint32(tcp[i+1])
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func localV4() [4]byte {
	c, err := net.Dial("udp4", "8.8.8.8:80")
	if err != nil {
		return [4]byte{}
	}
	defer c.Close()
	addr, _ := netip.ParseAddrPort(c.LocalAddr().String())
	if addr.Addr().Is4() {
		return addr.Addr().As4()
	}
	return [4]byte{}
}

func readRawICMP(fd int, dst netip.Addr, wait time.Duration) (Hop, bool, error) {
	tv := unix.NsecToTimeval(wait.Nanoseconds())
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	var buf [1500]byte
	n, _, err := unix.Recvfrom(fd, buf[:], 0)
	if err != nil {
		return Hop{}, false, err
	}
	if n < 20 {
		return Hop{}, false, fmt.Errorf("short icmp")
	}
	ihl := int(buf[0]&0x0f) * 4
	if n < ihl+8 {
		return Hop{}, false, fmt.Errorf("short icmp")
	}
	src := net.IP(buf[12:16]).String()
	typ := buf[ihl]
	done := typ == 0 || src == dst.String()
	// Dest unreachable / echo reply / time exceeded are all useful.
	if typ != 11 && typ != 3 && typ != 0 {
		return Hop{}, false, fmt.Errorf("icmp type %d", typ)
	}
	return Hop{IP: src}, done, nil
}
