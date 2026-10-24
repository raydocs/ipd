//go:build linux

package route

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
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
		return hops, nil
	}
	ihops, ierr := icmpTrace(ctx, dst, maxHops)
	if ierr != nil {
		notes = append(notes, "icmp: "+ierr.Error())
	} else if realHops(ihops) > realHops(hops) {
		return ihops, nil
	}
	thops, terr := tcpTrace(ctx, dst, maxHops)
	if terr != nil {
		notes = append(notes, "tcp: "+terr.Error())
	} else if realHops(thops) > 0 {
		return thops, nil
	}
	if realHops(hops) > 0 {
		return hops, nil
	}
	if len(notes) == 0 {
		notes = append(notes, "no icmp time-exceeded")
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
			return nil, fmt.Errorf("%w", err)
		}
		hop, done, err := recvErr(fd, 450*time.Millisecond)
		if err != nil {
			hops = append(hops, Hop{IP: "*"})
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
	return hops, nil
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

func recvErr(fd int, wait time.Duration) (Hop, bool, error) {
	// MSG_ERRQUEUE does not block. POLLERR is the signal that an ICMP error is queued.
	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLERR}}
	n, err := unix.Poll(pfd, int(wait.Milliseconds()))
	if err != nil {
		return Hop{}, false, err
	}
	if n == 0 {
		return Hop{}, false, fmt.Errorf("timeout")
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
	var hop Hop
	done := false
	for _, m := range msgs {
		if m.Header.Level != unix.IPPROTO_IP || m.Header.Type != unix.IP_RECVERR || len(m.Data) < 16 {
			continue
		}
		typ := m.Data[5]
		if typ == 3 {
			done = true
		}
		if ip := offenderIP(m.Data[16:]); ip != "" {
			hop.IP = ip
		}
	}
	if hop.IP == "" {
		hop.IP = "*"
	}
	return hop, done, nil
}

func offenderIP(b []byte) string {
	if len(b) < 8 {
		return ""
	}
	family := binary.NativeEndian.Uint16(b[:2])
	if family != unix.AF_INET {
		return ""
	}
	return net.IP(b[4:8]).String()
}

func icmpTrace(ctx context.Context, dst netip.Addr, maxHops int) ([]Hop, error) {
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("%w (CAP_NET_RAW or ping_group_range)", err)
	}
	defer c.Close()
	p, err := traceIPv4Conn(c)
	if err != nil {
		return nil, err
	}
	var hops []Hop
	for ttl := 1; ttl <= maxHops; ttl++ {
		if ctx.Err() != nil {
			return hops, ctx.Err()
		}
		if err := p.SetTTL(ttl); err != nil {
			return hops, err
		}
		var identity [20]byte
		if _, err := rand.Read(identity[:]); err != nil {
			return hops, err
		}
		probe := rawProbe{destination: dst, protocol: 1,
			echoID: binary.BigEndian.Uint16(identity[:2]), echoSeq: binary.BigEndian.Uint16(identity[2:4]), token: identity[4:]}
		msg := icmp.Message{
			Type: ipv4.ICMPTypeEcho, Code: 0,
			Body: &icmp.Echo{ID: int(probe.echoID), Seq: int(probe.echoSeq), Data: probe.token},
		}
		b, err := msg.Marshal(nil)
		if err != nil {
			return hops, err
		}
		start := time.Now()
		if _, err := c.WriteTo(b, &net.IPAddr{IP: dst.AsSlice()}); err != nil {
			return hops, err
		}
		buf := make([]byte, 1500)
		hop, done, err := awaitProbeReply(ctx, 450*time.Millisecond, time.Now,
			func(deadline time.Time) ([]byte, netip.Addr, error) {
				if err := c.SetReadDeadline(deadline); err != nil {
					return nil, netip.Addr{}, err
				}
				n, from, err := c.ReadFrom(buf)
				if err != nil {
					return nil, netip.Addr{}, err
				}
				peer := netip.Addr{}
				if ip, ok := from.(*net.IPAddr); ok {
					peer, _ = netip.AddrFromSlice(ip.IP)
					peer = peer.Unmap()
				}
				return buf[:n], peer, nil
			}, func(packet []byte, peer netip.Addr) (Hop, bool, error) { return parseProbeReply(packet, peer, probe) })
		if ctx.Err() != nil {
			return hops, ctx.Err()
		}
		if hop.IP != "" {
			hop.RTTMS = float64(time.Since(start).Microseconds()) / 1000
			hops = append(hops, hop)
		}
		if err != nil {
			if !errors.Is(err, errRawProbeTimeout) {
				return hops, err
			}
			hops = append(hops, Hop{IP: "*"})
			if realHops(hops) == 0 && ttl >= 4 {
				return hops, fmt.Errorf("no icmp reply")
			}
			continue
		}
		if done {
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
		var identity [4]byte
		if _, err := rand.Read(identity[:]); err != nil {
			return hops, err
		}
		probe := rawProbe{destination: dst, protocol: 6, sourcePort: uint16(40000 + ttl), destinationPort: 443, tcpSeq: binary.BigEndian.Uint32(identity[:])}
		pkt := synPacket(ip, int(probe.destinationPort), int(probe.sourcePort), probe.tcpSeq)
		start := time.Now()
		if err := unix.Sendto(tcpFD, pkt, 0, &unix.SockaddrInet4{Port: 443, Addr: ip}); err != nil {
			return hops, err
		}
		hop, done, err := readRawICMP(ctx, icmpFD, probe, 450*time.Millisecond)
		if ctx.Err() != nil {
			return hops, ctx.Err()
		}
		if hop.IP != "" {
			hop.RTTMS = float64(time.Since(start).Microseconds()) / 1000
			hops = append(hops, hop)
		}
		if err != nil {
			if !errors.Is(err, errRawProbeTimeout) {
				return hops, err
			}
			hops = append(hops, Hop{IP: "*"})
			if realHops(hops) == 0 && ttl >= 3 {
				return hops, fmt.Errorf("tcp traceroute got no icmp")
			}
			continue
		}
		if done {
			return hops, nil
		}
	}
	return hops, fmt.Errorf("hop limit reached before destination")
}

func synPacket(dst [4]byte, dport, sport int, seq uint32) []byte {
	hdr := make([]byte, 20)
	binary.BigEndian.PutUint16(hdr[0:2], uint16(sport))
	binary.BigEndian.PutUint16(hdr[2:4], uint16(dport))
	binary.BigEndian.PutUint32(hdr[4:8], seq)
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

func readRawICMP(ctx context.Context, fd int, probe rawProbe, wait time.Duration) (Hop, bool, error) {
	var buf [1500]byte
	return awaitProbeReply(ctx, wait, time.Now,
		func(deadline time.Time) ([]byte, netip.Addr, error) {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return nil, netip.Addr{}, errRawProbeTimeout
			}
			pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			n, err := unix.Poll(pfd, int((remaining+time.Millisecond-1)/time.Millisecond))
			if err != nil {
				return nil, netip.Addr{}, err
			}
			if n == 0 {
				return nil, netip.Addr{}, errRawProbeTimeout
			}
			n, _, err = unix.Recvfrom(fd, buf[:], unix.MSG_DONTWAIT)
			if errors.Is(err, unix.EAGAIN) {
				return nil, netip.Addr{}, errRawProbeTimeout
			}
			if err != nil {
				return nil, netip.Addr{}, err
			}
			return buf[:n], netip.Addr{}, nil
		}, func(packet []byte, _ netip.Addr) (Hop, bool, error) { return parseRawProbeReply(packet, probe) })
}
