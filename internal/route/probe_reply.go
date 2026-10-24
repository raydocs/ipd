package route

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// rawProbe identifies one outstanding IPv4 probe, never an entire trace.
// The receiver cannot authenticate ICMP; unpredictable identifiers reject blind
// guesses, but a party observing the probe can still forge a matching response.
type rawProbe struct {
	destination                 netip.Addr
	protocol                    byte
	echoID, echoSeq             uint16
	token                       []byte
	sourcePort, destinationPort uint16
	tcpSeq                      uint32
}

// ipv4Payload permits a truncated quotation, but not a truncated outer packet.
// Reject all fragments: transport identifiers in fragments are not sufficient
// evidence for this probe. IHL and total length bound any quoted extension data.
func ipv4Payload(packet []byte, quoted bool) ([]byte, netip.Addr, netip.Addr, byte, bool) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return nil, netip.Addr{}, netip.Addr{}, 0, false
	}
	ihl := int(packet[0]&15) * 4
	total := int(binary.BigEndian.Uint16(packet[2:4]))
	if ihl < 20 || len(packet) < ihl || total < ihl+8 || len(packet) < ihl+8 || binary.BigEndian.Uint16(packet[6:8])&0xbfff != 0 {
		return nil, netip.Addr{}, netip.Addr{}, 0, false
	}
	if total > len(packet) {
		if !quoted {
			return nil, netip.Addr{}, netip.Addr{}, 0, false
		}
	} else {
		packet = packet[:total]
	}
	return packet[ihl:], netip.AddrFrom4([4]byte(packet[12:16])), netip.AddrFrom4([4]byte(packet[16:20])), packet[9], true
}

func validICMPChecksum(packet []byte) bool {
	var sum uint32
	for len(packet) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(packet))
		packet = packet[2:]
	}
	if len(packet) > 0 {
		sum += uint32(packet[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return sum == 0xffff
}

// parseProbeReply receives an ICMP message without its outer IPv4 header.
// An empty hop means unrelated/insufficient evidence, not a timeout or error.
func parseProbeReply(packet []byte, peer netip.Addr, probe rawProbe) (Hop, bool, error) {
	if len(packet) < 8 || !peer.Is4() || peer.IsUnspecified() || peer.IsMulticast() || !validICMPChecksum(packet) {
		return Hop{}, false, nil
	}
	typ, code := packet[0], packet[1]
	if typ == 0 {
		if probe.protocol != 1 || peer != probe.destination || code != 0 || binary.BigEndian.Uint16(packet[4:6]) != probe.echoID || binary.BigEndian.Uint16(packet[6:8]) != probe.echoSeq || len(probe.token) == 0 || !bytes.Equal(packet[8:], probe.token) {
			return Hop{}, false, nil
		}
		return Hop{IP: peer.String()}, true, nil
	}
	if (typ != 11 || code != 0) && (typ != 3 || code > 15) {
		return Hop{}, false, nil
	}
	quote := packet[8:]
	quoted, _, destination, protocol, ok := ipv4Payload(quote, true)
	if !ok || protocol != probe.protocol || destination != probe.destination {
		return Hop{}, false, nil
	}
	probeLength := int(binary.BigEndian.Uint16(quote[2:4])) - int(quote[0]&15)*4
	switch protocol {
	case 1:
		if len(probe.token) == 0 || probeLength != 8+len(probe.token) {
			return Hop{}, false, nil
		}
		if quoted[0] != 8 || quoted[1] != 0 || binary.BigEndian.Uint16(quoted[4:6]) != probe.echoID || binary.BigEndian.Uint16(quoted[6:8]) != probe.echoSeq {
			return Hop{}, false, nil
		}
		// RFC-minimum quotations contain only the ICMP header. If token bytes are
		// present, require every available byte to match (never guess missing bytes).
		token := quoted[8:]
		if len(token) > len(probe.token) || !bytes.Equal(token, probe.token[:len(token)]) {
			return Hop{}, false, nil
		}
	case 6:
		if probeLength != 20 {
			return Hop{}, false, nil
		}
		if binary.BigEndian.Uint16(quoted[:2]) != probe.sourcePort || binary.BigEndian.Uint16(quoted[2:4]) != probe.destinationPort || binary.BigEndian.Uint32(quoted[4:8]) != probe.tcpSeq {
			return Hop{}, false, nil
		}
	default:
		return Hop{}, false, nil
	}
	hop := Hop{IP: peer.String()}
	if typ == 3 {
		return hop, false, fmt.Errorf("correlated ICMP destination unreachable code %d from %s", code, peer)
	}
	return hop, false, nil
}

func parseRawProbeReply(packet []byte, probe rawProbe) (Hop, bool, error) {
	message, source, _, protocol, ok := ipv4Payload(packet, false)
	if !ok || protocol != 1 {
		return Hop{}, false, nil
	}
	return parseProbeReply(message, source, probe)
}

var errRawProbeTimeout = errors.New("raw probe reply timeout")

type probePacketReader func(deadline time.Time) ([]byte, netip.Addr, error)

// awaitProbeReply uses a single absolute budget across unrelated packets and
// interrupted reads. Short bounded reads also observe cancellation without
// spawning a goroutine that could outlive the socket or the next probe.
func awaitProbeReply(ctx context.Context, wait time.Duration, now func() time.Time, read probePacketReader, parse func([]byte, netip.Addr) (Hop, bool, error)) (Hop, bool, error) {
	deadline := now().Add(wait)
	timeoutErr := errRawProbeTimeout
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
		timeoutErr = context.DeadlineExceeded
	}
	for {
		if err := ctx.Err(); err != nil {
			return Hop{}, false, err
		}
		current := now()
		if !current.Before(deadline) {
			return Hop{}, false, timeoutErr
		}
		readDeadline := current.Add(25 * time.Millisecond)
		if deadline.Before(readDeadline) {
			readDeadline = deadline
		}
		packet, peer, err := read(readDeadline)
		if ctx.Err() != nil {
			return Hop{}, false, ctx.Err()
		}
		if err != nil {
			var ne net.Error
			if errors.Is(err, errRawProbeTimeout) || errors.Is(err, syscall.EINTR) || (errors.As(err, &ne) && ne.Timeout()) {
				continue
			}
			return Hop{}, false, err
		}
		// A reader that returns data at/after the deadline cannot extend the budget.
		if !now().Before(deadline) {
			return Hop{}, false, timeoutErr
		}
		hop, done, err := parse(packet, peer)
		if hop.IP != "" || err != nil {
			return hop, done, err
		}
	}
}
