package leak

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// TCPFingerprint is a p0f-style read of a TCP SYN, from a captured packet.
type TCPFingerprint struct {
	TTL         int
	MSS         int
	Window      int
	WScale      int
	SACK        bool
	DF          bool
	OptionOrder string
	InitialTTL  int
	OSGuess     string
	Tunnel      bool
}

// ParseTCP parses an IPv4 packet containing a TCP SYN. IPv6 is accepted when
// the first nibble is 6 and the next header is TCP.
func ParseTCP(pkt []byte) (TCPFingerprint, error) {
	if len(pkt) < 20 {
		return TCPFingerprint{}, parseErr("short packet")
	}
	var fp TCPFingerprint
	ver := pkt[0] >> 4
	var tcp []byte
	switch ver {
	case 4:
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl {
			return TCPFingerprint{}, parseErr("bad ipv4 header")
		}
		fp.TTL = int(pkt[8])
		fp.DF = pkt[6]&0x40 != 0
		tcp = pkt[ihl:]
	case 6:
		if len(pkt) < 40 {
			return TCPFingerprint{}, parseErr("short ipv6")
		}
		fp.TTL = int(pkt[7])
		tcp = pkt[40:]
	default:
		return TCPFingerprint{}, parseErr("unknown ip version")
	}
	if len(tcp) < 20 {
		return TCPFingerprint{}, parseErr("short tcp")
	}
	fp.Window = int(binary.BigEndian.Uint16(tcp[14:16]))
	dataOff := int(tcp[12]>>4) * 4
	if dataOff < 20 || len(tcp) < dataOff {
		return TCPFingerprint{}, parseErr("bad tcp offset")
	}
	opts := tcp[20:dataOff]
	var order []string
	for len(opts) > 0 {
		kind := opts[0]
		if kind == 0 {
			order = append(order, "eol")
			break
		}
		if kind == 1 {
			order = append(order, "nop")
			opts = opts[1:]
			continue
		}
		if len(opts) < 2 {
			break
		}
		l := int(opts[1])
		if l < 2 || l > len(opts) {
			break
		}
		body := opts[2:l]
		switch kind {
		case 2:
			order = append(order, "mss")
			if len(body) >= 2 {
				fp.MSS = int(binary.BigEndian.Uint16(body))
			}
		case 3:
			order = append(order, "wscale")
			if len(body) >= 1 {
				fp.WScale = int(body[0])
			}
		case 4:
			order = append(order, "sackOK")
			fp.SACK = true
		case 8:
			order = append(order, "ts")
		default:
			order = append(order, fmt.Sprintf("opt%d", kind))
		}
		opts = opts[l:]
	}
	fp.OptionOrder = strings.Join(order, ",")
	fp.InitialTTL = guessTTL(fp.TTL)
	fp.OSGuess = guessOS(fp.InitialTTL)
	fp.Tunnel = fp.MSS > 0 && fp.MSS < 1400
	return fp, nil
}

func guessTTL(ttl int) int {
	switch {
	case ttl <= 64:
		return 64
	case ttl <= 128:
		return 128
	default:
		return 255
	}
}

func guessOS(initial int) string {
	switch initial {
	case 64:
		return "linux"
	case 128:
		return "windows"
	case 255:
		return "network"
	default:
		return "unknown"
	}
}

// UAMismatch is true when the user-agent claims an OS family that disagrees
// with the initial TTL bucket.
func UAMismatch(ua, osGuess string) bool {
	u := strings.ToLower(ua)
	switch osGuess {
	case "windows":
		return strings.Contains(u, "linux") && !strings.Contains(u, "windows") && strings.Contains(u, "x11")
	case "linux":
		return strings.Contains(u, "windows nt") && !strings.Contains(u, "linux")
	default:
		return false
	}
}
