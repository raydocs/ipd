package leak

import (
	"encoding/binary"
	"strconv"
	"strings"
)

// H2Fingerprint is the Akamai HTTP/2 fingerprint:
// S[;]|WU|P[,]#|PS[,]
type H2Fingerprint struct {
	Settings [][2]uint32
	Window   uint32
	Priority string
	Pseudo   []string
}

func (h H2Fingerprint) String() string {
	var s []string
	for _, kv := range h.Settings {
		s = append(s, strconv.FormatUint(uint64(kv[0]), 10)+":"+strconv.FormatUint(uint64(kv[1]), 10))
	}
	wu := ""
	if h.Window != 0 {
		wu = strconv.FormatUint(uint64(h.Window), 10)
	}
	return strings.Join(s, ";") + "|" + wu + "|" + h.Priority + "|" + strings.Join(h.Pseudo, ",")
}

// ParseH2 reads a connection preface plus the following frames and extracts
// the Akamai-style fingerprint: SETTINGS, connection WINDOW_UPDATE, PRIORITY
// frames, the HEADERS priority (after '#'), and pseudo-header order.
func ParseH2(payload []byte) H2Fingerprint {
	pref := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	if len(payload) >= len(pref) && string(payload[:len(pref)]) == string(pref) {
		payload = payload[len(pref):]
	}
	var fp H2Fingerprint
	var prios []string
	var headerPrio string
	var headerBlock []byte
	headersOpen := false
	for len(payload) >= 9 {
		ln := int(payload[0])<<16 | int(payload[1])<<8 | int(payload[2])
		typ := payload[3]
		flags := payload[4]
		sid := binary.BigEndian.Uint32(payload[5:9]) & 0x7fffffff
		payload = payload[9:]
		if ln > len(payload) {
			break
		}
		body := payload[:ln]
		payload = payload[ln:]
		switch typ {
		case 0x4: // SETTINGS
			if flags&0x1 != 0 {
				continue
			}
			for len(body) >= 6 {
				id := binary.BigEndian.Uint16(body)
				val := binary.BigEndian.Uint32(body[2:])
				body = body[6:]
				fp.Settings = append(fp.Settings, [2]uint32{uint32(id), val})
			}
		case 0x8: // WINDOW_UPDATE
			if sid == 0 && len(body) >= 4 && fp.Window == 0 {
				fp.Window = binary.BigEndian.Uint32(body) & 0x7fffffff
			}
		case 0x2: // PRIORITY
			if p := formatPriority(sid, body); p != "" {
				prios = append(prios, p)
			}
		case 0x1: // HEADERS
			block, prio := headerBody(sid, flags, body)
			if prio != "" {
				headerPrio = prio
			}
			headerBlock = append(headerBlock, block...)
			headersOpen = flags&0x4 == 0
			if !headersOpen {
				fp.Pseudo = decodePseudo(headerBlock)
			}
		case 0x9: // CONTINUATION
			if headersOpen {
				headerBlock = append(headerBlock, body...)
				if flags&0x4 != 0 {
					headersOpen = false
					fp.Pseudo = decodePseudo(headerBlock)
				}
			}
		}
	}
	fp.Priority = strings.Join(prios, ",")
	if headerPrio != "" {
		if fp.Priority != "" {
			fp.Priority += "#" + headerPrio
		} else {
			fp.Priority = "#" + headerPrio
		}
	}
	return fp
}

func formatPriority(stream uint32, body []byte) string {
	if len(body) < 5 {
		return ""
	}
	exclusive := 0
	if body[0]&0x80 != 0 {
		exclusive = 1
	}
	dep := binary.BigEndian.Uint32(body[:4]) & 0x7fffffff
	weight := body[4]
	return strconv.FormatUint(uint64(stream), 10) + ":" + strconv.Itoa(exclusive) + ":" + strconv.FormatUint(uint64(dep), 10) + ":" + strconv.Itoa(int(weight))
}

func headerBody(stream uint32, flags byte, body []byte) (block []byte, prio string) {
	if flags&0x08 != 0 && len(body) > 0 {
		pad := int(body[0])
		body = body[1:]
		if pad <= len(body) {
			body = body[:len(body)-pad]
		}
	}
	if flags&0x20 != 0 && len(body) >= 5 {
		prio = formatPriority(stream, body[:5])
		body = body[5:]
	}
	return body, prio
}

// Static table names that are pseudo-headers. Index 0 is unused.
var hpackPseudo = []string{
	"",
	":authority",
	":method",
	":method",
	":path",
	":path",
	":scheme",
	":scheme",
}

func pseudoShort(name string) string {
	switch name {
	case ":method":
		return "m"
	case ":authority":
		return "a"
	case ":scheme":
		return "s"
	case ":path":
		return "p"
	default:
		return ""
	}
}

func pseudoFromIndex(idx int) string {
	if idx > 0 && idx < len(hpackPseudo) {
		return pseudoShort(hpackPseudo[idx])
	}
	return ""
}

func decodePseudo(block []byte) []string {
	var out []string
	b := block
	for len(b) > 0 {
		x := b[0]
		switch {
		case x&0x80 != 0:
			idx, rest, ok := readHPACKInt(b, 7)
			if !ok {
				return out
			}
			b = rest
			if s := pseudoFromIndex(idx); s != "" {
				out = append(out, s)
			}
		case x&0xc0 == 0x40:
			idx, rest, ok := readHPACKInt(b, 6)
			if !ok {
				return out
			}
			rest, ok = consumeLiteral(rest, idx, &out)
			if !ok {
				return out
			}
			b = rest
		case x&0xe0 == 0x20:
			_, rest, ok := readHPACKInt(b, 5)
			if !ok {
				return out
			}
			b = rest
		case x&0xf0 == 0x10:
			idx, rest, ok := readHPACKInt(b, 4)
			if !ok {
				return out
			}
			rest, ok = consumeLiteral(rest, idx, &out)
			if !ok {
				return out
			}
			b = rest
		case x&0xf0 == 0x00:
			idx, rest, ok := readHPACKInt(b, 4)
			if !ok {
				return out
			}
			rest, ok = consumeLiteral(rest, idx, &out)
			if !ok {
				return out
			}
			b = rest
		default:
			return out
		}
	}
	return out
}

func consumeLiteral(b []byte, nameIdx int, out *[]string) ([]byte, bool) {
	if nameIdx == 0 {
		name, rest, ok := readString(b)
		if !ok {
			return nil, false
		}
		b = rest
		if s := pseudoShort(name); s != "" {
			*out = append(*out, s)
		}
	} else if s := pseudoFromIndex(nameIdx); s != "" {
		*out = append(*out, s)
	}
	return skipString(b)
}

func readHPACKInt(b []byte, prefixBits int) (int, []byte, bool) {
	if len(b) == 0 || prefixBits <= 0 || prefixBits > 8 {
		return 0, b, false
	}
	max := (1 << prefixBits) - 1
	val := int(b[0]) & max
	b = b[1:]
	if val < max {
		return val, b, true
	}
	m := 0
	for {
		if len(b) == 0 || m > 21 {
			return 0, nil, false
		}
		x := int(b[0])
		b = b[1:]
		val += (x & 127) << m
		m += 7
		if x&128 == 0 {
			return val, b, true
		}
	}
}

func skipString(b []byte) ([]byte, bool) {
	n, rest, ok := readHPACKInt(b, 7)
	if !ok || n < 0 || n > len(rest) {
		return nil, false
	}
	return rest[n:], true
}

func readString(b []byte) (string, []byte, bool) {
	if len(b) == 0 {
		return "", nil, false
	}
	huff := b[0]&0x80 != 0
	n, rest, ok := readHPACKInt(b, 7)
	if !ok || n > len(rest) {
		return "", nil, false
	}
	raw := rest[:n]
	rest = rest[n:]
	if huff {
		return "", rest, true
	}
	return string(raw), rest, true
}

// ProxyRTT reports whether the application RTT is far above the TCP handshake
// RTT, which usually means an extra proxy hop.
func ProxyRTT(tcpMS, appMS float64) bool {
	if appMS < 40 || tcpMS < 0 {
		return false
	}
	return appMS > tcpMS*3 && appMS-tcpMS > 30
}
