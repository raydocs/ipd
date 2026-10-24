package leak

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

// JA4 builds the basic JA4 fingerprint (not JA4+). The algorithm follows the
// published JA4 specification. Protocol is "t" for TCP, "q" for QUIC, "d" for DTLS.
func JA4(ch ClientHello, proto byte) string {
	if proto == 0 {
		proto = 't'
	}
	ver := ja4Version(ch)
	sni := "i"
	var alpn []byte
	var sigs []uint16
	exts := make([]uint16, 0, len(ch.Extensions))
	ciphers := make([]uint16, 0, len(ch.Ciphers))
	for _, c := range ch.Ciphers {
		if IsGREASE(c) {
			continue
		}
		ciphers = append(ciphers, c)
	}
	for _, e := range ch.Extensions {
		if IsGREASE(e.Type) {
			continue
		}
		exts = append(exts, e.Type)
		if e.Type == 0 {
			sni = "d"
		}
		if e.Type == 16 && len(alpn) == 0 {
			alpn = firstALPN(e.Data)
		}
		if e.Type == 13 {
			sigs = sigAlgs(e.Data)
		}
	}
	a := string(proto) + ver + sni + two(len(ciphers)) + two(len(exts)) + alpnPart(alpn)
	b := hashList(sortedHex(ciphers))
	sortedExt := make([]uint16, 0, len(exts))
	for _, e := range exts {
		if e == 0 || e == 16 {
			continue
		}
		sortedExt = append(sortedExt, e)
	}
	sort.Slice(sortedExt, func(i, j int) bool { return sortedExt[i] < sortedExt[j] })
	extStr := joinHex(sortedExt)
	if len(sigs) > 0 {
		if extStr != "" {
			extStr += "_"
		}
		extStr += joinHex(sigs)
	}
	c := hashList(extStr)
	if len(sortedExt) == 0 && len(sigs) == 0 {
		c = "000000000000"
	}
	return a + "_" + b + "_" + c
}

func ja4Version(ch ClientHello) string {
	v := ch.Version
	if s := supportedVersion(ch); s != 0 {
		v = s
	}
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0xfeff:
		return "d1"
	case 0xfefd:
		return "d2"
	case 0xfefc:
		return "d3"
	default:
		return "00"
	}
}

func two(n int) string {
	if n > 99 {
		n = 99
	}
	return leftPad(strconv.Itoa(n), 2)
}

func leftPad(s string, n int) string {
	for len(s) < n {
		s = "0" + s
	}
	return s
}

func firstALPN(data []byte) []byte {
	if len(data) < 3 {
		return nil
	}
	// list length
	list := int(binary.BigEndian.Uint16(data))
	data = data[2:]
	if list < len(data) {
		data = data[:list]
	}
	if len(data) < 1 {
		return nil
	}
	n := int(data[0])
	data = data[1:]
	if n > len(data) {
		n = len(data)
	}
	return data[:n]
}

func alpnPart(v []byte) string {
	if len(v) == 0 {
		return "00"
	}
	alnum := func(b byte) bool {
		return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
	}
	if !alnum(v[0]) || !alnum(v[len(v)-1]) {
		h := hex.EncodeToString(v)
		if len(h) == 1 {
			return h + h
		}
		return string([]byte{h[0], h[len(h)-1]})
	}
	if len(v) == 1 {
		return string([]byte{v[0], v[0]})
	}
	return string([]byte{v[0], v[len(v)-1]})
}

func sigAlgs(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}
	n := int(binary.BigEndian.Uint16(data))
	data = data[2:]
	if n > len(data) {
		n = len(data)
	}
	var out []uint16
	for i := 0; i+1 < n; i += 2 {
		v := binary.BigEndian.Uint16(data[i:])
		if IsGREASE(v) {
			continue
		}
		out = append(out, v)
	}
	return out
}

func sortedHex(vs []uint16) string {
	cp := append([]uint16(nil), vs...)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	return joinHex(cp)
}

func joinHex(vs []uint16) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = leftPad(strings.ToLower(hex.EncodeToString([]byte{byte(v >> 8), byte(v)})), 4)
	}
	return strings.Join(parts, ",")
}

func hashList(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// ParseClientHello parses a handshake record containing a ClientHello.
// record is the TLS record bytes, or a raw handshake message.
func ParseClientHello(record []byte) (ClientHello, error) {
	b := record
	if len(b) > 5 && b[0] == 22 {
		if len(b) < 5 {
			return ClientHello{}, errShort
		}
		n := int(binary.BigEndian.Uint16(b[3:5]))
		b = b[5:]
		if n < len(b) {
			b = b[:n]
		}
	}
	if len(b) < 4 || b[0] != 1 {
		return ClientHello{}, errShort
	}
	n := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	b = b[4:]
	if n < len(b) {
		b = b[:n]
	}
	if len(b) < 35 {
		return ClientHello{}, errShort
	}
	ch := ClientHello{Version: binary.BigEndian.Uint16(b)}
	b = b[2:]
	ch.Random = append([]byte(nil), b[:32]...)
	b = b[32:]
	if len(b) < 1 {
		return ClientHello{}, errShort
	}
	sid := int(b[0])
	b = b[1:]
	if len(b) < sid {
		return ClientHello{}, errShort
	}
	ch.SessionID = append([]byte(nil), b[:sid]...)
	b = b[sid:]
	if len(b) < 2 {
		return ClientHello{}, errShort
	}
	cs := int(binary.BigEndian.Uint16(b))
	b = b[2:]
	if len(b) < cs {
		return ClientHello{}, errShort
	}
	for i := 0; i+1 < cs; i += 2 {
		ch.Ciphers = append(ch.Ciphers, binary.BigEndian.Uint16(b[i:]))
	}
	b = b[cs:]
	if len(b) < 1 {
		return ClientHello{}, errShort
	}
	comp := int(b[0])
	b = b[1:]
	if len(b) < comp {
		return ClientHello{}, errShort
	}
	ch.Compress = append([]byte(nil), b[:comp]...)
	b = b[comp:]
	if len(b) < 2 {
		return ch, nil
	}
	el := int(binary.BigEndian.Uint16(b))
	b = b[2:]
	if el < len(b) {
		b = b[:el]
	}
	for len(b) >= 4 {
		typ := binary.BigEndian.Uint16(b)
		ln := int(binary.BigEndian.Uint16(b[2:]))
		b = b[4:]
		if ln > len(b) {
			break
		}
		ch.Extensions = append(ch.Extensions, Extension{Type: typ, Data: append([]byte(nil), b[:ln]...)})
		b = b[ln:]
	}
	return ch, nil
}

var errShort = parseErr("short client hello")

type parseErr string

func (e parseErr) Error() string { return string(e) }
