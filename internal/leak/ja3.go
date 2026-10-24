package leak

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// ClientHello is the subset of a TLS ClientHello we fingerprint.
type ClientHello struct {
	RecordVersion uint16
	Version       uint16
	Random        []byte
	SessionID     []byte
	Ciphers       []uint16
	Compress      []uint8
	Extensions    []Extension
}

// Extension is one TLS extension.
type Extension struct {
	Type uint16
	Data []byte
}

// IsGREASE reports TLS GREASE values (0x?A?A).
func IsGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && byte(v>>8) == byte(v)
}

// JA3 returns the ja3 string and its MD5.
func JA3(ch ClientHello) (raw, sum string) {
	var ciphers, exts, curves, points []string
	for _, c := range ch.Ciphers {
		if IsGREASE(c) {
			continue
		}
		ciphers = append(ciphers, strconv.Itoa(int(c)))
	}
	for _, e := range ch.Extensions {
		if IsGREASE(e.Type) {
			continue
		}
		exts = append(exts, strconv.Itoa(int(e.Type)))
		if e.Type == 10 { // supported_groups
			curves = append(curves, groups(e.Data)...)
		}
		if e.Type == 11 { // ec_point_formats
			points = append(points, pointsOf(e.Data)...)
		}
	}
	ver := ch.Version
	if v := supportedVersion(ch); v != 0 {
		ver = v
	}
	raw = fmt.Sprintf("%d,%s,%s,%s,%s", ver, strings.Join(ciphers, "-"), strings.Join(exts, "-"), strings.Join(curves, "-"), strings.Join(points, "-"))
	h := md5.Sum([]byte(raw))
	return raw, hex.EncodeToString(h[:])
}

func supportedVersion(ch ClientHello) uint16 {
	for _, e := range ch.Extensions {
		if e.Type != 43 || len(e.Data) < 3 {
			continue
		}
		n := int(e.Data[0])
		data := e.Data[1:]
		if n > len(data) {
			n = len(data)
		}
		var best uint16
		for i := 0; i+1 < n; i += 2 {
			v := binary.BigEndian.Uint16(data[i:])
			if IsGREASE(v) {
				continue
			}
			if v > best {
				best = v
			}
		}
		return best
	}
	return 0
}

func groups(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	n := int(binary.BigEndian.Uint16(data))
	data = data[2:]
	if n > len(data) {
		n = len(data)
	}
	var out []string
	for i := 0; i+1 < n; i += 2 {
		v := binary.BigEndian.Uint16(data[i:])
		if IsGREASE(v) {
			continue
		}
		out = append(out, strconv.Itoa(int(v)))
	}
	return out
}

func pointsOf(data []byte) []string {
	if len(data) < 1 {
		return nil
	}
	n := int(data[0])
	data = data[1:]
	if n > len(data) {
		n = len(data)
	}
	var out []string
	for i := 0; i < n; i++ {
		out = append(out, strconv.Itoa(int(data[i])))
	}
	return out
}
