package leak

import (
	"encoding/binary"
	"testing"
)

func TestParseH2Akamai(t *testing.T) {
	var b []byte
	b = append(b, []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")...)
	b = appendFrame(b, 0x4, 0, 0, settingsPair(1, 4096))
	b = appendFrame(b, 0x8, 0, 0, uint32be(100))
	// PRIORITY stream 3, exclusive 0, dep 0, weight 200
	prio := []byte{0, 0, 0, 0, 200}
	b = appendFrame(b, 0x2, 0, 3, prio)
	// HEADERS: indexed :method GET (2), :scheme https (7), :path / (4)
	b = appendFrame(b, 0x1, 0x4, 1, []byte{0x82, 0x87, 0x84})
	fp := ParseH2(b)
	if fp.String() != "1:4096|100|3:0:0:200|m,s,p" {
		t.Fatal(fp.String())
	}
}

func appendFrame(dst []byte, typ, flags byte, stream uint32, body []byte) []byte {
	hdr := make([]byte, 9)
	hdr[0] = byte(len(body) >> 16)
	hdr[1] = byte(len(body) >> 8)
	hdr[2] = byte(len(body))
	hdr[3] = typ
	hdr[4] = flags
	binary.BigEndian.PutUint32(hdr[5:], stream)
	return append(append(dst, hdr...), body...)
}

func settingsPair(id uint16, val uint32) []byte {
	b := make([]byte, 6)
	binary.BigEndian.PutUint16(b, id)
	binary.BigEndian.PutUint32(b[2:], val)
	return b
}

func uint32be(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}
