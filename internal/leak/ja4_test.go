package leak

import (
	"encoding/binary"
	"testing"
)

func TestJA4ReferenceVector(t *testing.T) {
	ciphers := []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035}
	extOrder := []uint16{0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015}
	sigs := []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601}
	var exts []Extension
	for _, typ := range extOrder {
		data := []byte{0x00}
		switch typ {
		case 0x0000:
			data = []byte{0x00, 0x0d, 0x00, 0x00, 0x0a, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'}
		case 0x0010:
			data = []byte{0x00, 0x03, 0x02, 'h', '2'}
		case 0x000d:
			data = make([]byte, 2+len(sigs)*2)
			binary.BigEndian.PutUint16(data, uint16(len(sigs)*2))
			for i, s := range sigs {
				binary.BigEndian.PutUint16(data[2+i*2:], s)
			}
		case 0x002b:
			data = []byte{0x02, 0x03, 0x04}
		}
		exts = append(exts, Extension{Type: typ, Data: data})
	}
	ch := ClientHello{Version: 0x0303, Ciphers: ciphers, Extensions: exts}
	got := JA4(ch, 't')
	want := "t13d1516h2_8daaf6152771_e5627efa2ab1"
	if got != want {
		t.Fatalf("got %s", got)
	}
	if IsGREASE(0x0a0a) != true || IsGREASE(0x1301) {
		t.Fatal("grease")
	}
}

func TestJA3Stable(t *testing.T) {
	ch := ClientHello{Version: 0x0303, Ciphers: []uint16{0x1301, 0x002f}, Extensions: []Extension{{Type: 0}}}
	raw, sum := JA3(ch)
	if raw == "" || len(sum) != 32 {
		t.Fatalf("%s %s", raw, sum)
	}
}
