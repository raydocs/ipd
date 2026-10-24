package route

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
)

func TestUDPExtendedErrorCompletion(t *testing.T) {
	dst := netip.MustParseAddr("192.0.2.1")
	for _, tc := range []struct {
		name, source      string
		origin, typ, code byte
		done, wantErr     bool
	}{
		{"router network unreachable", "203.0.113.1", 2, 3, 0, false, true},
		{"router host unreachable", "203.0.113.1", 2, 3, 1, false, true},
		{"router port unreachable", "203.0.113.1", 2, 3, 3, false, true},
		{"target host unreachable", "192.0.2.1", 2, 3, 1, false, true},
		{"target port unreachable", "192.0.2.1", 2, 3, 3, true, false},
		{"router TTL expired", "203.0.113.1", 2, 11, 0, false, false},
		{"local error is not destination", "192.0.2.1", 1, 3, 3, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Linux sock_extended_err followed by sockaddr_in, not a real socket.
			data := make([]byte, 32)
			binary.NativeEndian.PutUint32(data, 111)
			data[4], data[5], data[6] = tc.origin, tc.typ, tc.code
			binary.NativeEndian.PutUint16(data[16:18], 2)
			ip := netip.MustParseAddr(tc.source).As4()
			copy(data[20:24], ip[:])
			hop, done, err := parseUDPExtendedError(data, dst)
			if hop.IP != tc.source || done != tc.done || (err != nil) != tc.wantErr {
				t.Fatalf("hop %+v done %v err %v", hop, done, err)
			}
			if err != nil && tc.origin == 2 && !strings.Contains(err.Error(), tc.source) {
				t.Fatalf("lost error source %v", err)
			}
		})
	}
	for _, data := range [][]byte{nil, make([]byte, 16), make([]byte, 23)} {
		if _, done, err := parseUDPExtendedError(data, dst); done || err == nil {
			t.Fatal("malformed payload accepted")
		}
	}
}
