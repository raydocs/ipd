package listen

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"
)

func TestServeTLSHandshakeAndH2(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	seen := make(chan Seen, 1)
	go func() {
		_ = serveTLSListener(ctx, ln, SelfSigned(), func(s Seen) { seen <- s })
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}, ServerName: "localhost"})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	payload := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	payload = append(payload, frame(0x4, 0, 0, []byte{0, 1, 0, 0, 0x10, 0})...)
	payload = append(payload, frame(0x8, 0, 0, []byte{0, 0, 0, 100})...)
	if _, err := tlsConn.Write(payload); err != nil {
		t.Fatal(err)
	}
	select {
	case s := <-seen:
		if s.JA3 == "" || s.JA4 == "" {
			t.Fatalf("fingerprint %+v", s)
		}
		if !strings.Contains(s.H2, "1:4096") || !strings.Contains(s.H2, "|100|") {
			t.Fatalf("h2 %q", s.H2)
		}
		if s.MSS <= 0 {
			t.Fatalf("mss %d (tcp_info should work without raw sockets)", s.MSS)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("timed out waiting for fingerprint")
	}
}

func frame(typ, flags byte, stream uint32, body []byte) []byte {
	hdr := []byte{byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body)), typ, flags, byte(stream >> 24), byte(stream >> 16), byte(stream >> 8), byte(stream)}
	return append(hdr, body...)
}
