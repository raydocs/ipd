package listen

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"sync"
	"time"

	"ipd/internal/leak"
)

// Seen is one completed (or partially completed) TLS observation.
type Seen struct {
	IP     string
	JA3    string
	JA3Raw string
	JA4    string
	H2     string
	MSS    int
	TTL    int
}

// ServeTLS accepts connections, finishes the handshake with a process-local
// certificate, and records JA3, JA4, and the HTTP/2 Akamai fingerprint.
// TCP SYN/MSS comes from a packet socket when the process may open one, and
// from TCP_INFO otherwise. A missing privilege is not a fatal error.
func ServeTLS(ctx context.Context, addr string, save func(Seen)) error {
	if addr == "" {
		return nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	cfg := SelfSigned()
	return serveTLSListener(ctx, ln, cfg, save)
}

func serveTLSListener(ctx context.Context, ln net.Listener, cfg *tls.Config, save func(Seen)) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	var syn synTable
	if tcp, ok := ln.Addr().(*net.TCPAddr); ok && tcp.Port != 0 {
		if err := startSYNCapture(ctx, tcp.Port, &syn); err != nil {
			// Packet capture needs CAP_NET_RAW. TCP_INFO still supplies MSS.
			_ = err
		}
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go handleTLS(c, cfg, &syn, save)
	}
}

func handleTLS(c net.Conn, cfg *tls.Config, syn *synTable, save func(Seen)) {
	defer c.Close()
	host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	raw, err := readHelloRecord(c)
	seen := Seen{IP: host}
	if err == nil {
		if ch, perr := leak.ParseClientHello(raw); perr == nil {
			seen.JA3Raw, seen.JA3 = leak.JA3(ch)
			seen.JA4 = leak.JA4(ch, 't')
		}
	}
	if mss, ttl := syn.get(host); mss > 0 || ttl > 0 {
		seen.MSS, seen.TTL = mss, ttl
	}
	if seen.MSS == 0 {
		if mss := peerMSS(c); mss > 0 {
			seen.MSS = mss
		}
	}
	srv := tls.Server(&replayConn{Conn: c, buf: raw}, cfg)
	if err := srv.Handshake(); err != nil {
		if save != nil && (seen.JA3 != "" || seen.JA4 != "") {
			save(seen)
		}
		return
	}
	if srv.ConnectionState().NegotiatedProtocol == "h2" {
		acc := readFor(srv, 1200*time.Millisecond, 8192)
		if len(acc) > 0 {
			seen.H2 = leak.ParseH2(acc).String()
		}
	}
	if save != nil {
		save(seen)
	}
}

func readHelloRecord(c net.Conn) ([]byte, error) {
	var buf []byte
	hdr := make([]byte, 5)
	for len(buf) < 16*1024 {
		if _, err := io.ReadFull(c, hdr); err != nil {
			if len(buf) > 0 {
				return buf, nil
			}
			return nil, err
		}
		if hdr[0] != 22 {
			return append(buf, hdr...), io.ErrUnexpectedEOF
		}
		n := int(hdr[3])<<8 | int(hdr[4])
		if n <= 0 || n > 16384 {
			return nil, io.ErrUnexpectedEOF
		}
		rec := make([]byte, 5+n)
		copy(rec, hdr)
		if _, err := io.ReadFull(c, rec[5:]); err != nil {
			return nil, err
		}
		buf = append(buf, rec...)
		if handshakeComplete(buf) {
			return buf, nil
		}
	}
	return buf, nil
}

func handshakeComplete(buf []byte) bool {
	if len(buf) < 9 || buf[0] != 22 || buf[5] != 1 {
		return false
	}
	n := int(buf[6])<<16 | int(buf[7])<<8 | int(buf[8])
	return len(buf) >= 9+n
}

func readFor(c net.Conn, d time.Duration, max int) []byte {
	deadline := time.Now().Add(d)
	var acc []byte
	buf := make([]byte, 2048)
	for len(acc) < max && time.Now().Before(deadline) {
		_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, err := c.Read(buf)
		if n > 0 {
			acc = append(acc, buf[:n]...)
		}
		if err != nil {
			break
		}
	}
	return acc
}

type replayConn struct {
	net.Conn
	buf []byte
}

func (c *replayConn) Read(p []byte) (int, error) {
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

var (
	certOnce sync.Once
	certVal  tls.Certificate
	certErr  error
)

func localCert() (tls.Certificate, error) {
	certOnce.Do(func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			certErr = err
			return
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "ipd"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
			DNSNames:     []string{"localhost"},
			IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			certErr = err
			return
		}
		certVal = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	})
	return certVal, certErr
}

// SelfSigned returns a process-local certificate config. The listener uses it
// to finish the handshake so HTTP/2 frames can be read.
func SelfSigned() *tls.Config {
	cert, err := localCert()
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}}
	if err == nil {
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg
}
