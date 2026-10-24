// Package listen runs the auxiliary sockets: authoritative DNS for leak
// tokens, a STUN binding server, and a TLS ClientHello peeker.
// Addresses come from configuration. Nothing here binds a public interface
// unless the operator sets one.
package listen

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/pion/stun"
	"ipd/internal/leak"
)

// DNS records the source address of queries under a token label.
type DNS struct {
	Addr string
	// OnQuery receives the question name and the client IP.
	OnQuery func(name, client string)
}

// ServeDNS answers A queries with the socket's observed client address so a
// resolver test can see who asked. It does not recurse.
func (d DNS) Serve(ctx context.Context) error {
	if d.Addr == "" {
		return nil
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		client := ""
		if addr, ok := w.RemoteAddr().(*net.UDPAddr); ok {
			client = addr.IP.String()
		}
		if len(r.Question) > 0 && d.OnQuery != nil {
			d.OnQuery(r.Question[0].Name, client)
		}
		if ip := net.ParseIP(client); ip != nil && ip.To4() != nil && len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
				A:   ip.To4(),
			})
		}
		_ = w.WriteMsg(m)
	})
	srv := &dns.Server{Addr: d.Addr, Net: "udp", Handler: mux}
	go func() {
		<-ctx.Done()
		_ = srv.Shutdown()
	}()
	return srv.ListenAndServe()
}

// ServeSTUN answers binding requests with the XOR-mapped address.
func ServeSTUN(ctx context.Context, addr string) error {
	if addr == "" {
		return nil
	}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = pc.Close()
	}()
	buf := make([]byte, 1500)
	for {
		_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}
		req := new(stun.Message)
		req.Raw = append([]byte(nil), buf[:n]...)
		if err := req.Decode(); err != nil || req.Type != stun.BindingRequest {
			continue
		}
		udp, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		res, err := stun.Build(req, stun.BindingSuccess, &stun.XORMappedAddress{IP: udp.IP, Port: udp.Port}, stun.Fingerprint)
		if err != nil {
			continue
		}
		_, _ = pc.WriteTo(res.Raw, from)
	}
}

// Hello is a parsed ClientHello plus the peer address.
type Hello struct {
	IP string
	CH leak.ClientHello
}

// ServeTLSPeek reads one TLS record and closes. It does not complete a handshake,
// so it can see JA3 and JA4 without storing a certificate's session.
func ServeTLSPeek(ctx context.Context, addr string, save func(Hello)) error {
	if addr == "" {
		return nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func(c net.Conn) {
			defer c.Close()
			_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
			buf := make([]byte, 4096)
			n, err := io.ReadFull(c, buf[:5])
			if err != nil && n < 5 {
				return
			}
			// Read the rest of the record when the header says so.
			if buf[0] == 22 && n >= 5 {
				want := int(buf[3])<<8 | int(buf[4])
				if want > len(buf)-5 {
					want = len(buf) - 5
				}
				_, _ = io.ReadFull(c, buf[5:5+want])
				n = 5 + want
			}
			ch, err := leak.ParseClientHello(buf[:n])
			if err != nil {
				return
			}
			host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			if save != nil {
				save(Hello{IP: host, CH: ch})
			}
		}(c)
	}
}
