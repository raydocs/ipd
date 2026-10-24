package leak

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestTokenFromNameRejectsForeignZone(t *testing.T) {
	for _, name := range []string{"issued.dns.other.invalid.", "issued.dns.example.test.evil.", "extra.issued.dns.example.test.", "dns.example.test."} {
		if got := tokenFromName(name, "example.test"); got != "" {
			t.Errorf("foreign/non-token name %q accepted as %q", name, got)
		}
	}
}

// These are local message fixtures, never public recursive queries.
type dnsWriter struct {
	msg  *dns.Msg
	addr net.Addr
}

func (w *dnsWriter) LocalAddr() net.Addr         { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353} }
func (w *dnsWriter) RemoteAddr() net.Addr        { return w.addr }
func (w *dnsWriter) WriteMsg(m *dns.Msg) error   { w.msg = m.Copy(); return nil }
func (w *dnsWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *dnsWriter) Close() error                { return nil }
func (w *dnsWriter) TsigStatus() error           { return nil }
func (w *dnsWriter) TsigTimersOnly(bool)         {}
func (w *dnsWriter) Hijack()                     {}

func query(s *DNSServer, name string, typ uint16, source string, ecs *dns.EDNS0_SUBNET) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, typ)
	if ecs != nil {
		m.SetEdns0(1232, false)
		m.IsEdns0().Option = append(m.IsEdns0().Option, ecs)
	}
	w := &dnsWriter{addr: &net.UDPAddr{IP: net.ParseIP(source), Port: 5050}}
	s.ServeDNS(w, m)
	return w.msg
}

func TestDNSSessionBoundsExpiryIsolation(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := NewDNSServer("Example.TEST.", SessionOptions{Enabled: true, TTL: time.Minute, MaxSessions: 2, MaxObservations: 1, Now: func() time.Time { return now }})
	first, err := s.Issue()
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.Issue()
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Token) != 32 || len(first.QueryNames) != 3 || first.Token == second.Token {
		t.Fatalf("bad issuance: %#v", first)
	}
	if raw, err := hex.DecodeString(first.Token); err != nil || len(raw) != 16 {
		t.Fatal("not a 128-bit token")
	}
	if _, err = s.Issue(); !errors.Is(err, ErrCapacity) {
		t.Fatalf("capacity: %v", err)
	}
	for _, tc := range []struct {
		name string
		code int
	}{
		{first.Token + ".dns.example.test.", dns.RcodeNameError},
		{"q3." + first.Token + ".dns.example.test.", dns.RcodeNameError},
		{"extra." + first.QueryNames[0], dns.RcodeNameError},
		{"q0.unknown.dns.example.test.", dns.RcodeNameError},
		{"dns.example.test.", dns.RcodeSuccess},
		{"q0." + first.Token + ".dns.other.test.", dns.RcodeRefused},
		{first.QueryNames[0] + "evil.", dns.RcodeRefused},
	} {
		if m := query(s, tc.name, dns.TypeA, "192.0.2.10", nil); m.Rcode != tc.code || len(m.Answer) != 0 {
			t.Errorf("%s: %#v", tc.name, m)
		}
	}
	r, _ := s.Result(first.Token)
	if len(r.Observations) != 0 {
		t.Fatal("invalid query recorded")
	}
	// Unsupported query types are NODATA and do not consume the name.
	if m := query(s, first.QueryNames[0], dns.TypeMX, "192.0.2.10", nil); m.Rcode != 0 || len(m.Answer) != 0 {
		t.Fatal(m)
	}
	ecs := &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 32, Address: net.ParseIP("198.51.100.123")}
	m := query(s, strings.ToUpper(first.QueryNames[0]), dns.TypeA, "192.0.2.10", ecs)
	if m.Rcode != 0 || !m.Authoritative || m.RecursionAvailable || len(m.Answer) != 1 || m.Answer[0].Header().Rrtype != dns.TypeA || m.Answer[0].Header().Ttl != 0 {
		t.Fatal(m)
	}
	// One-time name: a replay with a new source cannot add an observation.
	query(s, first.QueryNames[0], dns.TypeAAAA, "192.0.2.11", nil)
	for i, typ := range []uint16{dns.TypeAAAA, dns.TypeTXT} {
		m = query(s, first.QueryNames[i+1], typ, "192.0.2.12", nil)
		if len(m.Answer) != 1 || m.Answer[0].Header().Rrtype != typ {
			t.Fatal(m)
		}
	}
	r, err = s.Result(first.Token)
	if err != nil || len(r.Observations) != 1 || r.Observations[0].Resolver != "192.0.2.10" || r.Observations[0].ECS != "198.51.100.0/24" || !r.Observations[0].At.Equal(now) {
		t.Fatalf("result: %#v %v", r, err)
	}
	r.Observations[0].Resolver = "mutated"
	copyResult, _ := s.Result(first.Token)
	if copyResult.Observations[0].Resolver == "mutated" {
		t.Fatal("shared result memory")
	}
	isolated, _ := s.Result(second.Token)
	if len(isolated.Observations) != 0 {
		t.Fatal("cross-session observation")
	}
	now = first.ExpiresAt
	if _, err = s.Result(first.Token); !errors.Is(err, ErrNotFound) {
		t.Fatal("not expired", err)
	}
	if m = query(s, first.QueryNames[0], dns.TypeA, "192.0.2.10", nil); m.Rcode != dns.RcodeNameError {
		t.Fatal(m)
	}
	if len(s.sessions) != 0 {
		t.Fatal("expired records not cleaned")
	}
	if _, err = s.Issue(); err != nil {
		t.Fatal("capacity not reclaimed", err)
	}
}

func TestDNSSessionDedupAndECS(t *testing.T) {
	s := NewDNSServer("example.test", SessionOptions{Enabled: true})
	st, _ := s.Issue()
	query(s, st.QueryNames[0], dns.TypeA, "192.0.2.1", nil)
	query(s, st.QueryNames[1], dns.TypeAAAA, "192.0.2.1", nil)
	query(s, st.QueryNames[2], dns.TypeTXT, "192.0.2.2", nil)
	result, _ := s.Result(st.Token)
	if len(result.Observations) != 2 {
		t.Fatalf("dedup: %#v", result)
	}
	for _, tc := range []struct {
		family      uint16
		mask, scope uint8
		ip, want    string
	}{
		{1, 32, 0, "198.51.100.123", "198.51.100.0/24"},
		{1, 16, 0, "198.51.100.123", "198.51.0.0/16"},
		{2, 128, 0, "2001:db8:1234:5678::123", "2001:db8:1234:5600::/56"},
		{2, 32, 0, "2001:db8::1", "2001:db8::/32"},
		{1, 33, 0, "198.51.100.123", ""}, {2, 24, 0, "198.51.100.123", ""},
		{1, 24, 1, "198.51.100.123", ""},
	} {
		m := new(dns.Msg)
		m.SetEdns0(1232, false)
		m.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_SUBNET{Family: tc.family, SourceNetmask: tc.mask, SourceScope: tc.scope, Address: net.ParseIP(tc.ip)}}
		if got := maskedECS(m); got != tc.want {
			t.Errorf("ECS %s/%d = %s want %s", tc.ip, tc.mask, got, tc.want)
		}
	}
}

func TestDNSSessionDisabledAndConcurrent(t *testing.T) {
	for _, s := range []*DNSServer{NewDNSServer("example.test"), NewDNSServer("bad..test", SessionOptions{Enabled: true}), NewDNSServer(strings.Repeat("a", 60)+"."+strings.Repeat("b", 60)+"."+strings.Repeat("c", 60)+"."+strings.Repeat("d", 60), SessionOptions{Enabled: true})} {
		if _, err := s.Issue(); !errors.Is(err, ErrDisabled) {
			t.Fatal(err)
		}
		if _, err := s.Result("anything"); !errors.Is(err, ErrDisabled) {
			t.Fatal(err)
		}
		if m := query(s, "q0.token.dns.example.test.", dns.TypeA, "192.0.2.1", nil); m.Rcode != dns.RcodeRefused {
			t.Fatal(m)
		}
		if len(s.sessions) != 0 {
			t.Fatal("disabled collected")
		}
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := NewDNSServer("example.test", SessionOptions{Enabled: true, MaxSessions: 8, Now: func() time.Time { return now }})
	st, _ := s.Issue()
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			query(s, st.QueryNames[i%3], dns.TypeA, "192.0.2.1", nil)
			s.Result(st.Token)
			s.Issue()
		}(i)
	}
	wg.Wait()
	r, _ := s.Result(st.Token)
	if len(r.Observations) != 1 || len(s.sessions) != 8 {
		t.Fatalf("bounds: %d %d", len(r.Observations), len(s.sessions))
	}
}

func TestDNSServerListenerCleanup(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network+" bind failure", func(t *testing.T) {
			// Occupy one transport and prove the other isn't left listening on failure.
			var addr string
			var release func() error
			if network == "tcp" {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				addr = ln.Addr().String()
				release = ln.Close
			} else {
				pc, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				addr = pc.LocalAddr().String()
				release = pc.Close
			}
			defer release()
			s := NewDNSServer("example.test", SessionOptions{Enabled: true})
			if err := s.Serve(context.Background(), addr); err == nil {
				t.Fatal("bind failure hidden")
			}
			if network == "udp" {
				ln, err := net.Listen("tcp", addr)
				if err != nil {
					t.Fatal("TCP leaked", err)
				}
				ln.Close()
			} else {
				pc, err := net.ListenPacket("udp", addr)
				if err != nil {
					t.Fatal("UDP leaked", err)
				}
				pc.Close()
			}
		})
	}
	for _, mode := range []string{"cancel", "udp failure", "tcp failure", "already canceled"} {
		t.Run(mode, func(t *testing.T) {
			tcp, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			udp, err := net.ListenPacket("udp", tcp.Addr().String())
			if err != nil {
				tcp.Close()
				t.Fatal(err)
			}
			addr := tcp.Addr().String()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "already canceled" {
				cancel()
			}
			done := make(chan error, 1)
			s := NewDNSServer("example.test", SessionOptions{Enabled: true})
			go func() { done <- s.ServeListeners(ctx, udp, tcp) }()
			if mode != "already canceled" {
				st, _ := s.Issue()
				m := new(dns.Msg)
				m.SetQuestion(st.QueryNames[0], dns.TypeA)
				if _, _, err := (&dns.Client{Net: "udp", Timeout: time.Second}).Exchange(m, addr); err != nil {
					t.Fatal(err)
				}
				switch mode {
				case "cancel":
					cancel()
				case "udp failure":
					udp.Close()
				case "tcp failure":
					tcp.Close()
				}
			}
			select {
			case err := <-done:
				if (mode == "cancel" || mode == "already canceled") && err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("listener shutdown hung")
			}
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				t.Fatal("TCP leaked", err)
			}
			ln.Close()
			pc, err := net.ListenPacket("udp", addr)
			if err != nil {
				t.Fatal("UDP leaked", err)
			}
			pc.Close()
		})
	}
}

func TestDNSSessionProtocolValidation(t *testing.T) {
	s := NewDNSServer("example.test", SessionOptions{Enabled: true})
	st, _ := s.Issue()
	for _, mode := range []string{"empty", "multiple", "class", "opcode"} {
		m := new(dns.Msg)
		m.SetQuestion(st.QueryNames[0], dns.TypeA)
		want := dns.RcodeFormatError
		switch mode {
		case "empty":
			m.Question = nil
		case "multiple":
			m.Question = append(m.Question, m.Question[0])
		case "class":
			m.Question[0].Qclass = dns.ClassCHAOS
			want = dns.RcodeRefused
		case "opcode":
			m.Opcode = dns.OpcodeUpdate
			want = dns.RcodeNotImplemented
		}
		w := &dnsWriter{addr: &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 5050}}
		s.ServeDNS(w, m)
		if w.msg.Rcode != want {
			t.Errorf("%s: %s", mode, w.msg)
		}
	}
	r, _ := s.Result(st.Token)
	if len(r.Observations) != 0 {
		t.Fatal("invalid protocol recorded")
	}
}

func TestDNSSessionOptionCeilings(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, options := range []SessionOptions{{Enabled: true}, {Enabled: true, TTL: time.Hour, MaxSessions: 10000, MaxObservations: 10000}} {
		options.Now = func() time.Time { return now }
		s := NewDNSServer("example.test", options)
		for i := 0; i < 256; i++ {
			st, err := s.Issue()
			if err != nil {
				t.Fatal(i, err)
			}
			if !st.ExpiresAt.Equal(now.Add(2 * time.Minute)) {
				t.Fatal("unbounded TTL")
			}
		}
		if _, err := s.Issue(); !errors.Is(err, ErrCapacity) {
			t.Fatal("unbounded session count", err)
		}
		if s.options.MaxObservations != 3 {
			t.Fatal("unbounded observation count")
		}
	}
}
