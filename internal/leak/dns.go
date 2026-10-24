// Package leak covers DNS, STUN, and TLS/TCP fingerprint endpoints.
package leak

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// DNSServer is an authoritative server for dns.<domain>. It records the
// resolver address and EDNS client subnet for a token, never a WebRTC IP.
type DNSServer struct {
	Domain string
	mu     sync.Mutex
	seen   map[string][]Observation
}

// Observation is one recursive lookup of a token.
type Observation struct {
	Token    string
	Resolver string
	ECS      string
	QName    string
	At       time.Time
}

// NewDNSServer returns an empty recorder.
func NewDNSServer(domain string) *DNSServer {
	return &DNSServer{Domain: domain, seen: map[string][]Observation{}}
}

// Serve listens until ctx is cancelled.
func (s *DNSServer) Serve(ctx context.Context, addr string) error {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handle)
	udp := &dns.Server{Addr: addr, Net: "udp", Handler: mux}
	tcp := &dns.Server{Addr: addr, Net: "tcp", Handler: mux}
	errc := make(chan error, 2)
	go func() { errc <- udp.ListenAndServe() }()
	go func() { errc <- tcp.ListenAndServe() }()
	select {
	case <-ctx.Done():
		_ = udp.Shutdown()
		_ = tcp.Shutdown()
		return nil
	case err := <-errc:
		return err
	}
}

func (s *DNSServer) handle(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true
	if len(r.Question) == 0 {
		_ = w.WriteMsg(msg)
		return
	}
	q := r.Question[0]
	token := tokenFromName(q.Name, s.Domain)
	ecs := ""
	if opt := r.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if e, ok := o.(*dns.EDNS0_SUBNET); ok {
				ecs = e.Address.String()
			}
		}
	}
	if token != "" {
		host, _, _ := net.SplitHostPort(w.RemoteAddr().String())
		s.mu.Lock()
		s.seen[token] = append(s.seen[token], Observation{
			Token: token, Resolver: host, ECS: ecs, QName: q.Name, At: time.Now().UTC(),
		})
		s.mu.Unlock()
	}
	rr, _ := dns.NewRR(q.Name + " 60 IN TXT \"ipd\"")
	if rr != nil {
		msg.Answer = append(msg.Answer, rr)
	}
	_ = w.WriteMsg(msg)
}

func tokenFromName(qname, domain string) string {
	qname = strings.TrimSuffix(strings.ToLower(qname), ".")
	suffix := ".dns." + strings.ToLower(domain)
	if !strings.HasSuffix(qname, suffix) && qname != "dns."+strings.ToLower(domain) {
		// also accept the domain itself as the zone apex
		if !strings.Contains(qname, ".dns.") {
			return ""
		}
	}
	labels := strings.Split(qname, ".")
	if len(labels) >= 1 {
		return labels[0]
	}
	return ""
}

// Observations returns what the server saw for a token.
func (s *DNSServer) Observations(token string) []Observation {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]Observation(nil), s.seen[token]...)
	if out == nil {
		out = []Observation{}
	}
	return out
}

// NewToken is a URL-safe id.
func NewToken() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// ParseECS is used by tests that feed a raw EDNS subnet string.
func ParseECS(addr string) string { return addr }

// LeakReport is the dns_leak_test payload. Resolver IPs are the recursive
// resolvers, which the user asked us to identify. They are not WebRTC candidates.
type LeakReport struct {
	Resolvers []Resolver `json:"resolvers"`
	Leak      bool       `json:"leak"`
	Mode      string     `json:"mode"`
}

// Resolver is one recursive resolver observed or compared.
type Resolver struct {
	IP  string `json:"ip"`
	ASN int    `json:"asn,omitempty"`
	CC  string `json:"cc,omitempty"`
	ECS string `json:"ecs,omitempty"`
}

// Compare decides whether system resolvers disagree with the egress country
// or with a DoH reference.
func Compare(egressCC string, resolvers []Resolver, dohCC string) LeakReport {
	leak := false
	for _, r := range resolvers {
		if r.CC != "" && egressCC != "" && r.CC != egressCC {
			leak = true
		}
	}
	if dohCC != "" && egressCC != "" && dohCC != egressCC {
		leak = true
	}
	return LeakReport{Resolvers: resolvers, Leak: leak, Mode: "comparative"}
}
