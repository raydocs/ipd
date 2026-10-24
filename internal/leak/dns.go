// Package leak covers DNS, STUN, and TLS/TCP fingerprint endpoints.
package leak

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var (
	ErrDisabled = errors.New("DNS sessions disabled")
	ErrCapacity = errors.New("DNS session capacity reached")
	ErrNotFound = errors.New("DNS session not found or expired")
)

const queryCount = 3

// SessionOptions bounds this in-memory recorder. Nonpositive limits use defaults;
// larger values are clamped. Now must be safe for concurrent calls.
type SessionOptions struct {
	Enabled         bool
	TTL             time.Duration
	MaxSessions     int
	MaxObservations int
	Now             func() time.Time
}

// DNSServer is a bounded, opt-in authoritative observation recorder. Neither
// recursive resolution nor browser-path/leak classification happens here.
type DNSServer struct {
	zone     string
	options  SessionOptions
	mu       sync.Mutex
	sessions map[string]*sessionState
}

type sessionState struct {
	expires      time.Time
	used         [queryCount]bool
	observations []Observation
}

// Observation retains only recursive source, masked ECS prefix and first time.
// It never retains the raw question, HTTP client address or headers.
type Observation struct {
	Resolver string    `json:"resolver"`
	ECS      string    `json:"ecs,omitempty"`
	At       time.Time `json:"at"`
}

// Session is issued only to its bearer. Query names are derived, not stored.
type Session struct {
	Token      string    `json:"token"`
	QueryNames []string  `json:"query_names"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type SessionResult struct {
	ExpiresAt    time.Time     `json:"expires_at"`
	Observations []Observation `json:"observations"`
}

// NewDNSServer defaults to disabled. Options and zone are immutable after construction.
func NewDNSServer(domain string, options ...SessionOptions) *DNSServer {
	o := SessionOptions{}
	if len(options) > 0 {
		o = options[0]
	}
	if o.TTL <= 0 || o.TTL > 2*time.Minute {
		o.TTL = 2 * time.Minute
	}
	if o.MaxSessions <= 0 || o.MaxSessions > 256 {
		o.MaxSessions = 256
	}
	if o.MaxObservations <= 0 || o.MaxObservations > queryCount {
		o.MaxObservations = queryCount
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	zone := "dns." + domain + "."
	if _, ok := dns.IsDomainName("q0." + strings.Repeat("0", 32) + "." + zone); !ok || domain == "" || strings.ContainsAny(domain, "\\ \t\r\n") {
		o.Enabled = false
	}
	return &DNSServer{zone: zone, options: o, sessions: make(map[string]*sessionState)}
}

// cleanupLocked runs on every issuance, read and query. An idle listener also
// sweeps each second; idle standalone recorders remain bounded by MaxSessions.
func (s *DNSServer) cleanupLocked(now time.Time) {
	for token, session := range s.sessions {
		if !now.Before(session.expires) {
			delete(s.sessions, token)
		}
	}
}

func (s *DNSServer) Issue() (Session, error) {
	if !s.options.Enabled {
		return Session{}, ErrDisabled
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.options.Now().UTC()
	s.cleanupLocked(now)
	if len(s.sessions) >= s.options.MaxSessions {
		return Session{}, ErrCapacity
	}
	var token string
	for {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			return Session{}, err
		}
		token = hex.EncodeToString(b[:])
		if _, exists := s.sessions[token]; !exists {
			break
		}
	}
	expires := now.Add(s.options.TTL)
	s.sessions[token] = &sessionState{expires: expires, observations: []Observation{}}
	names := make([]string, queryCount)
	for i := range names {
		names[i] = "q" + strconv.Itoa(i) + "." + token + "." + s.zone
	}
	return Session{Token: token, QueryNames: names, ExpiresAt: expires}, nil
}

func (s *DNSServer) Result(token string) (SessionResult, error) {
	if !s.options.Enabled {
		return SessionResult{}, ErrDisabled
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(s.options.Now())
	st, ok := s.sessions[token]
	if !ok {
		return SessionResult{}, ErrNotFound
	}
	out := append([]Observation{}, st.observations...)
	return SessionResult{ExpiresAt: st.expires, Observations: out}, nil
}

// Serve binds both transports before starting either, and closes both on any
// failure or cancellation. Port zero selects one shared ephemeral UDP/TCP port.
func (s *DNSServer) Serve(ctx context.Context, addr string) error {
	if addr == "" {
		return nil
	}
	if ctx.Err() != nil {
		return nil
	}
	tcp, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp", tcp.Addr().String())
	if err != nil {
		return err
	}
	defer udp.Close()
	return s.ServeListeners(ctx, udp, tcp)
}

// ServeListeners owns and closes both supplied listeners, including on startup
// failure. This also permits deterministic local integration without port races.
func (s *DNSServer) ServeListeners(ctx context.Context, udp net.PacketConn, tcp net.Listener) error {
	defer udp.Close()
	defer tcp.Close()
	if ctx.Err() != nil {
		return nil
	}
	uReady, tReady := make(chan struct{}), make(chan struct{})
	var uOnce, tOnce sync.Once
	uStarted := func() { uOnce.Do(func() { close(uReady) }) }
	tStarted := func() { tOnce.Do(func() { close(tReady) }) }
	u := &dns.Server{PacketConn: udp, Net: "udp", Handler: s, NotifyStartedFunc: uStarted}
	t := &dns.Server{Listener: tcp, Net: "tcp", Handler: s, NotifyStartedFunc: tStarted}
	done := make(chan error, 2)
	go func() { err := u.ActivateAndServe(); uStarted(); done <- err }()
	go func() { err := t.ActivateAndServe(); tStarted(); done <- err }()
	// Each gate closes on startup OR failure, never twice for one server.
	<-uReady
	<-tReady
	finished := 0
	var result error
	select {
	case result = <-done:
		finished++
	default:
	}

	if finished == 0 {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
	loop:
		for {
			select {
			case <-ctx.Done():
				break loop
			case err := <-done:
				finished++
				result = err
				break loop
			case <-ticker.C:
				s.mu.Lock()
				s.cleanupLocked(s.options.Now())
				s.mu.Unlock()
			}
		}
	}
	_ = u.Shutdown()
	_ = t.Shutdown()
	for finished < 2 {
		<-done
		finished++
	}
	return result
}

// tokenFromName accepts exactly one token label in the configured zone.
func tokenFromName(qname, domain string) string {
	name := strings.ToLower(dns.Fqdn(qname))
	suffix := ".dns." + strings.ToLower(strings.TrimSuffix(domain, ".")) + "."
	if !strings.HasSuffix(name, suffix) {
		return ""
	}
	token := strings.TrimSuffix(name, suffix)
	if token == "" || strings.Contains(token, ".") {
		return ""
	}
	return token
}

func (s *DNSServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.RecursionAvailable = false
	if r.Opcode != dns.OpcodeQuery {
		m.Rcode = dns.RcodeNotImplemented
		_ = w.WriteMsg(m)
		return
	}
	if len(r.Question) != 1 {
		m.Rcode = dns.RcodeFormatError
		_ = w.WriteMsg(m)
		return
	}
	q := r.Question[0]
	name := strings.ToLower(dns.Fqdn(q.Name))
	if !s.options.Enabled || (name != s.zone && !strings.HasSuffix(name, "."+s.zone)) || q.Qclass != dns.ClassINET {
		m.Rcode = dns.RcodeRefused
		_ = w.WriteMsg(m)
		return
	}
	m.Authoritative = true
	// The configured zone apex exists, but is not an issued observation name.
	if name == s.zone {
		_ = w.WriteMsg(m)
		return
	}
	labels := strings.SplitN(name, ".", 2)
	index := -1
	for i := 0; i < queryCount; i++ {
		if labels[0] == "q"+strconv.Itoa(i) {
			index = i
		}
	}
	token := ""
	if len(labels) == 2 {
		token = tokenFromName(labels[1], strings.TrimSuffix(strings.TrimPrefix(s.zone, "dns."), "."))
	}
	s.mu.Lock()
	now := s.options.Now().UTC()
	s.cleanupLocked(now)
	st, found := s.sessions[token]
	if !found || index < 0 {
		s.mu.Unlock()
		m.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(m)
		return
	}
	supported := q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA || q.Qtype == dns.TypeTXT
	if supported && !st.used[index] {
		st.used[index] = true
		host, _, err := net.SplitHostPort(w.RemoteAddr().String())
		ip, parseErr := netip.ParseAddr(host)
		if err == nil && parseErr == nil {
			obs := Observation{Resolver: ip.Unmap().String(), ECS: maskedECS(r), At: now}
			duplicate := false
			for _, old := range st.observations {
				if old.Resolver == obs.Resolver && old.ECS == obs.ECS {
					duplicate = true
					break
				}
			}
			if !duplicate && len(st.observations) < s.options.MaxObservations {
				st.observations = append(st.observations, obs)
			}
		}
	}
	s.mu.Unlock()
	h := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET, Ttl: 0}
	switch q.Qtype {
	case dns.TypeA:
		m.Answer = []dns.RR{&dns.A{Hdr: h, A: net.IPv4(192, 0, 2, 1)}}
	case dns.TypeAAAA:
		m.Answer = []dns.RR{&dns.AAAA{Hdr: h, AAAA: net.ParseIP("2001:db8::1")}}
	case dns.TypeTXT:
		m.Answer = []dns.RR{&dns.TXT{Hdr: h, Txt: []string{"ipd"}}}
	}
	_ = w.WriteMsg(m)
}

func maskedECS(r *dns.Msg) string {
	opt := r.IsEdns0()
	if opt == nil {
		return ""
	}
	for _, o := range opt.Option {
		e, ok := o.(*dns.EDNS0_SUBNET)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(e.Address)
		if !ok {
			return ""
		}
		ip = ip.Unmap()
		bits, cap := int(e.SourceNetmask), 56
		if e.Family == 1 && ip.Is4() {
			cap = 24
		} else if e.Family != 2 || !ip.Is6() {
			return ""
		}
		if bits > ip.BitLen() || e.SourceScope != 0 {
			return ""
		}
		if bits > cap {
			bits = cap
		}
		return netip.PrefixFrom(ip, bits).Masked().String()
	}
	return ""
}

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
