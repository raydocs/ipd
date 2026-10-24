package app

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
	"ipd/data"
	"ipd/internal/config"
	"ipd/internal/dnsbl"
	"ipd/internal/gfw"
	"ipd/internal/ingest"
	"ipd/internal/lookup"
	"ipd/internal/nodes"
	"ipd/internal/privacy"
	"ipd/internal/probe"
	"ipd/internal/providers"
	"ipd/internal/route"
	"ipd/internal/score"
	"ipd/internal/store"
	"ipd/internal/unlock"
)

// Service is safe for concurrent use.
type Service struct {
	Cfg         *config.Config
	Look        *lookup.Engine
	DB          *store.Store
	Enrich      *providers.Fanout
	Vantage     probe.Provider
	Checks      *unlock.Engine
	Now         func() time.Time
	Egress      func(ctx context.Context) (v4, v6 string)
	Tracer      func(ctx context.Context, target string) ([]route.Hop, error)
	Dial        func(ctx context.Context, network, addr string) (net.Conn, error)
	DNS         ResolverSource
	nodeChecker nodes.Checker
	mu          sync.Mutex
	fp          map[string]Fingerprint
}

// ResolverSource is the DNS leak comparative input.
type ResolverSource interface {
	Resolvers(ctx context.Context) []dnsblLike
}

type dnsblLike = struct {
	IP, CC, ECS string
	ASN         int
}

// Fingerprint is the last ClientHello seen from an address.
type Fingerprint struct {
	IP     string    `json:"ip"`
	JA3    string    `json:"ja3"`
	JA3Raw string    `json:"ja3_raw"`
	JA4    string    `json:"ja4"`
	MSS    int       `json:"mss"`
	TTL    int       `json:"ttl"`
	H2     string    `json:"h2,omitempty"`
	At     time.Time `json:"at"`
}

// New wires the default offline-capable service.
func New(cfg *config.Config, db *store.Store) *Service {
	if cfg == nil {
		cfg = config.FromEnv()
	}
	client := &http.Client{Timeout: 12 * time.Second, Transport: &http.Transport{DisableCompression: true, Proxy: http.ProxyFromEnvironment}}
	if cfg.Proxy != "" {
		if u, err := url.Parse(cfg.Proxy); err == nil {
			client.Transport = &http.Transport{DisableCompression: true, Proxy: http.ProxyURL(u)}
		}
	}
	s := &Service{
		Cfg:    cfg,
		Look:   lookup.New(),
		DB:     db,
		Enrich: providers.New(providers.All(cfg.ProviderKeys, cfg.ProviderBase, client), cfg.EnrichTimeout),
		Checks: &unlock.Engine{Get: unlock.LiveGetter{Client: client}},
		Now:    time.Now,
		fp:     map[string]Fingerprint{},
	}
	// Apply registry so a disabled selection is visible.
	reg := probe.NewRegistry(cfg.Vantage,
		probe.Globalping{BaseURL: cfg.GlobalpingURL, Token: cfg.GlobalpingToken},
		probe.RipeAtlas{Key: cfg.RipeKey, BaseURL: cfg.RipeURL},
		probe.BOCE{Key: cfg.BoceKey, BaseURL: cfg.BoceURL},
	)
	s.Vantage = reg.Active()
	s.Tracer = func(ctx context.Context, target string) ([]route.Hop, error) {
		raw, err := route.Trace(ctx, target, 12)
		if err != nil {
			return nil, err
		}
		ph := make([]probe.Hop, len(raw))
		for i, h := range raw {
			ph[i] = probe.Hop{IP: h.IP, RTTMS: h.RTTMS, ASN: h.ASN}
		}
		return s.annotate(ph), nil
	}
	if cfg.EgressIPv4 != "" || cfg.EgressIPv6 != "" {
		s.Egress = func(ctx context.Context) (string, string) { return cfg.EgressIPv4, cfg.EgressIPv6 }
	}
	// A previous `ipd data update` is picked up by every command. Tests do not
	// have this directory, so they keep the bundled snapshot.
	_ = ingest.Load(s.Look, cfg)
	return s
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// LookupIP is the passive evidence matrix.
func (s *Service) LookupIP(ctx context.Context, ip string) (Report, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return Report{}, fmt.Errorf("invalid ip")
	}
	p := s.Look.Lookup(addr)
	if p.Reserved {
		return Report{
			Verdict: "reserved",
			Summary: ip + " is not a public address and will not be probed",
			Data: map[string]any{
				"ip": ip, "geo": map[string]any{"cc": "", "sources": []any{}},
				"asn":  map[string]any{"asn": 0, "org": "", "type": "reserved"},
				"rdns": "", "registered_cc": "", "announced_by": []int{}, "disagreements": []any{},
			},
			Sources:  []Source{},
			CachedAt: s.now(),
		}, nil
	}
	geoSources := []map[string]any{}
	for _, h := range p.Hits {
		if h.Rec.CC != "" || h.Rec.City != "" {
			geoSources = append(geoSources, map[string]any{"id": h.Source, "cc": h.Rec.CC, "city": h.Rec.City, "region": h.Rec.Region})
		}
	}
	if geoSources == nil {
		geoSources = []map[string]any{}
	}
	data := map[string]any{
		"ip": ip,
		"geo": map[string]any{
			"cc": p.CC, "region": p.Region, "city": p.City, "lat": p.Lat, "lon": p.Lon, "sources": geoSources,
		},
		"asn":           map[string]any{"asn": p.ASN, "org": p.Org, "type": p.ASType},
		"rdns":          p.RDNS,
		"registered_cc": p.RegisteredCC,
		"announced_by":  p.AnnouncedBy,
		"disagreements": p.Disagreements,
		"conflicts":     conflictsOrEmpty(p),
		"anycast":       p.Anycast,
	}
	if data["announced_by"] == nil {
		data["announced_by"] = []int{}
	}
	if data["disagreements"] == nil {
		data["disagreements"] = []lookup.Disagreement{}
	}
	v := "ok"
	sum := fmt.Sprintf("%s %s AS%d %s", ip, p.CC, p.ASN, p.ASType)
	if len(p.Disagreements) > 0 {
		v = "ok_with_caveats"
		sum += "; sources disagree"
	}
	if p.ASType == "unknown" && p.ASN == 0 {
		v = "abstain"
		sum = ip + " has no local observation; 无法判定"
	}
	return Report{Verdict: v, Summary: sum, Data: data, Sources: s.decorate(sourcesFrom(p)), CachedAt: s.now(), Attribution: s.attr()}, nil
}

// Risk explains purity, residential class, and native/broadcast.
func (s *Service) Risk(ctx context.Context, ip string, live bool) (Report, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return Report{}, fmt.Errorf("invalid ip")
	}
	p := s.Look.Lookup(addr)
	var enrich []providers.Result
	if live && !s.Cfg.Offline && s.Enrich != nil {
		enrich = s.Enrich.Lookup(ctx, addr)
	}
	scam, ipqs, abuse, _, _, _ := providers.Signals(enrich)
	var hits []dnsbl.Hit
	if live && !s.Cfg.Offline && s.DB != nil {
		// DNSBL is best-effort; the default resolver is the system resolver.
		hits, _ = dnsbl.Query(ctx, net.DefaultResolver, ip)
	}
	comp := s.Look.Composition(prefix24(addr))
	nat := score.ClassifyNative(p)
	feats := score.FeaturesFromProfile(p)
	cls := score.ClassifyObserved(p, comp, feats)
	pur := score.ScorePurity(score.PurityInput{
		ASType: p.ASType, Cloud: p.Cloud, Flags: p.Flags,
		Disagreement:          len(p.Disagreements) > 0,
		LocationInconsistent:  nat.Verdict == "broadcast",
		NeighborContamination: comp.Contamination,
		AnnouncedByHoster:     p.UpstreamType == "hosting",
		Scamalytics:           scam, IPQS: ipqs, AbuseConfidence: abuse,
		DNSBLHits: len(hits),
	})
	if cls.Class == "abstain" || cls.Class == "cannot determine" {
		// keep purity verdict; residential abstains on its own
	}
	data := map[string]any{
		"purity": map[string]any{
			"score": pur.Score, "grade": pur.Grade, "verdict": pur.Verdict,
			"factors": pur.Factors, "confidence": pur.Confidence, "model_version": pur.ModelVersion,
		},
		"residential":   cls,
		"native":        nat,
		"confidence":    pur.Confidence,
		"disagreements": p.Disagreements,
		"conflicts":     conflictsOrEmpty(p),
		"anycast":       p.Anycast,
		"enrichment":    enrich,
		"dnsbl":         hits,
	}
	sum := fmt.Sprintf("purity %d %s (%s); residential %s; native %s", pur.Score, pur.Grade, pur.Verdict, cls.Class, nat.Verdict)
	if cls.SuspectedFakeResidential {
		sum += "; suspected fake residential"
	}
	if cls.Class == "abstain" || cls.Class == "cannot determine" {
		sum += "; 住宅类型无法判定"
	}
	srcs := s.decorate(sourcesFrom(p))
	for _, e := range enrich {
		if e.Status == "ok" {
			srcs = append(srcs, Source{ID: e.ID, Raw: e.Raw})
		}
	}
	_ = s.recordHistory(ip, p, cls.Class)
	return Report{Verdict: pur.Verdict, Summary: sum, Data: data, Sources: srcs, CachedAt: s.now(), Attribution: s.attr()}, nil
}

func (s *Service) recordHistory(ip string, p lookup.Profile, class string) error {
	if s.DB == nil {
		return nil
	}
	flags := strings.Join(p.Flags, ",")
	_, err := s.DB.AddHistory(ip, p.Prefix, p.CC, class, flags, p.ASN, s.now())
	return err
}

func prefix24(ip netip.Addr) string {
	if !ip.Is4() {
		p, _ := ip.Prefix(64)
		return p.String()
	}
	b := ip.As4()
	return fmt.Sprintf("%d.%d.%d.0/24", b[0], b[1], b[2])
}

func (s *Service) decorate(in []Source) []Source {
	meta := map[string]lookup.SourceMeta{}
	for _, m := range s.Look.Sources(s.now()) {
		meta[m.ID] = m
	}
	for i := range in {
		if m, ok := meta[in[i].ID]; ok {
			in[i].Attribution = m.Attribution
			in[i].License = m.License
		}
	}
	return in
}

func (s *Service) attr() []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range s.Look.Sources(s.now()) {
		if !m.Enabled || m.Attribution == "" || seen[m.Attribution] {
			continue
		}
		seen[m.Attribution] = true
		out = append(out, m.Attribution)
	}
	if out == nil {
		out = []string{}
	}
	return out
}

// Batch looks up many addresses. The cap is 1000.
func (s *Service) Batch(ctx context.Context, ips []string) (Report, error) {
	if len(ips) > 1000 {
		return Report{}, fmt.Errorf("max 1000 addresses")
	}
	rows := make([]map[string]any, 0, len(ips))
	for _, ip := range ips {
		r, err := s.Risk(ctx, strings.TrimSpace(ip), false)
		if err != nil {
			rows = append(rows, map[string]any{"ip": ip, "error": err.Error()})
			continue
		}
		cc, asn, typ, scoreN, grade := "", 0, "", 0, ""
		if m, ok := r.Data.(map[string]any); ok {
			if res, ok := m["residential"].(score.Class); ok {
				typ = res.Class
			}
			if pur, ok := m["purity"].(map[string]any); ok {
				if v, ok := pur["score"].(int); ok {
					scoreN = v
				}
				grade, _ = pur["grade"].(string)
			}
		}
		// Pull cc/asn from a nested lookup to keep the batch row flat.
		if lp, err := s.LookupIP(ctx, strings.TrimSpace(ip)); err == nil {
			if m, ok := lp.Data.(map[string]any); ok {
				if g, ok := m["geo"].(map[string]any); ok {
					cc, _ = g["cc"].(string)
				}
				if a, ok := m["asn"].(map[string]any); ok {
					asn, _ = a["asn"].(int)
				}
			}
		}
		rows = append(rows, map[string]any{"ip": strings.TrimSpace(ip), "cc": cc, "asn": asn, "type": typ, "score": scoreN, "grade": grade})
	}
	return Report{Verdict: "ok", Summary: fmt.Sprintf("%d addresses", len(rows)), Data: map[string]any{"results": rows}, Sources: []Source{}, CachedAt: s.now(), Attribution: s.attr()}, nil
}

// ASN returns what we know about an autonomous system.
func (s *Service) ASN(asn int) Report {
	info := s.Look.ASNInfo(asn)
	if info.PrefixesV4 == nil {
		info.PrefixesV4 = []string{}
	}
	if info.PrefixesV6 == nil {
		info.PrefixesV6 = []string{}
	}
	if info.Upstreams == nil {
		info.Upstreams = []int{}
	}
	v := "ok"
	if info.Org == "" && len(info.PrefixesV4) == 0 {
		v = "abstain"
	}
	return Report{Verdict: v, Summary: fmt.Sprintf("AS%d %s %s", asn, info.Org, info.Type), Data: info, Sources: []Source{{ID: "bgp"}, {ID: "peeringdb"}, {ID: "apnic_eyeball"}}, CachedAt: s.now(), Attribution: s.attr()}
}

// Prefix returns neighbour composition.
func (s *Service) Prefix(cidr string) (Report, error) {
	pfx, err := netip.ParsePrefix(cidr)
	if err != nil {
		return Report{}, fmt.Errorf("invalid prefix")
	}
	comp := s.Look.Composition(pfx.Masked().String())
	if comp.Composition == nil {
		comp.Composition = map[string]float64{}
	}
	if comp.Notable == nil {
		comp.Notable = []string{}
	}
	v := "ok"
	if comp.Contamination >= 0.8 {
		v = "risky"
	}
	return Report{Verdict: v, Summary: fmt.Sprintf("%s contamination %.2f", comp.CIDR, comp.Contamination), Data: comp, Sources: []Source{{ID: "cloud_ranges"}, {ID: "vpn_lists"}, {ID: "tor_exits"}}, CachedAt: s.now(), Attribution: s.attr()}, nil
}

// History returns field changes.
func (s *Service) History(ip string, days int) (Report, error) {
	if s.DB == nil {
		return Report{Verdict: "abstain", Summary: "no store", Data: map[string]any{"events": []any{}}, Sources: []Source{}, CachedAt: s.now()}, nil
	}
	if days <= 0 || days > 365 {
		days = 90
	}
	ev, err := s.DB.History(ip, s.now().AddDate(0, 0, -days))
	if err != nil {
		return Report{}, err
	}
	return Report{Verdict: "ok", Summary: fmt.Sprintf("%d changes", len(ev)), Data: map[string]any{"events": ev}, Sources: []Source{{ID: "history"}}, CachedAt: s.now()}, nil
}

// Sources lists datasets.
func (s *Service) Sources() Report {
	list := s.Look.Sources(s.now())
	online := providers.All(s.Cfg.ProviderKeys, s.Cfg.ProviderBase, nil)
	type row struct {
		ID          string `json:"id"`
		Version     string `json:"version"`
		UpdatedAt   string `json:"updated_at"`
		License     string `json:"license"`
		Attribution string `json:"attribution"`
		Enabled     bool   `json:"enabled"`
		Kind        string `json:"kind"`
		Rows        int    `json:"rows"`
		Stale       bool   `json:"stale"`
	}
	var rows []row
	staleN := 0
	for _, m := range list {
		u := ""
		if !m.UpdatedAt.IsZero() {
			u = m.UpdatedAt.UTC().Format(time.RFC3339)
		}
		rows = append(rows, row{ID: m.ID, Version: m.Version, UpdatedAt: u, License: m.License, Attribution: m.Attribution, Enabled: m.Enabled, Kind: m.Kind, Rows: m.Rows, Stale: m.Stale})
		if m.Stale {
			staleN++
		}
	}
	for _, p := range online {
		rows = append(rows, row{ID: p.ID(), Version: "", UpdatedAt: "", License: p.License(), Attribution: p.Attribution(), Enabled: p.Enabled(), Kind: "online", Rows: 0, Stale: false})
	}
	for _, z := range dnsbl.Zones() {
		rows = append(rows, row{ID: "dnsbl:" + z.Zone, License: z.License, Attribution: z.Name, Enabled: true, Kind: "dnsbl"})
	}
	v := "ok"
	if staleN > 0 {
		v = "ok_with_caveats"
	}
	return Report{Verdict: v, Summary: fmt.Sprintf("%d sources, %d stale", len(rows), staleN), Data: map[string]any{"sources": rows}, Sources: []Source{}, CachedAt: s.now(), Attribution: s.attr()}
}

// WhoAmI uses the injected egress or the caller address.
func (s *Service) WhoAmI(ctx context.Context, caller string, want string) (Report, error) {
	v4, v6 := "", ""
	if s.Egress != nil {
		v4, v6 = s.Egress(ctx)
	}
	if v4 == "" && caller != "" {
		if ip, err := netip.ParseAddr(caller); err == nil && ip.Is4() {
			v4 = caller
		}
		if ip, err := netip.ParseAddr(caller); err == nil && ip.Is6() {
			v6 = caller
		}
	}
	use := v4
	if want == "6" && v6 != "" {
		use = v6
	}
	if use == "" {
		use = v6
	}
	if use == "" {
		return Report{}, fmt.Errorf("requires_egress_run: set IPD_EGRESS_IPV4 or run `ipd me` on the egress")
	}
	risk, err := s.Risk(ctx, use, !s.Cfg.Offline)
	if err != nil {
		return Report{}, err
	}
	cc, asn, typ, scoreN, grade := "", 0, "", 0, ""
	if m, ok := risk.Data.(map[string]any); ok {
		if res, ok := m["residential"].(score.Class); ok {
			typ = res.Class
		}
		if pur, ok := m["purity"].(map[string]any); ok {
			scoreN, _ = pur["score"].(int)
			grade, _ = pur["grade"].(string)
		}
	}
	if lp, err := s.LookupIP(ctx, use); err == nil {
		if m, ok := lp.Data.(map[string]any); ok {
			if g, ok := m["geo"].(map[string]any); ok {
				cc, _ = g["cc"].(string)
			}
			if a, ok := m["asn"].(map[string]any); ok {
				asn, _ = a["asn"].(int)
			}
		}
	}
	data := map[string]any{
		"asn": asn, "cc": cc, "type": typ,
		"purity": map[string]any{"score": scoreN, "grade": grade},
	}
	if v4 != "" && want != "6" {
		data["ipv4"] = v4
	}
	if v6 != "" && want != "4" {
		data["ipv6"] = v6
	}
	return Report{Verdict: risk.Verdict, Summary: risk.Summary, Data: data, Sources: risk.Sources, CachedAt: s.now(), Attribution: s.attr()}, nil
}

// GFW runs the vantage and the state machine.
func (s *Service) GFW(ctx context.Context, target string, ports []int) (Report, error) {
	if !privacy.IsProbeTargetAllowed(hostOnly(target)) && net.ParseIP(hostOnly(target)) != nil {
		return Report{}, fmt.Errorf("target is not a public address")
	}
	if len(ports) == 0 {
		ports = []int{22, 80, 443}
	}
	if len(ports) > 5 {
		ports = ports[:5]
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	samples, err := s.measure(ctx, target, ports)
	if err != nil && !errors.Is(err, probe.ErrQuota) {
		return Report{}, err
	}
	if len(samples) == 0 {
		note := "vantage returned no probes"
		if errors.Is(err, probe.ErrQuota) {
			note = "globalping hourly quota exhausted"
		}
		judged := gfw.Result{Verdict: gfw.VerdictInsufficient, PerCarrier: map[string]string{"ct": "insufficient", "cu": "insufficient", "cm": "insufficient"}, Probes: []gfw.ProbeView{}, Control: []gfw.ProbeView{}, Notes: []string{note}, Confidence: 0.2}
		return Report{Verdict: judged.Verdict, Summary: judged.Verdict + " — " + note, Data: judged, Sources: []Source{{ID: s.Vantage.Name()}}, CachedAt: s.now(), Attribution: s.attr()}, nil
	}
	obs := make([]gfw.Obs, 0, len(samples))
	for _, sm := range samples {
		tcp := sm.TCP
		if tcp == nil {
			tcp = map[int]string{}
		}
		obs = append(obs, gfw.Obs{
			Network: sm.Network, ASN: sm.ASN, City: sm.City, Healthy: sm.Healthy,
			ICMP: sm.ICMP, Loss: sm.Loss, TCP: tcp, DNSAddrs: sm.DNSAddrs, SNI: sm.SNI,
		})
	}
	judged := gfw.Judge(obs, ports, poisonSet())
	sum := judged.Verdict + " — " + strings.Join(judged.Notes, " ")
	return Report{Verdict: judged.Verdict, Summary: sum, Data: judged, Sources: []Source{{ID: s.Vantage.Name()}}, CachedAt: s.now(), Attribution: s.attr()}, nil
}

func (s *Service) measure(ctx context.Context, target string, ports []int) ([]probe.Sample, error) {
	if s.Vantage == nil || !s.Vantage.Enabled() {
		return nil, fmt.Errorf("vantage disabled")
	}
	base, err := s.Vantage.Measure(ctx, probe.Query{Kind: probe.KindPing, Target: target, Limit: gfw.Quorum, Control: 1, Packets: 3})
	if err != nil {
		return nil, err
	}
	if len(base) == 0 {
		return nil, fmt.Errorf("vantage returned no probes")
	}
	tcpPorts := ports
	if len(tcpPorts) > 2 {
		tcpPorts = tcpPorts[:2]
	}
	for _, p := range tcpPorts {
		extra, err := s.Vantage.Measure(ctx, probe.Query{Kind: probe.KindTCP, Target: target, Port: p, Limit: gfw.Quorum, Control: 1, Packets: 2})
		if errors.Is(err, probe.ErrQuota) {
			return base, err
		}
		if err != nil {
			continue
		}
		base = mergeByProbe(base, extra)
	}
	if net.ParseIP(hostOnly(target)) == nil {
		extra, err := s.Vantage.Measure(ctx, probe.Query{Kind: probe.KindDNS, Target: hostOnly(target), DNSName: hostOnly(target), Limit: gfw.Quorum, Control: 1})
		if errors.Is(err, probe.ErrQuota) {
			return base, err
		}
		if err == nil {
			base = mergeByProbe(base, extra)
		}
	}
	wantHTTP := false
	for _, p := range ports {
		if p == 443 {
			wantHTTP = true
		}
	}
	if wantHTTP {
		extra, err := s.Vantage.Measure(ctx, probe.Query{Kind: probe.KindHTTP, Target: target, Port: 443, Limit: gfw.Quorum, Control: 1})
		if errors.Is(err, probe.ErrQuota) {
			return base, err
		}
		if err == nil {
			base = mergeByProbe(base, extra)
		}
	}
	return base, nil
}

func mergeByProbe(dst, src []probe.Sample) []probe.Sample {
	for _, s := range src {
		i := -1
		for j := range dst {
			if dst[j].Network == s.Network && dst[j].ASN == s.ASN && dst[j].City == s.City && s.ASN != 0 {
				i = j
				break
			}
		}
		if i < 0 {
			dst = append(dst, s)
			continue
		}
		if len(s.TCP) > 0 {
			if dst[i].TCP == nil {
				dst[i].TCP = map[int]string{}
			}
			for p, st := range s.TCP {
				dst[i].TCP[p] = st
			}
		}
		if len(s.DNSAddrs) > 0 {
			dst[i].DNSAddrs = append([]string(nil), s.DNSAddrs...)
		}
		if s.SNI != "" {
			dst[i].SNI = s.SNI
		}
		if dst[i].ICMP == "" && s.ICMP != "" {
			dst[i].ICMP = s.ICMP
		}
		if len(s.Hops) > 0 && len(dst[i].Hops) == 0 {
			dst[i].Hops = s.Hops
		}
	}
	return dst
}

func poisonSet() map[string]struct{} {
	var doc struct {
		Addresses []string `yaml:"addresses"`
	}
	_ = yaml.Unmarshal(data.Poison, &doc)
	m := map[string]struct{}{}
	for _, a := range doc.Addresses {
		m[a] = struct{}{}
	}
	return m
}

func hostOnly(t string) string {
	if h, _, err := net.SplitHostPort(t); err == nil {
		return h
	}
	return t
}

// RouteForward asks the China vantage for a path and classifies it.
func (s *Service) RouteForward(ctx context.Context, target string, carriers []string) (Report, error) {
	if s.Vantage == nil || !s.Vantage.Enabled() {
		return Report{}, fmt.Errorf("vantage disabled")
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	samples, err := s.Vantage.Measure(ctx, probe.Query{Kind: probe.KindTrace, Target: target, Carriers: carriers, Limit: 1, MaxHops: 20})
	if err != nil {
		return Report{}, err
	}
	var paths []route.Path
	for _, sm := range samples {
		if sm.Network == "control" {
			continue
		}
		hops := s.annotate(sm.Hops)
		class := route.Classify(hops)
		paths = append(paths, route.Path{Carrier: sm.Network, Probe: sm.City, Hops: hops, RouteClass: class})
	}
	if paths == nil {
		paths = []route.Path{}
	}
	sum, _ := route.Summarize(paths, "")
	return Report{Verdict: "ok", Summary: sum, Data: route.Result{Paths: paths, Summary: sum}, Sources: []Source{{ID: s.Vantage.Name()}}, CachedAt: s.now()}, nil
}

func (s *Service) annotate(hops []probe.Hop) []route.Hop {
	out := make([]route.Hop, 0, len(hops))
	for _, h := range hops {
		rh := route.Hop{IP: h.IP, RTTMS: h.RTTMS, ASN: h.ASN}
		if ip, err := netip.ParseAddr(h.IP); err == nil {
			p := s.Look.Lookup(ip)
			if p.ASN != 0 {
				rh.ASN = p.ASN
			}
			rh.GeoCC = p.CC
			rh.RDNS = p.RDNS
		}
		out = append(out, rh)
	}
	return out
}

// RouteReturn traces from this process toward China targets.
func (s *Service) RouteReturn(ctx context.Context, scope, claimed string) (Report, error) {
	targets := route.Targets(scope)
	if s.Tracer == nil {
		return Report{
			Verdict: "abstain",
			Summary: "traceroute needs CAP_NET_RAW or an injected tracer; classification is ready once hops are supplied",
			Data:    route.Result{Paths: []route.Path{}, Summary: "no tracer", Claimed: claimed},
			Sources: []Source{{ID: "local"}}, CachedAt: s.now(),
		}, nil
	}
	var paths []route.Path
	fail := 0
	var firstErr string
	for _, t := range targets {
		if ctx.Err() != nil {
			paths = append(paths, route.Path{Carrier: t.Carrier, Province: t.Province, RouteClass: "unknown", Error: ctx.Err().Error()})
			fail++
			continue
		}
		hops, err := s.Tracer(ctx, t.IP)
		if err != nil {
			if firstErr == "" {
				firstErr = err.Error()
			}
			fail++
			paths = append(paths, route.Path{Carrier: t.Carrier, Province: t.Province, RouteClass: "unknown", Error: err.Error()})
			continue
		}
		class := route.Classify(hops)
		paths = append(paths, route.Path{Carrier: t.Carrier, Province: t.Province, Hops: hops, RouteClass: class})
	}
	if fail == len(targets) && firstErr != "" {
		return Report{
			Verdict: "abstain",
			Summary: "回程 traceroute 没有拿到跳数：" + firstErr,
			Data:    route.Result{Paths: paths, Summary: firstErr, Claimed: claimed},
			Sources: []Source{{ID: "local"}}, CachedAt: s.now(),
		}, nil
	}
	sum, mismatch := route.Summarize(paths, claimed)
	v := "ok"
	if mismatch {
		v = "risky"
	}
	return Report{Verdict: v, Summary: sum, Data: route.Result{Paths: paths, Summary: sum, Claimed: claimed, ClaimMismatch: mismatch}, Sources: []Source{{ID: "local"}}, CachedAt: s.now()}, nil
}

// ClassifyPath is used by tests and by agents that already have hops.
func (s *Service) ClassifyPath(hops []route.Hop, claimed string) Report {
	class := route.Classify(hops)
	p := route.Path{Hops: hops, RouteClass: class}
	sum, mismatch := route.Summarize([]route.Path{p}, claimed)
	v := "ok"
	if mismatch {
		v = "risky"
	}
	return Report{Verdict: v, Summary: sum, Data: route.Result{Paths: []route.Path{p}, Summary: sum, Claimed: claimed, ClaimMismatch: mismatch}, Sources: []Source{{ID: "local"}}, CachedAt: s.now()}
}

// Latency asks the vantage for RTTs.
func (s *Service) Latency(ctx context.Context, target string) (Report, error) {
	if s.Vantage == nil || !s.Vantage.Enabled() {
		return Report{}, fmt.Errorf("vantage disabled")
	}
	samples, err := s.Vantage.Measure(ctx, probe.Query{Kind: probe.KindPing, Target: target, Limit: 2, Control: 2})
	if err != nil {
		return Report{}, err
	}
	rows := []map[string]any{}
	for _, sm := range samples {
		rows = append(rows, map[string]any{
			"probe": sm.Provider, "cc": sm.Country, "city": sm.City, "asn": sm.ASN, "rtt_ms": sm.RTTMS, "loss": sm.Loss,
		})
	}
	return Report{Verdict: "ok", Summary: fmt.Sprintf("%d probes", len(rows)), Data: map[string]any{"rows": rows, "svg": latencySVG(rows)}, Sources: []Source{{ID: s.Vantage.Name()}}, CachedAt: s.now()}, nil
}

func latencySVG(rows []map[string]any) string {
	var b strings.Builder
	b.WriteString(`<svg xmlns="http://www.w3.org/2000/svg" width="640" height="`)
	h := 40 + 28*len(rows)
	if h < 80 {
		h = 80
	}
	fmt.Fprintf(&b, `%d" viewBox="0 0 640 %d">`, h, h)
	b.WriteString(`<rect width="100%" height="100%" fill="#f4f1ea"/>`)
	b.WriteString(`<text x="16" y="28" font-family="ui-monospace,monospace" font-size="16">ipd latency</text>`)
	for i, row := range rows {
		y := 56 + i*28
		city, _ := row["city"].(string)
		cc, _ := row["cc"].(string)
		rtt, _ := row["rtt_ms"].(float64)
		fmt.Fprintf(&b, `<text x="16" y="%d" font-family="ui-monospace,monospace" font-size="13">%s %s  %.1f ms</text>`, y, cc, city, rtt)
	}
	b.WriteString(`</svg>`)
	return b.String()
}

// Unlock runs egress-side service checks.
func (s *Service) Unlock(ctx context.Context, ids []string) Report {
	if s.Checks == nil {
		return Report{Verdict: "abstain", Summary: "unlock engine missing", Data: map[string]any{"results": []any{}}, Sources: []Source{}}
	}
	res := s.Checks.Check(ctx, ids)
	bad := 0
	for _, r := range res {
		if r.Status == unlock.No || r.Status == unlock.ErrStatus {
			bad++
		}
	}
	v := "ok"
	if bad > 0 && bad < len(res) {
		v = "ok_with_caveats"
	}
	if len(res) > 0 && bad == len(res) {
		v = "blocked"
	}
	return Report{Verdict: v, Summary: fmt.Sprintf("%d services, %d unavailable", len(res), bad), Data: map[string]any{"results": res}, Sources: []Source{{ID: "unlock"}}, CachedAt: s.now()}
}

// GoogleRegion is the egress-side 送中 check.
func (s *Service) GoogleRegion(ctx context.Context) Report {
	u := s.Checks
	if u == nil {
		return Report{Verdict: "abstain", Summary: "no unlock client", Data: map[string]any{"sent_to_china": false}, Sources: []Source{}}
	}
	res := u.Check(ctx, []string{"google_region", "youtube_premium"})
	sent := false
	tld, gl, play := "", "", ""
	for _, r := range res {
		if r.Service == "google_region" && strings.Contains(r.Evidence, "sent_to_china=true") {
			sent = true
		}
		if strings.Contains(r.Evidence, "google.cn") {
			tld = "google.cn"
			sent = true
		} else if strings.Contains(r.Evidence, "google.com.hk") {
			tld = "google.com.hk"
			sent = true
		} else if tld == "" {
			tld = "google.com"
		}
		if r.Region != "" && gl == "" {
			gl = r.Region
		}
	}
	v := "ok"
	if sent {
		v = "risky"
	}
	return Report{
		Verdict: v,
		Summary: gfw.ExplainWallVsSent("ok", sent),
		Data:    map[string]any{"sent_to_china": sent, "google_tld": tld, "youtube_gl": gl, "play_region": play},
		Sources: []Source{{ID: "google"}}, CachedAt: s.now(),
	}
}

// AIEnv is the P1 verdict.
func (s *Service) AIEnv(ctx context.Context, includeCLI bool) Report {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	services := []string{"claude", "chatgpt", "gemini", "grok", "copilot", "meta_ai", "perplexity"}
	results := s.Checks.Check(ctx, services)
	traces := s.traces(ctx)
	v4, v6 := "", ""
	if s.Egress != nil {
		v4, v6 = s.Egress(ctx)
	}
	type fix struct {
		Severity string `json:"severity"`
		Issue    string `json:"issue"`
		How      string `json:"how"`
	}
	var fixes []fix
	per := []map[string]any{}
	blocked := false
	ips := map[string]struct{}{}
	for _, r := range results {
		seen := ""
		for _, t := range traces {
			if strings.Contains(t.URL, strings.Split(r.Service, "_")[0]) || (r.Service == "chatgpt" && strings.Contains(t.URL, "chatgpt")) || (r.Service == "claude" && strings.Contains(t.URL, "claude")) {
				seen = t.IP
			}
		}
		per = append(per, map[string]any{"service": r.Service, "available": r.Status == unlock.Yes || r.Status == unlock.WebOnly || r.Status == unlock.AppOnly, "seen_ip": seen, "region": r.Region, "status": r.Status})
		if r.Status == unlock.No && (r.Service == "claude" || r.Service == "chatgpt" || r.Service == "gemini") {
			blocked = true
			fixes = append(fixes, fix{"high", r.Service + "_unavailable", "switch to an egress in a supported region"})
		}
	}
	for _, t := range traces {
		if t.IP != "" {
			ips[t.IP] = struct{}{}
		}
	}
	consistent := len(ips) <= 1
	if len(ips) > 1 {
		fixes = append([]fix{{"high", "egress_mismatch", "the AI sites and telemetry domains do not see the same egress; fix the proxy rules so those domains share one path"}}, fixes...)
	}
	ipv6Bypass := false
	if v4 != "" && v6 != "" {
		p4 := s.lookupCC(v4)
		p6 := s.lookupCC(v6)
		if p4 != "" && p6 != "" && p4 != p6 {
			ipv6Bypass = true
			fixes = append(fixes, fix{"high", "ipv6_bypass", "disable IPv6 or route ::/0 through the proxy"})
		}
	}
	dnsLeak := false
	if s.DNS != nil {
		rep := s.DNS.Resolvers(ctx)
		for _, r := range rep {
			if r.CC != "" && v4 != "" && r.CC != s.lookupCC(v4) {
				dnsLeak = true
			}
		}
	}
	if dnsLeak {
		fixes = append(fixes, fix{"medium", "dns_leak", "point the system resolver at the proxy's DNS or a non-local DoH"})
	}
	tzIssue := timezoneIssue(s.lookupCC(v4))
	if tzIssue {
		fixes = append(fixes, fix{"medium", "timezone_mismatch", "set the system timezone to the egress country"})
	}
	if includeCLI {
		proxy := os.Getenv("HTTPS_PROXY")
		if proxy == "" {
			proxy = os.Getenv("https_proxy")
		}
		if proxy == "" {
			fixes = append(fixes, fix{"medium", "cli_proxy_unset", "export HTTPS_PROXY so Claude Code and Codex use the same egress as the browser"})
		}
	}
	v := "safe"
	if blocked {
		v = "blocked"
	} else if len(fixes) > 0 {
		v = "risky"
	}
	if fixes == nil {
		fixes = []fix{}
	}
	sum := "AI environment " + v
	if len(fixes) > 0 {
		sum = "VERDICT detail: " + fixes[0].Issue + " — " + fixes[0].How
	}
	data := map[string]any{
		"verdict": v, "fixes": fixes, "per_service": per,
		"egress_consistency": consistent, "ipv6_bypass": ipv6Bypass, "dns_leak": dnsLeak,
		"timezone_mismatch": tzIssue, "traces": traces,
	}
	return Report{Verdict: v, Summary: sum, Data: data, Sources: []Source{{ID: "unlock"}, {ID: "trace"}}, CachedAt: s.now()}
}

type traceHit struct {
	URL string `json:"url"`
	IP  string `json:"ip"`
	Loc string `json:"loc"`
}

func (s *Service) traces(ctx context.Context) []traceHit {
	if s.Checks == nil || s.Checks.Get == nil {
		return nil
	}
	urls := []string{
		"https://claude.ai/cdn-cgi/trace",
		"https://chatgpt.com/cdn-cgi/trace",
		"https://api.anthropic.com/cdn-cgi/trace",
		"https://statsigapi.net/cdn-cgi/trace",
		"https://browser.sentry.io/cdn-cgi/trace",
	}
	var out []traceHit
	for _, u := range urls {
		r := s.Checks.Get.Get(ctx, u, nil)
		ip, loc := "", ""
		for _, line := range strings.Split(r.Body, "\n") {
			if strings.HasPrefix(line, "ip=") {
				ip = strings.TrimPrefix(line, "ip=")
			}
			if strings.HasPrefix(line, "loc=") {
				loc = strings.TrimPrefix(line, "loc=")
			}
		}
		if ip != "" || r.Err == nil && r.Body != "" {
			out = append(out, traceHit{URL: u, IP: ip, Loc: loc})
		}
	}
	return out
}

func (s *Service) lookupCC(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	return s.Look.Lookup(addr).CC
}

func timezoneIssue(cc string) bool {
	if cc == "" {
		return false
	}
	_, offset := time.Now().Zone()
	hours := offset / 3600
	switch cc {
	case "CN", "HK", "SG":
		return hours != 8
	case "JP":
		return hours != 9
	case "US":
		return hours < -10 || hours > -4
	case "GB":
		return hours < 0 || hours > 1
	case "DE":
		return hours < 0 || hours > 2
	default:
		return false
	}
}

// DNSLeak runs the comparative resolver check.
func (s *Service) DNSLeak(ctx context.Context, rounds int) Report {
	if rounds <= 0 {
		rounds = 1
	}
	if rounds > 5 {
		rounds = 5
	}
	var resolvers []map[string]any
	leak := false
	if s.DNS != nil {
		for _, r := range s.DNS.Resolvers(ctx) {
			resolvers = append(resolvers, map[string]any{"ip": r.IP, "asn": r.ASN, "cc": r.CC, "ecs": r.ECS})
			if r.CC == "CN" {
				leak = true
			}
		}
	}
	if resolvers == nil {
		resolvers = []map[string]any{}
	}
	v := "ok"
	if leak {
		v = "risky"
	}
	if len(resolvers) == 0 {
		v = "abstain"
	}
	return Report{Verdict: v, Summary: fmt.Sprintf("dns leak=%v resolvers=%d", leak, len(resolvers)), Data: map[string]any{"resolvers": resolvers, "leak": leak}, Sources: []Source{{ID: "dns"}}, CachedAt: s.now()}
}

// PortCheck asks the vantage whether a TCP port answers.
func (s *Service) PortCheck(ctx context.Context, target string, port int, from string) (Report, error) {
	if port < 1 || port > 65535 {
		return Report{}, fmt.Errorf("invalid port")
	}
	rep, err := s.GFW(ctx, target, []int{port})
	if err != nil {
		return Report{}, err
	}
	reachable := []string{}
	if g, ok := rep.Data.(gfw.Result); ok {
		for _, p := range append(g.Probes, g.Control...) {
			if p.TCP[fmt.Sprint(port)] == "ok" || p.ICMP == "ok" {
				reachable = append(reachable, p.City)
			}
		}
	}
	return Report{Verdict: rep.Verdict, Summary: rep.Summary, Data: map[string]any{"reachable_by": reachable}, Sources: rep.Sources, CachedAt: s.now()}, nil
}

// SaveFingerprint records a ClientHello summary for a short time.
func (s *Service) SaveFingerprint(fp Fingerprint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fp == nil {
		s.fp = map[string]Fingerprint{}
	}
	fp.At = s.now()
	s.fp[fp.IP] = fp
}

// Fingerprint returns the last observation.
func (s *Service) Fingerprint(ip string) (Fingerprint, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fp, ok := s.fp[ip]
	return fp, ok
}

// Share stores a redacted report when sharing is explicitly enabled.
func (s *Service) Share(body string, hosts []string) (Report, error) {
	if s.Cfg == nil || !s.Cfg.ShareEnabled {
		return Report{}, fmt.Errorf("sharing is disabled (IPD_SHARE_ENABLED=false)")
	}
	if s.DB == nil {
		return Report{}, fmt.Errorf("no store")
	}
	clean := privacy.Redact(body, hosts)
	sum := sha256.Sum256([]byte(clean))
	id := hex.EncodeToString(sum[:])[:12]
	if err := s.DB.SaveShare(id, clean, s.now()); err != nil {
		return Report{}, err
	}
	return Report{Verdict: "ok", Summary: "shared " + id, Data: map[string]any{"id": id, "body": clean}, Sources: []Source{}, CachedAt: s.now()}, nil
}

// LoadShare reads a shared report.
func (s *Service) LoadShare(id string) (string, error) {
	if s.DB == nil {
		return "", fmt.Errorf("no store")
	}
	return s.DB.Share(id)
}

// Label stores an opt-in training label when the feature flag is on.
func (s *Service) Label(ip, label, note string) error {
	if s.Cfg == nil || !s.Cfg.LabelsEnabled {
		return fmt.Errorf("label submission is disabled (IPD_LABELS_ENABLED=false)")
	}
	if s.DB == nil {
		return fmt.Errorf("no store")
	}
	return s.DB.AddLabel(ip, label, note, s.now())
}

// WebRTC stores only the boolean verdict.
func (s *Service) WebRTC(r privacy.WebRTCReport) error {
	if s.DB == nil {
		return nil
	}
	return s.DB.SaveWebRTC(r, s.now())
}

// CreateWatch registers a watch.
func (s *Service) CreateWatch(target, checks, webhook string) (Report, error) {
	if s.DB == nil {
		return Report{}, fmt.Errorf("no store")
	}
	id := newID()
	secret := newID()
	if err := s.DB.CreateWatch(id, target, checks, webhook, secret, s.now().Add(time.Hour)); err != nil {
		return Report{}, err
	}
	return Report{Verdict: "ok", Summary: "watch " + id, Data: map[string]any{"watch_id": id, "next_run": s.now().Add(time.Hour).UTC().Format(time.RFC3339), "secret": secret}, Sources: []Source{}, CachedAt: s.now()}, nil
}

// ListWatches returns watches without secrets.
func (s *Service) ListWatches() (Report, error) {
	if s.DB == nil {
		return Report{Verdict: "ok", Summary: "0 watches", Data: map[string]any{"watches": []any{}}, Sources: []Source{}}, nil
	}
	ws, err := s.DB.ListWatches()
	if err != nil {
		return Report{}, err
	}
	rows := []map[string]any{}
	for _, w := range ws {
		rows = append(rows, map[string]any{"watch_id": w.ID, "target": w.Target, "checks": w.Checks, "next_run": w.NextRun.Format(time.RFC3339)})
	}
	return Report{Verdict: "ok", Summary: fmt.Sprintf("%d watches", len(rows)), Data: map[string]any{"watches": rows}, Sources: []Source{}, CachedAt: s.now()}, nil
}

// DeleteWatch removes a watch.
func (s *Service) DeleteWatch(id string) error {
	if s.DB == nil {
		return fmt.Errorf("no store")
	}
	return s.DB.DeleteWatch(id)
}

// RunDueWatches delivers webhooks for watches whose snapshot changed.
func (s *Service) RunDueWatches(ctx context.Context, post func(url string, body []byte, sig string) error) (int, error) {
	if s.DB == nil {
		return 0, nil
	}
	due, err := s.DB.DueWatches(s.now())
	if err != nil {
		return 0, err
	}
	n := 0
	for _, w := range due {
		risk, err := s.Risk(ctx, w.Target, false)
		if err != nil {
			continue
		}
		payload, _ := json.Marshal(map[string]any{"event": "ip.changed", "target": w.Target, "verdict": risk.Verdict, "summary": risk.Summary})
		sum := sha256.Sum256(payload)
		hash := hex.EncodeToString(sum[:])
		if hash != w.LastHash && w.LastHash != "" && w.Webhook != "" && post != nil {
			mac := hmacSHA(w.Secret, payload)
			if err := post(w.Webhook, payload, mac); err != nil {
				continue
			}
			n++
		}
		_ = s.DB.UpdateWatch(w.ID, hash, s.now().Add(24*time.Hour))
		if w.LastHash == "" {
			// first observation is the baseline, not an alert
			continue
		}
	}
	return n, nil
}

func hmacSHA(secret string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	_, _ = m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// PeakCoverage is the fraction of hourly buckets that contain a sample.
func PeakCoverage(samples []time.Time, start, end time.Time) float64 {
	if !end.After(start) {
		return 0
	}
	buckets := map[int64]struct{}{}
	for _, ts := range samples {
		if ts.Before(start) || ts.After(end) {
			continue
		}
		buckets[ts.UTC().Truncate(time.Hour).Unix()] = struct{}{}
	}
	hours := int(end.Sub(start).Hours())
	if hours <= 0 {
		return 0
	}
	return float64(len(buckets)) / float64(hours)
}

// CanaryDiff compares observed statuses with canary.yaml.
func CanaryDiff(observed map[string]map[string]string) []string {
	var doc struct {
		Probes []struct {
			ID       string            `yaml:"id"`
			Services map[string]string `yaml:"services"`
		} `yaml:"probes"`
	}
	if err := yaml.Unmarshal(data.Canary, &doc); err != nil {
		return []string{"canary.yaml: " + err.Error()}
	}
	var alerts []string
	for _, p := range doc.Probes {
		got := observed[p.ID]
		for svc, want := range p.Services {
			if got[svc] != want {
				alerts = append(alerts, fmt.Sprintf("%s %s: got %q want %q", p.ID, svc, got[svc], want))
			}
		}
	}
	return alerts
}

// Job loads an async job. The result JSON is returned as data when present.
func (s *Service) Job(id string) (Report, error) {
	if s.DB == nil {
		return Report{}, fmt.Errorf("no store")
	}
	kind, status, result, err := s.DB.Job(id)
	if err != nil {
		return Report{}, err
	}
	var parsed any
	if result != "" {
		_ = json.Unmarshal([]byte(result), &parsed)
	}
	if parsed == nil {
		parsed = map[string]any{}
	}
	return Report{Verdict: status, Summary: kind + " " + status, Data: map[string]any{"status": status, "result": parsed}, Sources: []Source{}, CachedAt: s.now()}, nil
}

// ReadAll is a small helper for report bodies.
func ReadAll(r io.Reader, n int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, n))
}
