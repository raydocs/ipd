// Package providers fans out to optional online IP intelligence APIs.
// Every adapter is disabled when its key is empty. Raw payloads are returned
// unchanged so the evidence matrix can show them.
package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"time"
)

// Result is one provider response.
type Result struct {
	ID      string         `json:"id"`
	Enabled bool           `json:"enabled"`
	Status  string         `json:"status"` // ok, disabled, timeout, error, short_circuit
	Raw     map[string]any `json:"raw,omitempty"`
	Error   string         `json:"error,omitempty"`
	Cached  bool           `json:"cached,omitempty"`
}

// Provider looks up one IP.
type Provider interface {
	ID() string
	Enabled() bool
	Attribution() string
	License() string
	Lookup(ctx context.Context, ip netip.Addr) (map[string]any, error)
}

// Fanout calls every enabled provider with a shared deadline and a per-source
// circuit breaker. A slow source is marked timeout and does not hold the rest.
type Fanout struct {
	Providers []Provider
	Timeout   time.Duration
	Client    *http.Client
	mu        sync.Mutex
	cache     map[string]cacheItem
	breakers  map[string]*breaker
}

type cacheItem struct {
	raw map[string]any
	exp time.Time
}

type breaker struct {
	fails int
	open  time.Time
}

func New(list []Provider, timeout time.Duration) *Fanout {
	if timeout <= 0 {
		timeout = 1200 * time.Millisecond
	}
	return &Fanout{
		Providers: list,
		Timeout:   timeout,
		cache:     map[string]cacheItem{},
		breakers:  map[string]*breaker{},
	}
}

// Lookup returns one result per configured provider. Disabled providers are
// listed so callers can show that the source exists but has no key.
func (f *Fanout) Lookup(ctx context.Context, ip netip.Addr) []Result {
	if f == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, f.Timeout)
	defer cancel()
	out := make([]Result, len(f.Providers))
	var wg sync.WaitGroup
	for i, p := range f.Providers {
		i, p := i, p
		out[i] = Result{ID: p.ID(), Enabled: p.Enabled()}
		if !p.Enabled() {
			out[i].Status = "disabled"
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i] = f.one(ctx, p, ip)
		}()
	}
	wg.Wait()
	return out
}

func (f *Fanout) one(ctx context.Context, p Provider, ip netip.Addr) Result {
	res := Result{ID: p.ID(), Enabled: true}
	key := p.ID() + "|" + ip.String()
	f.mu.Lock()
	if it, ok := f.cache[key]; ok && time.Now().Before(it.exp) {
		f.mu.Unlock()
		res.Status = "ok"
		res.Raw = it.raw
		res.Cached = true
		return res
	}
	br := f.breakers[p.ID()]
	if br == nil {
		br = &breaker{}
		f.breakers[p.ID()] = br
	}
	if br.fails >= 5 && time.Now().Before(br.open) {
		f.mu.Unlock()
		res.Status = "short_circuit"
		res.Error = "circuit open"
		return res
	}
	f.mu.Unlock()

	raw, err := p.Lookup(ctx, ip)
	f.mu.Lock()
	defer f.mu.Unlock()
	if err != nil {
		br.fails++
		if br.fails >= 5 {
			br.open = time.Now().Add(30 * time.Second)
		}
		if ctx.Err() != nil {
			res.Status = "timeout"
		} else {
			res.Status = "error"
		}
		res.Error = err.Error()
		return res
	}
	br.fails = 0
	if len(f.cache) > 4096 {
		f.cache = map[string]cacheItem{}
	}
	f.cache[key] = cacheItem{raw: raw, exp: time.Now().Add(6 * time.Hour)}
	res.Status = "ok"
	res.Raw = raw
	return res
}

// HTTP is a small JSON GET adapter.
type HTTP struct {
	Name, LicenseText, Credit, Base, KeyName, Key string
	Build                                         func(base, key, ip string) (string, http.Header)
	Client                                        *http.Client
}

func (h HTTP) ID() string          { return h.Name }
func (h HTTP) Enabled() bool       { return h.Key != "" }
func (h HTTP) Attribution() string { return h.Credit }
func (h HTTP) License() string     { return h.LicenseText }
func (h HTTP) Lookup(ctx context.Context, ip netip.Addr) (map[string]any, error) {
	if h.Key == "" {
		return nil, fmt.Errorf("disabled")
	}
	u, hdr := h.Build(h.Base, h.Key, ip.String())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("user-agent", "ipd")
	client := h.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s status %d", h.Name, resp.StatusCode)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// All returns the ten online adapters. Each stays disabled until its key is set.
func All(keys, bases map[string]string, client *http.Client) []Provider {
	g := func(m map[string]string, k string) string {
		if m == nil {
			return ""
		}
		return m[k]
	}
	mk := func(name, license, credit, key string, build func(base, key, ip string) (string, http.Header)) Provider {
		return HTTP{Name: name, LicenseText: license, Credit: credit, Base: g(bases, name), Key: g(keys, key), Build: build, Client: client}
	}
	return []Provider{
		mk("scamalytics", "Scamalytics API terms", "Scamalytics", "scamalytics", func(base, key, ip string) (string, http.Header) {
			return base + "/" + url.PathEscape(ip) + "?key=" + url.QueryEscape(key), nil
		}),
		mk("ipqs", "IPQualityScore terms", "IPQualityScore", "ipqs", func(base, key, ip string) (string, http.Header) {
			return base + "/" + url.PathEscape(key) + "/" + url.PathEscape(ip), nil
		}),
		mk("abuseipdb", "AbuseIPDB terms", "AbuseIPDB", "abuseipdb", func(base, key, ip string) (string, http.Header) {
			return base + "?ipAddress=" + url.QueryEscape(ip), http.Header{"Key": {key}, "Accept": {"application/json"}}
		}),
		mk("ipapiis", "ipapi.is terms", "ipapi.is", "ipapiis", func(base, key, ip string) (string, http.Header) {
			return base + "?q=" + url.QueryEscape(ip) + "&key=" + url.QueryEscape(key), nil
		}),
		mk("proxycheck", "proxycheck.io terms", "proxycheck.io", "proxycheck", func(base, key, ip string) (string, http.Header) {
			return base + "/" + url.PathEscape(ip) + "?key=" + url.QueryEscape(key), nil
		}),
		mk("ipinfo", "IPinfo terms", "IP address data powered by IPinfo", "ipinfo", func(base, key, ip string) (string, http.Header) {
			return base + "/" + url.PathEscape(ip) + "/json?token=" + url.QueryEscape(key), nil
		}),
		mk("greynoise", "GreyNoise terms", "GreyNoise Community", "greynoise", func(base, key, ip string) (string, http.Header) {
			return base + "/" + url.PathEscape(ip), http.Header{"key": {key}}
		}),
		mk("ipdata", "ipdata terms", "ipdata.co", "ipdata", func(base, key, ip string) (string, http.Header) {
			return base + "/" + url.PathEscape(ip) + "?api-key=" + url.QueryEscape(key), nil
		}),
		mk("ipregistry", "ipregistry terms", "ipregistry", "ipregistry", func(base, key, ip string) (string, http.Header) {
			return base + "/" + url.PathEscape(ip) + "?key=" + url.QueryEscape(key), nil
		}),
		mk("ip2locationio", "ip2location.io terms", "ip2location.io", "ip2locationio", func(base, key, ip string) (string, http.Header) {
			return base + "/?key=" + url.QueryEscape(key) + "&ip=" + url.QueryEscape(ip), nil
		}),
	}
}

// IntField reads a numeric JSON field that may have been decoded as float64.
func IntField(raw map[string]any, keys ...string) (int, bool) {
	for _, k := range keys {
		v, ok := raw[k]
		if !ok {
			continue
		}
		switch n := v.(type) {
		case float64:
			return int(n), true
		case int:
			return n, true
		case json.Number:
			i, err := n.Int64()
			if err == nil {
				return int(i), true
			}
		}
	}
	return 0, false
}

// Signals extracts the fields purity knows how to use. Missing fields stay unknown.
func Signals(results []Result) (scam, ipqs, abuse int, scamOK, ipqsOK, abuseOK bool) {
	scam, ipqs, abuse = -1, -1, -1
	for _, r := range results {
		if r.Status != "ok" || r.Raw == nil {
			continue
		}
		switch r.ID {
		case "scamalytics":
			if n, ok := IntField(r.Raw, "scamalytics_score", "score", "fraud_score"); ok {
				scam, scamOK = n, true
			}
		case "ipqs":
			if n, ok := IntField(r.Raw, "fraud_score"); ok {
				ipqs, ipqsOK = n, true
			}
		case "abuseipdb":
			if data, ok := r.Raw["data"].(map[string]any); ok {
				if n, ok := IntField(data, "abuseConfidenceScore"); ok {
					abuse, abuseOK = n, true
				}
			}
			if n, ok := IntField(r.Raw, "abuseConfidenceScore"); ok {
				abuse, abuseOK = n, true
			}
		}
	}
	return
}
