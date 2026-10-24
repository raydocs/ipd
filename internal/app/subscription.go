package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const subscriptionLimit = 2 << 20
const subscriptionTimeout = 20 * time.Second
const subscriptionRedirectLimit = 10

func readSource(ctx context.Context, source, proxy string) (string, error) {
	lower := strings.ToLower(source)
	if strings.HasPrefix(lower, "http:") || strings.HasPrefix(lower, "https:") {
		if proxy != "" {
			return "", errors.New("subscription fetch: configured proxy cannot preserve destination pinning")
		}
		// No environment proxy, default transport, or caller-controlled safety policy.
		transport := subscriptionTransport{
			lookup: (&net.Resolver{PreferGo: true, StrictErrors: true}).LookupNetIP,
			dial:   (&net.Dialer{Timeout: subscriptionTimeout}).DialContext,
		}
		return fetchSubscription(ctx, source, &http.Client{
			Transport:     transport,
			CheckRedirect: subscriptionRedirect,
		})
	}
	f, err := os.Open(source)
	if err == nil {
		defer f.Close()
		return readSubscriptionBody(f)
	}
	if strings.Contains(source, "proxies:") {
		return readSubscriptionBody(strings.NewReader(source))
	}
	// Preserve inline proxy URIs, not arbitrary remote-fetch schemes (file/ftp/etc.).
	if strings.Contains(source, "://") {
		for _, line := range strings.Split(strings.TrimSpace(source), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			u, err := url.Parse(strings.TrimSpace(line))
			if err != nil {
				return "", errors.New("invalid inline subscription URI")
			}
			switch u.Scheme {
			case "ss", "ssr", "vmess", "vless", "trojan", "hysteria", "hysteria2", "hy2", "tuic", "socks", "socks5":
			default:
				return "", errors.New("unsupported subscription URL scheme")
			}
		}
		return readSubscriptionBody(strings.NewReader(source))
	}
	return "", errors.New("cannot open subscription file")
}

func readSubscriptionBody(r io.Reader) (string, error) {
	b, err := io.ReadAll(io.LimitReader(r, subscriptionLimit+1))
	if err != nil {
		return "", errors.New("subscription body read failed")
	}
	if len(b) > subscriptionLimit {
		return "", errors.New("subscription exceeds 2 MiB limit")
	}
	return string(b), nil
}

// fetchSubscription owns the total deadline (including DNS, redirects and body).
// Its client argument is an internal HTTP test seam; readSource always supplies
// the validating transport. Never expose this client as user configuration.
func fetchSubscription(ctx context.Context, source string, client *http.Client) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, subscriptionTimeout)
	defer cancel()
	if _, err := subscriptionURL(source); err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return "", errors.New("invalid subscription URL")
	}
	resp, err := client.Do(req)
	if err != nil {
		// net/url and net/http errors contain URLs (including query tokens), and
		// resolver/dial errors can contain hostnames. Do not wrap those errors.
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", errors.New("subscription fetch failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("subscription HTTP status %d", resp.StatusCode)
	}
	body, err := readSubscriptionBody(resp.Body)
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	return body, err
}

func subscriptionRedirect(req *http.Request, via []*http.Request) error {
	// Subscription queries commonly contain tokens; do not forward them as Referer.
	req.Header.Del("Referer")
	if len(via) > subscriptionRedirectLimit {
		return errors.New("subscription redirect limit exceeded")
	}
	_, err := subscriptionURL(req.URL.String())
	return err
}

func subscriptionURL(raw string) (*url.URL, error) {
	invalid := errors.New("invalid subscription URL")
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Opaque != "" || u.Host == "" {
		return nil, invalid
	}
	host := u.Hostname()
	if host == "" || strings.ContainsAny(host, "%\\") {
		return nil, invalid
	}
	port := u.Port()
	if strings.HasSuffix(u.Host, ":") {
		return nil, invalid
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, invalid
		}
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" {
			return nil, invalid
		}
		// Brackets are mandatory for IPv6 and forbidden for IPv4.
		if ip.Is6() != strings.HasPrefix(u.Host, "[") {
			return nil, invalid
		}
	} else {
		if strings.HasPrefix(u.Host, "[") {
			return nil, invalid
		}
		// ASCII DNS names only: reject alternate numeric IPv4 forms, percent/zone
		// encodings, malformed labels, and Unicode lookalikes before DNS.
		name := strings.TrimSuffix(host, ".")
		if len(name) == 0 || len(name) > 253 {
			return nil, invalid
		}
		labels := strings.Split(name, ".")
		for _, label := range labels {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return nil, invalid
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
					return nil, invalid
				}
			}
		}
		// A numeric or hexadecimal final label is ambiguous with legacy IP syntax.
		last := strings.ToLower(labels[len(labels)-1])
		if last[0] >= '0' && last[0] <= '9' {
			return nil, invalid
		}
	}
	return u, nil
}

// Conservatively exclude special-use ranges, including documentation,
// benchmarking, transition mechanisms and reserved future address space.
// netip.IsGlobalUnicast alone also accepts private and special-purpose IPs.
// IANA global-unicast allocations to RIRs (registry dated 2025-10-10).
// A broad 2000::/3 allowlist would include IANA-reserved future allocations.
var subscriptionIPv6Allocated = []netip.Prefix{
	netip.MustParsePrefix("2001:200::/23"), netip.MustParsePrefix("2001:400::/23"),
	netip.MustParsePrefix("2001:600::/23"), netip.MustParsePrefix("2001:800::/22"),
	netip.MustParsePrefix("2001:c00::/23"), netip.MustParsePrefix("2001:e00::/23"),
	netip.MustParsePrefix("2001:1200::/23"), netip.MustParsePrefix("2001:1400::/22"),
	netip.MustParsePrefix("2001:1800::/23"), netip.MustParsePrefix("2001:1a00::/23"),
	netip.MustParsePrefix("2001:1c00::/22"), netip.MustParsePrefix("2001:2000::/19"),
	netip.MustParsePrefix("2001:4000::/23"), netip.MustParsePrefix("2001:4200::/23"),
	netip.MustParsePrefix("2001:4400::/23"), netip.MustParsePrefix("2001:4600::/23"),
	netip.MustParsePrefix("2001:4800::/23"), netip.MustParsePrefix("2001:4a00::/23"),
	netip.MustParsePrefix("2001:4c00::/23"), netip.MustParsePrefix("2001:5000::/20"),
	netip.MustParsePrefix("2001:8000::/19"), netip.MustParsePrefix("2001:a000::/20"),
	netip.MustParsePrefix("2001:b000::/20"), netip.MustParsePrefix("2003::/18"),
	netip.MustParsePrefix("2400::/12"), netip.MustParsePrefix("2410::/12"),
	netip.MustParsePrefix("2600::/12"), netip.MustParsePrefix("2610::/23"),
	netip.MustParsePrefix("2620::/23"), netip.MustParsePrefix("2630::/12"),
	netip.MustParsePrefix("2800::/12"), netip.MustParsePrefix("2a00::/12"),
	netip.MustParsePrefix("2a10::/12"), netip.MustParsePrefix("2c00::/12"),
}

var subscriptionDenied = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"), netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.175.48.0/24"), netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("2620:4f:8000::/48"),
	netip.MustParsePrefix("3fff::/20"),
}

func subscriptionAddressAllowed(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	// Only currently allocated IPv6 global-unicast space; excludes NAT64,
	// IPv4-compatible and local translation prefixes as well as ULA/linklocal.
	if ip.Is6() {
		allocated := false
		for _, prefix := range subscriptionIPv6Allocated {
			if prefix.Contains(ip) {
				allocated = true
				break
			}
		}
		if !allocated {
			return false
		}
	}
	for _, prefix := range subscriptionDenied {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

type subscriptionTransport struct {
	lookup func(context.Context, string, string) ([]netip.Addr, error)
	dial   func(context.Context, string, string) (net.Conn, error)
}

func (t subscriptionTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	u, err := subscriptionURL(req.URL.String())
	if err != nil {
		return nil, err
	}
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil {
		ips = []netip.Addr{ip}
	} else {
		ips, err = t.lookup(req.Context(), "ip", u.Hostname())
		if err != nil {
			return nil, errors.New("subscription DNS lookup failed")
		}
	}
	if len(ips) == 0 {
		return nil, errors.New("subscription DNS returned no addresses")
	}
	for _, ip := range ips {
		if !subscriptionAddressAllowed(ip) {
			return nil, errors.New("subscription destination is not public")
		}
	}
	return roundTripSubscriptionPinned(req, ips, t.dial)
}

// All addresses must have been validated together by RoundTrip. This separate
// helper allows socket-level tests using documentation IPs routed to httptest,
// without a production trust-private flag or injectable address policy.
func roundTripSubscriptionPinned(req *http.Request, ips []netip.Addr, dial func(context.Context, string, string) (net.Conn, error)) (*http.Response, error) {
	port := req.URL.Port()
	if port == "" {
		port = "80"
		if req.URL.Scheme == "https" {
			port = "443"
		}
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   subscriptionTimeout,
		ResponseHeaderTimeout: subscriptionTimeout,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			for _, ip := range ips {
				conn, err := dial(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
				if err == nil {
					return conn, nil
				}
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
			}
			return nil, errors.New("subscription connection failed")
		},
	}
	// URL/Host are unchanged, so HTTPS still verifies the original hostname/SNI.
	defer transport.CloseIdleConnections()
	return transport.RoundTrip(req)
}
