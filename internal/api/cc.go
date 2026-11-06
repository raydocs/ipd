package api

import (
	_ "embed"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

//go:embed cc.sh
var ccScript string

var ccDNS = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

// ccOrigin accepts configuration only, never request Host/forwarded headers.
// HTTP is restricted to explicit loopback development origins.
func ccOrigin(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" {
		return "", false
	}
	host := u.Hostname()
	ip, ipErr := netip.ParseAddr(host)
	if host == "" || (ipErr != nil && (!ccDNS.MatchString(host) || len(host) > 253)) || strings.Contains(host, "%") {
		return "", false
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && (host == "localhost" || (ipErr == nil && ip.IsLoopback()))) {
		return "", false
	}
	if u.Port() != "" {
		p, e := strconv.Atoi(u.Port())
		if e != nil || p < 1 || p > 65535 {
			return "", false
		}
	}
	// Restrict the entire serialized authority, including odd port delimiters.
	authority := host
	if strings.Contains(host, ":") {
		authority = "[" + host + "]"
	}
	if u.Port() != "" {
		authority += ":" + u.Port()
	}
	if u.Host != authority {
		return "", false
	}
	origin := u.Scheme + "://" + authority
	if raw != origin && raw != origin+"/" {
		return "", false
	}
	return origin, true
}

func (s *Server) cc(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	origin, ok := "", false
	if s.Svc.Cfg != nil && !s.Svc.Cfg.Offline {
		origin, ok = ccOrigin(s.Svc.Cfg.CCOrigin)
	}
	if !ok {
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, "#!/bin/sh\nprintf '%s\\n' 'cc: unknown (offline or no trusted IPD_CC_ORIGIN)'\nexit 3\n")
		return
	}
	fmt.Fprint(w, strings.Replace(ccScript, "@ORIGIN@", origin, 1))
}

// This route does not call lookups, persist signals, or trust forwarding headers.
// A reverse proxy's peer address is not necessarily the end user's egress.
func (s *Server) ccIP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if s.Svc.Cfg != nil && s.Svc.Cfg.Offline {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintln(w, "unknown")
		return
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	ip, e := netip.ParseAddr(host)
	if err != nil || e != nil || ip.Zone() != "" {
		fmt.Fprintln(w, "unknown")
		return
	}
	fmt.Fprintln(w, ip.Unmap().String())
}
