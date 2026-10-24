// Package config loads ipd settings from the environment.
// Every listen address and the public domain are configuration, never hardcoded
// into a deployment.
package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the process-wide configuration.
type Config struct {
	Domain            string
	HTTPAddr          string
	DNSAddr           string
	STUNAddr          string
	TLSAddr           string
	DataDir           string
	ServerURL         string
	ShareEnabled      bool
	LabelsEnabled     bool
	Privacy           bool
	Offline           bool
	TrustProxy        bool
	EnrichTimeout     time.Duration
	LogRetention      time.Duration
	AnonymousRPM      int
	KeyedRPM          int
	ProbePerHour      int
	KeyedProbePerHour int
	Vantage           string
	GlobalpingURL     string
	GlobalpingToken   string
	RipeKey           string
	BoceKey           string
	APIKeys           map[string]struct{}
	ProviderKeys      map[string]string
	ProviderBase      map[string]string
	MaxMindCity       string
	MaxMindASN        string
	MaxMindKey        string
	DBIPCity          bool
	DataUpdate        bool
	DataEvery         time.Duration
	Peak              bool
	PeakEvery         time.Duration
	PeakTarget        string
	Canary            bool
	CanaryEvery       time.Duration
	CanaryProbe       string
	RipeURL           string
	BoceURL           string
	EnrollToken       string
	HubKeyPath        string
	EgressIPv4        string
	EgressIPv6        string
	UnlockFixture     string
	MetricsPublic     bool
	Proxy             string
	PowRequired       bool
	PowBits           int
}

// FromEnv reads IPD_* variables. Empty values fall back to local defaults so
// the binary runs without a domain or a public address.
func FromEnv() *Config {
	c := &Config{
		Domain:            env("IPD_DOMAIN", "localhost"),
		HTTPAddr:          env("IPD_HTTP_ADDR", "127.0.0.1:8787"),
		DNSAddr:           env("IPD_DNS_ADDR", "127.0.0.1:5353"),
		STUNAddr:          env("IPD_STUN_ADDR", "127.0.0.1:34780"),
		TLSAddr:           env("IPD_TLS_ADDR", "127.0.0.1:8443"),
		DataDir:           env("IPD_DATA_DIR", "var/lib/ipd"),
		ServerURL:         env("IPD_SERVER", ""),
		ShareEnabled:      envBool("IPD_SHARE_ENABLED", false),
		LabelsEnabled:     envBool("IPD_LABELS_ENABLED", false),
		Privacy:           envBool("IPD_PRIVACY", true),
		Offline:           envBool("IPD_OFFLINE", false),
		TrustProxy:        envBool("IPD_TRUST_PROXY", false),
		EnrichTimeout:     envDuration("IPD_ENRICH_TIMEOUT", 1200*time.Millisecond),
		LogRetention:      envDuration("IPD_LOG_RETENTION", 7*24*time.Hour),
		AnonymousRPM:      envInt("IPD_ANON_RPM", 60),
		KeyedRPM:          envInt("IPD_KEY_RPM", 600),
		ProbePerHour:      envInt("IPD_PROBE_PER_HOUR", 10),
		KeyedProbePerHour: envInt("IPD_KEY_PROBE_PER_HOUR", 100),
		Vantage:           env("IPD_VANTAGE", "globalping"),
		GlobalpingURL:     env("IPD_GLOBALPING_URL", "https://api.globalping.io/v1"),
		GlobalpingToken:   env("IPD_GLOBALPING_TOKEN", ""),
		RipeKey:           env("IPD_RIPE_KEY", ""),
		BoceKey:           env("IPD_BOCE_KEY", ""),
		APIKeys:           setOf(env("IPD_API_KEYS", "")),
		ProviderKeys: map[string]string{
			"scamalytics":   env("IPD_SCAMALYTICS_KEY", ""),
			"ipqs":          env("IPD_IPQS_KEY", ""),
			"abuseipdb":     env("IPD_ABUSEIPDB_KEY", ""),
			"ipapiis":       env("IPD_IPAPIIS_KEY", ""),
			"proxycheck":    env("IPD_PROXYCHECK_KEY", ""),
			"ipinfo":        env("IPD_IPINFO_TOKEN", ""),
			"greynoise":     env("IPD_GREYNOISE_KEY", ""),
			"ipdata":        env("IPD_IPDATA_KEY", ""),
			"ipregistry":    env("IPD_IPREGISTRY_KEY", ""),
			"ip2locationio": env("IPD_IP2LOCATION_KEY", ""),
		},
		ProviderBase: map[string]string{
			"scamalytics":   env("IPD_SCAMALYTICS_URL", "https://api.scamalytics.com/ipd"),
			"ipqs":          env("IPD_IPQS_URL", "https://ipqualityscore.com/api/json/ip"),
			"abuseipdb":     env("IPD_ABUSEIPDB_URL", "https://api.abuseipdb.com/api/v2/check"),
			"ipapiis":       env("IPD_IPAPIIS_URL", "https://api.ipapi.is"),
			"proxycheck":    env("IPD_PROXYCHECK_URL", "https://proxycheck.io/v2"),
			"ipinfo":        env("IPD_IPINFO_URL", "https://ipinfo.io"),
			"greynoise":     env("IPD_GREYNOISE_URL", "https://api.greynoise.io/v3/community"),
			"ipdata":        env("IPD_IPDATA_URL", "https://api.ipdata.co"),
			"ipregistry":    env("IPD_IPREGISTRY_URL", "https://api.ipregistry.co"),
			"ip2locationio": env("IPD_IP2LOCATION_URL", "https://api.ip2location.io"),
		},
		MaxMindCity:   env("IPD_MAXMIND_CITY", ""),
		MaxMindASN:    env("IPD_MAXMIND_ASN", ""),
		MaxMindKey:    env("IPD_MAXMIND_KEY", ""),
		DBIPCity:      envBool("IPD_DBIP_CITY", false),
		DataEvery:     envDuration("IPD_DATA_UPDATE_INTERVAL", 24*time.Hour),
		Peak:          envBool("IPD_PEAK", false),
		PeakEvery:     envDuration("IPD_PEAK_INTERVAL", 15*time.Minute),
		PeakTarget:    env("IPD_PEAK_TARGET", "1.1.1.1:443"),
		Canary:        envBool("IPD_CANARY", false),
		CanaryEvery:   envDuration("IPD_CANARY_INTERVAL", 24*time.Hour),
		CanaryProbe:   env("IPD_CANARY_PROBE", ""),
		RipeURL:       env("IPD_RIPE_URL", "https://atlas.ripe.net/api/v2"),
		BoceURL:       env("IPD_BOCE_URL", "https://api.boce.com/v3"),
		EnrollToken:   env("IPD_ENROLL_TOKEN", ""),
		HubKeyPath:    env("IPD_HUB_KEY", ""),
		EgressIPv4:    env("IPD_EGRESS_IPV4", ""),
		EgressIPv6:    env("IPD_EGRESS_IPV6", ""),
		UnlockFixture: env("IPD_UNLOCK_FIXTURE", ""),
		MetricsPublic: envBool("IPD_METRICS_PUBLIC", false),
		Proxy:         env("IPD_PROXY", ""),
		PowRequired:   envBool("IPD_POW", false),
		PowBits:       envInt("IPD_POW_BITS", 12),
	}
	// Default the refresh job on when the process is allowed to use the network.
	// IPD_DATA_UPDATE=false keeps a long-running serve on the bundled snapshot.
	c.DataUpdate = envBool("IPD_DATA_UPDATE", !c.Offline)
	return c
}

// HasAPIKey reports whether the presented token is configured.
func (c *Config) HasAPIKey(k string) bool {
	if k == "" {
		return false
	}
	_, ok := c.APIKeys[k]
	return ok
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envBool(k string, def bool) bool {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func envInt(k string, def int) int {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envDuration(k string, def time.Duration) time.Duration {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

func setOf(csv string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, p := range strings.Split(csv, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out[p] = struct{}{}
		}
	}
	return out
}
