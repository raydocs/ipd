// Package probe is the vantage abstraction. China-facing measurements go
// through a provider. Globalping is the default. RIPE Atlas and BOCE exist
// behind the same interface and stay disabled until a key is configured.
package probe

import "context"

// Kind selects a measurement.
type Kind string

const (
	KindPing  Kind = "ping"
	KindTCP   Kind = "tcp"
	KindTrace Kind = "traceroute"
	KindMTR   Kind = "mtr"
	KindDNS   Kind = "dns"
	KindHTTP  Kind = "http"
)

// Query is a measurement request.
type Query struct {
	Kind      Kind
	Target    string
	Port      int
	Carriers  []string // ct, cu, cm; empty means all three
	Countries []string // when set, skip ASN picking and use these countries
	Limit     int      // probes per location
	Control   int      // overseas control probes
	DNSName   string
	Packets   int
	MaxHops   int
}

// Sample is one probe result, provider-agnostic.
type Sample struct {
	Provider string
	Network  string
	ASN      int
	City     string
	Country  string
	Healthy  bool
	ICMP     string
	Loss     float64
	RTTMS    float64
	TCP      map[int]string
	Hops     []Hop
	DNSAddrs []string
	SNI      string
	Error    string
	// DestinationReached is nil when completion is unknown, not an implicit success.
	DestinationReached *bool
	TraceDestination   string
}

// Hop is one traceroute hop before local ASN annotation.
type Hop struct {
	IP    string
	RTTMS float64
	ASN   int
}

// Provider runs measurements from a vantage.
type Provider interface {
	Name() string
	Enabled() bool
	Measure(ctx context.Context, q Query) ([]Sample, error)
}

// Registry picks the configured default and can fall back.
type Registry struct {
	Default   string
	Providers map[string]Provider
}

// NewRegistry builds the four implementations. Disabled ones return an error
// from Measure so callers can tell a missing key from an empty result.
func NewRegistry(defaultName string, gp, ripe, boce Provider) *Registry {
	if defaultName == "" {
		defaultName = "globalping"
	}
	return &Registry{
		Default: defaultName,
		Providers: map[string]Provider{
			"self":       Self{},
			"globalping": gp,
			"ripeatlas":  ripe,
			"boce":       boce,
		},
	}
}

// Active returns the selected provider.
func (r *Registry) Active() Provider {
	if r == nil {
		return disabled{name: "none", reason: "no registry"}
	}
	p := r.Providers[r.Default]
	if p == nil {
		return disabled{name: r.Default, reason: "unknown vantage"}
	}
	return p
}

type disabled struct {
	name, reason string
}

func (d disabled) Name() string  { return d.name }
func (d disabled) Enabled() bool { return false }
func (d disabled) Measure(ctx context.Context, q Query) ([]Sample, error) {
	return nil, errDisabled(d.name, d.reason)
}

type errString string

func (e errString) Error() string { return string(e) }

func errDisabled(name, reason string) error {
	return errString("vantage " + name + " disabled: " + reason)
}
