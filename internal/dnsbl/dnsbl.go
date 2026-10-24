// Package dnsbl queries a fixed list of public DNS blocklists through an
// injected resolver so tests never touch the network.
package dnsbl

import (
	"context"
	"net"
	"strings"

	"gopkg.in/yaml.v3"
	"ipd/data"
)

// Zone is one DNSBL.
type Zone struct {
	Zone    string `yaml:"zone" json:"zone"`
	Name    string `yaml:"name" json:"name"`
	License string `yaml:"license" json:"license"`
}

// Resolver looks up a name.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// Hit is one listing.
type Hit struct {
	Zone string `json:"zone"`
	Name string `json:"name"`
}

// Zones returns the published list (at least 15).
func Zones() []Zone {
	var doc struct {
		Zones []Zone `yaml:"zones"`
	}
	if err := yaml.Unmarshal(data.DNSBL, &doc); err != nil {
		return nil
	}
	return doc.Zones
}

// Query checks ip against every zone. Listed means an A record came back.
func Query(ctx context.Context, r Resolver, ip string) ([]Hit, error) {
	if r == nil {
		return nil, nil
	}
	rev := reverse(ip)
	if rev == "" {
		return nil, nil
	}
	var hits []Hit
	for _, z := range Zones() {
		addrs, err := r.LookupHost(ctx, rev+"."+z.Zone)
		if err != nil {
			if ne, ok := err.(*net.DNSError); ok && ne.IsNotFound {
				continue
			}
			// a timeout on one zone is not fatal
			continue
		}
		if len(addrs) > 0 {
			hits = append(hits, Hit{Zone: z.Zone, Name: z.Name})
		}
	}
	if hits == nil {
		hits = []Hit{}
	}
	return hits, nil
}

func reverse(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	return parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0]
}
