package dnsbl

import (
	"context"
	"testing"
)

type mem struct{ hit map[string]bool }

func (m mem) LookupHost(ctx context.Context, host string) ([]string, error) {
	if m.hit[host] {
		return []string{"127.0.0.2"}, nil
	}
	return nil, &notFound{}
}

type notFound struct{}

func (notFound) Error() string   { return "nx" }
func (notFound) Timeout() bool   { return false }
func (notFound) Temporary() bool { return false }

func TestZonesAndHit(t *testing.T) {
	if len(Zones()) < 15 {
		t.Fatal(len(Zones()))
	}
	zone := Zones()[0].Zone
	r := mem{hit: map[string]bool{"1.2.3.4." + zone: true}}
	hits, err := Query(context.Background(), r, "4.3.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Zone != zone {
		t.Fatalf("%+v", hits)
	}
}
