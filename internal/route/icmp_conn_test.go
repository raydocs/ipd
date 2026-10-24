package route

import (
	"testing"

	"golang.org/x/net/icmp"
)

// Exercise the same endpoint setup used by icmpTrace with concrete x/net types,
// without opening a socket. The invalid endpoint must return an error, not panic
// in an attempted net.Conn assertion. No fake endpoint or production test branch.
func TestTraceIPv4ConnWithoutSocket(t *testing.T) {
	for _, c := range []*icmp.PacketConn{new(icmp.PacketConn), nil} {
		p, err := traceIPv4Conn(c)
		if p != nil || err == nil {
			t.Fatalf("endpoint=%v err=%v; want nil endpoint and error", p, err)
		}
	}
}
