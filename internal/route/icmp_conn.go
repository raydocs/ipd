package route

import (
	"fmt"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// traceIPv4Conn uses the IPv4 endpoint already owned by the ICMP connection.
// An ICMP PacketConn is not a net.Conn and must not be wrapped with NewPacketConn.
func traceIPv4Conn(c *icmp.PacketConn) (*ipv4.PacketConn, error) {
	p := c.IPv4PacketConn()
	if p == nil {
		return nil, fmt.Errorf("ICMP connection has no IPv4 endpoint")
	}
	return p, nil
}
