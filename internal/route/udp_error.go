package route

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// parseUDPExtendedError decodes Linux's sock_extended_err + sockaddr_in payload.
// Keep the wire decoder platform-independent so packet fixtures run without raw
// sockets on every host. Only a destination-sourced ICMP port-unreachable proves
// the UDP trace reached its target; other unreachable errors retain their hop.
func parseUDPExtendedError(data []byte, dst netip.Addr) (Hop, bool, error) {
	if len(data) < 24 {
		return Hop{}, false, fmt.Errorf("short UDP extended error")
	}
	hop := Hop{}
	if binary.NativeEndian.Uint16(data[16:18]) == 2 { // Linux AF_INET
		ip := netip.AddrFrom4([4]byte(data[20:24]))
		if !ip.IsUnspecified() {
			hop.IP = ip.String()
		}
	}
	origin, typ, code := data[4], data[5], data[6]
	if origin != 2 {
		return hop, false, fmt.Errorf("UDP error origin %d is not ICMP", origin)
	} // SO_EE_ORIGIN_ICMP
	if typ == 3 && code == 3 && hop.IP == dst.Unmap().String() {
		return hop, true, nil
	}
	if typ == 11 && code == 0 && hop.IP != "" {
		return hop, false, nil
	} // TTL exceeded in transit
	return hop, false, fmt.Errorf("UDP ICMP type %d code %d from %s did not reach destination", typ, code, hop.IP)
}
