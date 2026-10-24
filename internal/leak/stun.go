package leak

import (
	"context"
	"net"

	"github.com/pion/stun"
)

// STUN serves binding requests. It does not persist mapped addresses.
func ServeSTUN(ctx context.Context, addr string) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	defer pc.Close()
	go func() {
		<-ctx.Done()
		_ = pc.Close()
	}()
	buf := make([]byte, 1500)
	for {
		n, raddr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		msg := &stun.Message{Raw: append([]byte(nil), buf[:n]...)}
		if err := msg.Decode(); err != nil {
			continue
		}
		if msg.Type != stun.BindingRequest {
			continue
		}
		ip, port := addrParts(raddr)
		res, err := stun.Build(msg, stun.BindingSuccess,
			&stun.XORMappedAddress{IP: ip, Port: port},
			stun.Fingerprint,
		)
		if err != nil {
			continue
		}
		_, _ = pc.WriteTo(res.Raw, raddr)
	}
}

func addrParts(a net.Addr) (net.IP, int) {
	switch v := a.(type) {
	case *net.UDPAddr:
		return v.IP, v.Port
	default:
		return net.IPv4zero, 0
	}
}
