package ingest

import (
	"math/bits"
	"net/netip"
)

// prefixesBetween converts an inclusive address range into CIDR prefixes.
// A single range is capped at 32 prefixes so a fragmented span cannot explode.
func prefixesBetween(start, end netip.Addr) []netip.Prefix {
	if !start.IsValid() || !end.IsValid() || start.BitLen() != end.BitLen() || start.Compare(end) > 0 {
		return nil
	}
	var out []netip.Prefix
	bitsN := start.BitLen()
	for start.IsValid() && start.Compare(end) <= 0 {
		if len(out) >= 32 {
			break
		}
		k := trailingZeros(start)
		for {
			p := netip.PrefixFrom(start, bitsN-k).Masked()
			last := lastAddr(p)
			if last.IsValid() && last.Compare(end) <= 0 {
				out = append(out, p)
				start = last.Next()
				break
			}
			if k == 0 {
				out = append(out, netip.PrefixFrom(start, bitsN).Masked())
				start = start.Next()
				break
			}
			k--
		}
	}
	return out
}

func trailingZeros(a netip.Addr) int {
	b := a.AsSlice()
	n := 0
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] == 0 {
			n += 8
			continue
		}
		n += bits.TrailingZeros8(b[i])
		break
	}
	if n > a.BitLen() {
		return a.BitLen()
	}
	return n
}

func lastAddr(p netip.Prefix) netip.Addr {
	p = p.Masked()
	b := p.Addr().AsSlice()
	host := p.Addr().BitLen() - p.Bits()
	for i := len(b) - 1; i >= 0 && host > 0; i-- {
		if host >= 8 {
			b[i] = 0xff
			host -= 8
			continue
		}
		b[i] |= 0xff >> (8 - host)
		host = 0
	}
	a, ok := netip.AddrFromSlice(b)
	if !ok {
		return netip.Addr{}
	}
	return a
}

// addOffset returns a + off, or false on overflow.
func addOffset(a netip.Addr, off uint64) (netip.Addr, bool) {
	b := a.AsSlice()
	carry := off
	for i := len(b) - 1; i >= 0; i-- {
		sum := uint64(b[i]) + carry
		b[i] = byte(sum)
		carry = sum >> 8
	}
	if carry != 0 {
		return netip.Addr{}, false
	}
	out, ok := netip.AddrFromSlice(b)
	return out, ok
}
