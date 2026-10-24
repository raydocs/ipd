//go:build !linux

package route

import (
	"context"
	"fmt"
	"net/netip"
)

func platformTrace(ctx context.Context, dst netip.Addr, maxHops int) ([]Hop, error) {
	return nil, fmt.Errorf("raw traceroute is implemented for linux; use tracepath")
}
