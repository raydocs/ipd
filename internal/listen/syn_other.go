//go:build !linux

package listen

import (
	"context"
	"fmt"
	"net"
)

func startSYNCapture(ctx context.Context, port int, table *synTable) error {
	return fmt.Errorf("packet capture is linux-only")
}

func peerMSS(c net.Conn) int { return 0 }
