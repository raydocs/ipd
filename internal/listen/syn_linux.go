//go:build linux

package listen

import (
	"context"
	"encoding/binary"
	"time"

	"golang.org/x/sys/unix"
	"ipd/internal/leak"
)

func startSYNCapture(ctx context.Context, port int, table *synTable) error {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, htons(unix.ETH_P_IP))
	if err != nil {
		return err
	}
	go func() {
		defer unix.Close(fd)
		tv := unix.NsecToTimeval(int64(time.Second))
		_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
		buf := make([]byte, 2048)
		for {
			if ctx.Err() != nil {
				return
			}
			n, _, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(200 * time.Millisecond):
				}
				continue
			}
			if n < 40 || buf[0]>>4 != 4 || buf[9] != 6 {
				continue
			}
			fp, err := leak.ParseTCP(buf[:n])
			if err != nil || fp.MSS == 0 {
				continue
			}
			ihl := int(buf[0]&0x0f) * 4
			if n < ihl+14 {
				continue
			}
			flags := buf[ihl+13]
			if flags&0x02 == 0 || flags&0x10 != 0 {
				continue
			}
			dst := int(binary.BigEndian.Uint16(buf[ihl+2 : ihl+4]))
			if dst != port {
				continue
			}
			src := netIP(buf[12:16])
			table.add(src, fp.MSS, fp.TTL)
		}
	}()
	return nil
}

func htons(i uint16) int {
	return int(i<<8 | i>>8)
}

func netIP(b []byte) string {
	if len(b) != 4 {
		return ""
	}
	return itoa(int(b[0])) + "." + itoa(int(b[1])) + "." + itoa(int(b[2])) + "." + itoa(int(b[3]))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var a [4]byte
	i := len(a)
	for n > 0 {
		i--
		a[i] = byte('0' + n%10)
		n /= 10
	}
	return string(a[i:])
}
