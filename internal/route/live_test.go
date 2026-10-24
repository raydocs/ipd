package route

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestLiveTracePublic(t *testing.T) {
	c, err := net.DialTimeout("tcp", "1.1.1.1:443", 3*time.Second)
	if err != nil {
		t.Skip(err)
	}
	_ = c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	hops, err := Trace(ctx, "1.1.1.1", 8)
	if err != nil {
		t.Skip(err)
	}
	if realHops(hops) == 0 {
		t.Fatal("no hops")
	}
	t.Logf("hops %+v", hops)
}
