package ingest

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestLiveSmallFeeds(t *testing.T) {
	if !dial("1.1.1.1:443", 3*time.Second) {
		t.Skip("network unreachable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 20 * time.Second}
	cf, err := httpGet(ctx, client, "https://www.cloudflare.com/ips-v4", 1<<20)
	if err != nil {
		t.Skip(err)
	}
	rows, err := parseCloudflare(cf)
	if err != nil || len(rows) < 5 {
		t.Fatal(err, len(rows))
	}
	drop, err := httpGet(ctx, client, "https://www.spamhaus.org/drop/drop.txt", 2<<20)
	if err != nil {
		t.Skip(err)
	}
	srows, err := parseCIDRList(drop, "spamhaus_drop", rows[0].Rec, 0)
	if err != nil || len(srows) < 5 {
		t.Fatal(err, len(srows))
	}
	t.Logf("cloudflare %d spamhaus %d", len(rows), len(srows))
}

func dial(addr string, d time.Duration) bool {
	c, err := net.DialTimeout("tcp", addr, d)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}
