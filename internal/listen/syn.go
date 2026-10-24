package listen

import (
	"sync"
	"time"
)

type synTable struct {
	mu sync.Mutex
	m  map[string]synHit
}

type synHit struct {
	MSS int
	TTL int
	At  time.Time
}

func (t *synTable) add(ip string, mss, ttl int) {
	if t == nil || ip == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.m == nil {
		t.m = map[string]synHit{}
	}
	t.m[ip] = synHit{MSS: mss, TTL: ttl, At: time.Now()}
}

func (t *synTable) get(ip string) (int, int) {
	if t == nil {
		return 0, 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	h, ok := t.m[ip]
	if !ok || time.Since(h.At) > 5*time.Second {
		return 0, 0
	}
	return h.MSS, h.TTL
}
