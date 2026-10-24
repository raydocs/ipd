package app

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"ipd/internal/probe"
	"ipd/internal/unlock"
)

func TestMergeByProbeKeepsICMP(t *testing.T) {
	base := []probe.Sample{{Network: "ct", ASN: 4134, City: "Shanghai", ICMP: "ok"}}
	extra := []probe.Sample{{Network: "ct", ASN: 4134, City: "Shanghai", TCP: map[int]string{443: "timeout"}, SNI: "reset"}}
	got := mergeByProbe(base, extra)
	if len(got) != 1 || got[0].ICMP != "ok" || got[0].TCP[443] != "timeout" || got[0].SNI != "reset" {
		t.Fatalf("%+v", got)
	}
}

func TestPeakOnceDial(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	s := newSvc(t)
	s.Cfg.PeakTarget = ln.Addr().String()
	if err := s.PeakOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	times, err := s.DB.PeakTimes(ln.Addr().String(), time.Now().Add(-time.Minute))
	if err != nil || len(times) != 1 {
		t.Fatal(err, times)
	}
}

type stubGetter struct{}

func (stubGetter) Get(ctx context.Context, rawURL string, headers map[string]string) unlock.Response {
	return unlock.Response{Status: 200, Body: "ok", FinalURL: rawURL}
}

func TestCanaryProbeFilter(t *testing.T) {
	s := newSvc(t)
	s.Checks.Get = stubGetter{}
	s.Cfg.CanaryProbe = ""
	alerts, obs := s.CanaryOnce(context.Background())
	if len(alerts) != 0 || len(obs) == 0 {
		t.Fatalf("alerts %v obs %v", alerts, obs)
	}
	s.Cfg.CanaryProbe = "la-direct"
	alerts, _ = s.CanaryOnce(context.Background())
	for _, a := range alerts {
		if strings.HasPrefix(a, "unsupported-region") {
			t.Fatal(a)
		}
	}
}
