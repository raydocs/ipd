package app

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// PeakOnce records one local TCP connect sample for the peak-hour series.
func (s *Service) PeakOnce(ctx context.Context) error {
	if s == nil || s.DB == nil {
		return fmt.Errorf("no store")
	}
	target := "1.1.1.1:443"
	if s.Cfg != nil && s.Cfg.PeakTarget != "" {
		target = s.Cfg.PeakTarget
	}
	if _, _, err := net.SplitHostPort(target); err != nil {
		target += ":443"
	}
	start := time.Now()
	d := net.Dialer{Timeout: 3 * time.Second}
	c, err := d.DialContext(ctx, "tcp", target)
	loss := 0.0
	rtt := 0.0
	if err != nil {
		loss = 1
	} else {
		rtt = float64(time.Since(start).Microseconds()) / 1000
		_ = c.Close()
	}
	return s.DB.AddPeak(target, "local", s.now(), loss, rtt)
}

// CanaryOnce runs the egress unlock checks used by the daily patrol.
// Alerts are produced only when IPD_CANARY_PROBE names an id in canary.yaml.
// An empty probe id records the observation and does not compare other probes.
func (s *Service) CanaryOnce(ctx context.Context) (alerts []string, observed map[string]string) {
	observed = map[string]string{}
	if s == nil || s.Checks == nil {
		return nil, observed
	}
	res := s.Checks.Check(ctx, []string{"claude", "chatgpt", "netflix", "google_region"})
	for _, r := range res {
		observed[r.Service] = r.Status
	}
	id := ""
	if s.Cfg != nil {
		id = s.Cfg.CanaryProbe
	}
	if id == "" {
		return nil, observed
	}
	for _, a := range CanaryDiff(map[string]map[string]string{id: observed}) {
		if strings.HasPrefix(a, id+" ") {
			alerts = append(alerts, a)
		}
	}
	return alerts, observed
}
