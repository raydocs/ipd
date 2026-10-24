package config

import "testing"

func TestDNSSessionsExplicitOptIn(t *testing.T) {
	for _, tc := range []struct {
		value   string
		enabled bool
	}{{"", false}, {"false", false}, {"invalid", false}, {"true", true}} {
		t.Setenv("IPD_DNS_SESSIONS_ENABLED", tc.value)
		if got := FromEnv().DNSSessionsEnabled; got != tc.enabled {
			t.Errorf("%q: enabled=%v", tc.value, got)
		}
	}
}
