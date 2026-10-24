package privacy

import (
	"testing"
	"time"
)

func TestRedactPrivateAndHost(t *testing.T) {
	in := "egress 1.1.1.1 via 192.168.1.20 and 10.1.2.3 host mybox.local hostname laptop"
	out := Redact(in, []string{"laptop"})
	if stringsContains(out, "192.168.1.20") || stringsContains(out, "10.1.2.3") || stringsContains(out, "mybox.local") || stringsContains(out, "laptop") {
		t.Fatalf("redaction missed: %s", out)
	}
	if !stringsContains(out, "1.1.1.1") {
		t.Fatalf("public ip should remain: %s", out)
	}
}

func TestRetention(t *testing.T) {
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	old := now.Add(-8 * 24 * time.Hour)
	fresh := now.Add(-24 * time.Hour)
	if !Expired(old, now, Retention) {
		t.Fatal("8 day old log should expire")
	}
	if Expired(fresh, now, Retention) {
		t.Fatal("1 day old log should remain")
	}
}

func TestMetadataBlocked(t *testing.T) {
	if IsProbeTargetAllowed("169.254.169.254") || IsProbeTargetAllowed("127.0.0.1") || IsProbeTargetAllowed("10.0.0.5") || IsProbeTargetAllowed("192.168.0.1") {
		t.Fatal("reserved targets must be rejected")
	}
	if !IsProbeTargetAllowed("1.1.1.1") {
		t.Fatal("public ip allowed")
	}
}

func stringsContains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && (s == sub || len(s) > 0 && contains(s, sub)))
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
