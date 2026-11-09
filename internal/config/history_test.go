package config

import (
	"testing"
	"time"
)

func TestHistoryWindow(t *testing.T) {
	for _, tc := range []struct {
		env  string
		want time.Duration
	}{
		{"", DefaultHistoryRetention}, {"invalid", DefaultHistoryRetention}, {"0s", DefaultHistoryRetention}, {"-1h", DefaultHistoryRetention}, {"48h", 48 * time.Hour},
	} {
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv("IPD_HISTORY_RETENTION", tc.env)
			if got := FromEnv().HistoryWindow(); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
	if got := (*Config)(nil).HistoryWindow(); got != DefaultHistoryRetention {
		t.Fatal(got)
	}
}
