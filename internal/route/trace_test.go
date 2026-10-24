package route

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestParseTraceOutput(t *testing.T) {
	text := `
 1?: [LOCALHOST]                                         pmtu 1500
 1:  10.0.0.1                                            0.432ms
 2:  no reply
 3:  1.1.1.1                                             1.250ms reached
`
	hops := ParseTraceOutput(text)
	if len(hops) != 2 || hops[0].IP != "10.0.0.1" || hops[1].IP != "1.1.1.1" {
		t.Fatalf("%+v", hops)
	}
	if hops[1].RTTMS < 1 || hops[1].RTTMS > 1.3 {
		t.Fatal(hops[1].RTTMS)
	}
	tr := ParseTraceOutput(" 1  192.0.2.1  0.5 ms\n 2  * * *\n")
	if len(tr) != 2 || tr[0].IP != "192.0.2.1" || tr[1].IP != "*" {
		t.Fatalf("%+v", tr)
	}
}

func TestCommandTracePreservesPartialError(t *testing.T) {
	dir := t.TempDir()
	// A deterministic failing tracer emits a real hop before the failure.
	script := "#!/bin/sh\nprintf ' 1  203.0.113.1  12.5 ms\\n'\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "tracepath"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	hops, err := commandTrace(context.Background(), "192.0.2.1", 3)
	if err == nil || len(hops) != 1 || hops[0].IP != "203.0.113.1" || hops[0].RTTMS != 12.5 {
		t.Fatalf("hops=%+v err=%v", hops, err)
	}
}

func TestCommandTraceDestinationEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, output string
		wantErr      bool
	}{
		{"unreached", " 1  203.0.113.1  1 ms\\n", true},
		{"reached", " 1  203.0.113.1  1 ms\\n 2  192.0.2.1  2 ms\\n", false},
		{"timeouts", " 1  * * *\\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "tracepath"), []byte("#!/bin/sh\nprintf '"+tc.output+"'\n"), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir)
			hops, err := commandTrace(context.Background(), "192.0.2.1", 3)
			if (err != nil) != tc.wantErr || len(hops) == 0 {
				t.Fatalf("hops %+v err %v", hops, err)
			}
		})
	}
}
