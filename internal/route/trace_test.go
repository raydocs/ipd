package route

import "testing"

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
