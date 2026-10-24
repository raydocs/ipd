package route

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

var fixtureDestination = netip.MustParseAddr("192.0.2.10")
var fixtureRouter = netip.MustParseAddr("198.51.100.1")

func fixtureProbe(protocol byte) rawProbe {
	return rawProbe{destination: fixtureDestination, protocol: protocol, echoID: 0x1234, echoSeq: 7, token: []byte("fixture-token-16"), sourcePort: 40007, destinationPort: 443, tcpSeq: 0x12345678}
}
func fixtureChecksum(b []byte) uint16 {
	var sum uint32
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) > 0 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
func fixtureICMP(typ, code byte, body []byte) []byte {
	b := make([]byte, 8)
	b[0], b[1] = typ, code
	b = append(b, body...)
	binary.BigEndian.PutUint16(b[2:4], fixtureChecksum(b))
	return b
}
func fixtureEcho(p rawProbe) []byte {
	b := fixtureICMP(0, 0, p.token)
	binary.BigEndian.PutUint16(b[4:6], p.echoID)
	binary.BigEndian.PutUint16(b[6:8], p.echoSeq)
	b[2], b[3] = 0, 0
	binary.BigEndian.PutUint16(b[2:4], fixtureChecksum(b))
	return b
}
func fixtureIPv4(proto byte, src, dst netip.Addr, ihl int, payload []byte) []byte {
	b := make([]byte, ihl)
	b[0] = 0x40 | byte(ihl/4)
	binary.BigEndian.PutUint16(b[2:4], uint16(ihl+len(payload)))
	b[8], b[9] = 1, proto
	copy(b[12:16], src.AsSlice())
	copy(b[16:20], dst.AsSlice())
	return append(b, payload...)
}
func fixtureQuote(p rawProbe, ihl int) []byte {
	var payload []byte
	if p.protocol == 1 {
		payload = fixtureEcho(p)
		payload[0] = 8
		payload[2], payload[3] = 0, 0
		binary.BigEndian.PutUint16(payload[2:4], fixtureChecksum(payload))
	} else {
		payload = make([]byte, 20)
		binary.BigEndian.PutUint16(payload[:2], p.sourcePort)
		binary.BigEndian.PutUint16(payload[2:4], p.destinationPort)
		binary.BigEndian.PutUint32(payload[4:8], p.tcpSeq)
		payload[12] = 5 << 4
		payload[13] = 2
	}
	return fixtureIPv4(p.protocol, netip.MustParseAddr("192.0.2.20"), p.destination, ihl, payload)
}
func fixtureError(typ, code byte, quote []byte) []byte { return fixtureICMP(typ, code, quote) }

func TestProbeReplyCorrelation(t *testing.T) {
	echo := fixtureProbe(1)
	tcp := fixtureProbe(6)
	type testCase struct {
		name               string
		probe              rawProbe
		peer               netip.Addr
		packet             []byte
		hop, done, wantErr bool
	}
	cases := []testCase{
		{"correct echo", echo, fixtureDestination, fixtureEcho(echo), true, true, false},
		{"wrong echo source", echo, fixtureRouter, fixtureEcho(echo), false, false, false},
		{"TCP cannot complete on echo", tcp, fixtureDestination, fixtureEcho(echo), false, false, false},
		{"echo without token", echo, fixtureDestination, fixtureEcho(rawProbe{echoID: echo.echoID, echoSeq: echo.echoSeq}), false, false, false},
		{"truncated echo", echo, fixtureDestination, []byte{0, 0}, false, false, false},
	}
	for _, protocol := range []byte{1, 6} {
		p := fixtureProbe(protocol)
		for _, ihl := range []int{20, 24, 60} {
			q := fixtureQuote(p, ihl)
			cases = append(cases, testCase{fmt.Sprintf("protocol=%d/IHL=%d quoted time exceeded", protocol, ihl), p, fixtureRouter, fixtureError(11, 0, q[:ihl+8]), true, false, false})
		}
		cases = append(cases,
			testCase{"full quote", p, fixtureRouter, fixtureError(11, 0, fixtureQuote(p, 20)), true, false, false},
			testCase{"target time exceeded is not completion", p, fixtureDestination, fixtureError(11, 0, fixtureQuote(p, 20)), true, false, false},
			testCase{"target unreachable is error not completion", p, fixtureDestination, fixtureError(3, 3, fixtureQuote(p, 20)), true, false, true},
			testCase{"router unreachable is error", p, fixtureRouter, fixtureError(3, 1, fixtureQuote(p, 20)), true, false, true},
			testCase{"reassembly timeout ignored", p, fixtureRouter, fixtureError(11, 1, fixtureQuote(p, 20)), false, false, false},
		)
		type mutation struct {
			name   string
			change func([]byte)
		}
		mutations := []mutation{
			{"wrong version", func(q []byte) { q[0] = 0x65 }},
			{"short IHL", func(q []byte) { q[0] = 0x44 }},
			{"IHL exceeds quote", func(q []byte) { q[0] = 0x4f }},
			{"wrong protocol", func(q []byte) { q[9] = 17 }},
			{"wrong destination", func(q []byte) { q[19]++ }},
			{"fragment offset", func(q []byte) { q[7] = 1 }},
			{"first fragment", func(q []byte) { q[6] = 0x20 }},
			{"short declared length", func(q []byte) { binary.BigEndian.PutUint16(q[2:4], 27) }},
			{"only identifiers declared", func(q []byte) { binary.BigEndian.PutUint16(q[2:4], 28) }},
		}
		if protocol == 1 {
			mutations = append(mutations,
				mutation{"wrong ID", func(q []byte) { q[24]++ }},
				mutation{"late sequence", func(q []byte) { q[27]-- }},
				mutation{"quoted echo reply", func(q []byte) { q[20] = 0 }},
				mutation{"quoted echo code", func(q []byte) { q[21] = 1 }},
				mutation{"quoted token mismatch", func(q []byte) { q[28]++ }},
			)
		} else {
			mutations = append(mutations,
				mutation{"wrong source port", func(q []byte) { q[21]++ }},
				mutation{"wrong destination port", func(q []byte) { q[23]++ }},
				mutation{"late TCP sequence", func(q []byte) { q[27]-- }},
			)
		}
		for _, m := range mutations {
			q := fixtureQuote(p, 20)
			m.change(q)
			cases = append(cases, testCase{fmt.Sprintf("protocol=%d/%s", protocol, m.name), p, fixtureRouter, fixtureError(11, 0, q), false, false, false})
		}
		for n := 28; n < len(fixtureQuote(p, 20)); n++ {
			cases = append(cases, testCase{fmt.Sprintf("protocol=%d/partial quote=%d", protocol, n), p, fixtureRouter, fixtureError(11, 0, fixtureQuote(p, 20)[:n]), true, false, false})
		}
		for n := 0; n < 28; n++ {
			cases = append(cases, testCase{fmt.Sprintf("protocol=%d/truncated quote=%d", protocol, n), p, fixtureRouter, fixtureError(11, 0, fixtureQuote(p, 20)[:n]), false, false, false})
		}
	}
	for _, change := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"wrong echo ID", func(b []byte) { b[4]++ }}, {"late echo sequence", func(b []byte) { b[7]-- }}, {"wrong echo code", func(b []byte) { b[1] = 1 }}, {"wrong token", func(b []byte) { b[8]++ }},
	} {
		b := fixtureEcho(echo)
		change.mutate(b)
		b[2], b[3] = 0, 0
		binary.BigEndian.PutUint16(b[2:4], fixtureChecksum(b))
		cases = append(cases, testCase{change.name, echo, fixtureDestination, b, false, false, false})
	}
	b := fixtureEcho(echo)
	b[2]++
	cases = append(cases, testCase{"bad ICMP checksum", echo, fixtureDestination, b, false, false, false})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hop, done, err := parseProbeReply(tc.packet, tc.peer, tc.probe)
			if (hop.IP != "") != tc.hop || done != tc.done || (err != nil) != tc.wantErr {
				t.Fatalf("hop=%+v done=%v err=%v; want hop=%v done=%v err=%v", hop, done, err, tc.hop, tc.done, tc.wantErr)
			}
			if tc.hop && hop.IP != tc.peer.String() {
				t.Fatal(hop)
			}
		})
	}
}
func TestRawProbeReplyRejectsUnrelatedEcho(t *testing.T) {
	p := fixtureProbe(6)
	packet := fixtureIPv4(1, fixtureDestination, netip.MustParseAddr("192.0.2.20"), 20, fixtureEcho(fixtureProbe(1)))
	hop, done, err := parseRawProbeReply(packet, p)
	if hop.IP != "" || done || err != nil {
		t.Fatalf("unrelated EchoReply accepted: hop=%+v done=%v err=%v", hop, done, err)
	}
}

func TestRawProbeReplyIPv4Envelope(t *testing.T) {
	p := fixtureProbe(6)
	message := fixtureError(11, 0, fixtureQuote(p, 24))
	valid := fixtureIPv4(1, fixtureRouter, netip.MustParseAddr("192.0.2.20"), 24, message)
	for n := 0; n < len(valid); n++ {
		hop, done, err := parseRawProbeReply(valid[:n], p)
		if hop.IP != "" || done || err != nil {
			t.Fatalf("truncated at %d: hop=%+v done=%v err=%v", n, hop, done, err)
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"version", func(b []byte) { b[0] = 0x66 }},
		{"IHL", func(b []byte) { b[0] = 0x44 }},
		{"protocol", func(b []byte) { b[9] = 6 }},
		{"fragment", func(b []byte) { b[7] = 1 }},
		{"more fragments", func(b []byte) { b[6] = 0x20 }},
		{"length", func(b []byte) { binary.BigEndian.PutUint16(b[2:4], 27) }},
		{"checksum", func(b []byte) { b[26]++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := append([]byte(nil), valid...)
			tc.mutate(b)
			hop, done, err := parseRawProbeReply(b, p)
			if hop.IP != "" || done || err != nil {
				t.Fatalf("hop=%+v done=%v err=%v", hop, done, err)
			}
		})
	}
	hop, done, err := parseRawProbeReply(valid, p)
	if hop.IP != fixtureRouter.String() || done || err != nil {
		t.Fatalf("valid: hop=%+v done=%v err=%v", hop, done, err)
	}
}

func TestAwaitProbeReplyDeadlineIgnoresNoise(t *testing.T) {
	for _, raw := range []bool{false, true} {
		t.Run(fmt.Sprintf("raw=%v", raw), func(t *testing.T) {
			p := fixtureProbe(6)
			start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			current := start
			calls := 0
			parse := func(b []byte, peer netip.Addr) (Hop, bool, error) {
				if raw {
					return parseRawProbeReply(b, p)
				}
				return parseProbeReply(b, peer, p)
			}
			hop, done, err := awaitProbeReply(context.Background(), 450*time.Millisecond, func() time.Time { return current }, func(deadline time.Time) ([]byte, netip.Addr, error) {
				calls++
				if deadline.After(start.Add(450*time.Millisecond)) || deadline.After(current.Add(25*time.Millisecond)) {
					t.Fatalf("deadline extended: %v", deadline.Sub(start))
				}
				current = current.Add(5 * time.Millisecond)
				b := fixtureEcho(fixtureProbe(1))
				if raw {
					b = fixtureIPv4(1, fixtureDestination, netip.MustParseAddr("192.0.2.20"), 20, b)
				}
				return b, fixtureDestination, nil
			}, parse)
			if !errors.Is(err, errRawProbeTimeout) || hop.IP != "" || done || calls != 90 || current.Sub(start) != 450*time.Millisecond {
				t.Fatalf("hop=%+v done=%v err=%v calls=%d elapsed=%v", hop, done, err, calls, current.Sub(start))
			}
		})
	}
}

func TestAwaitProbeReplyRetainsValidReplyAfterNoise(t *testing.T) {
	for _, protocol := range []byte{1, 6} {
		p := fixtureProbe(protocol)
		for _, typ := range []byte{11, 3} {
			t.Run(fmt.Sprintf("protocol=%d/type=%d", protocol, typ), func(t *testing.T) {
				current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
				calls := 0
				old := p
				old.echoSeq--
				old.tcpSeq--
				hop, done, err := awaitProbeReply(context.Background(), 450*time.Millisecond, func() time.Time { return current }, func(time.Time) ([]byte, netip.Addr, error) {
					calls++
					current = current.Add(time.Millisecond)
					switch calls {
					case 1:
						return nil, netip.Addr{}, syscall.EINTR
					case 2:
						return nil, netip.Addr{}, errRawProbeTimeout
					case 3:
						return fixtureError(11, 0, fixtureQuote(old, 20)), fixtureRouter, nil
					case 4:
						return fixtureError(typ, 0, fixtureQuote(p, 20)), fixtureRouter, nil
					default:
						t.Fatal("lost valid reply")
						return nil, netip.Addr{}, nil
					}
				}, func(b []byte, peer netip.Addr) (Hop, bool, error) { return parseProbeReply(b, peer, p) })
				if calls != 4 || hop.IP != fixtureRouter.String() || done || (err != nil) != (typ == 3) {
					t.Fatalf("calls=%d hop=%+v done=%v err=%v", calls, hop, done, err)
				}
			})
		}
	}
}

func TestAwaitProbeReplyCancellationAndReadError(t *testing.T) {
	p := fixtureProbe(1)
	parse := func(b []byte, peer netip.Addr) (Hop, bool, error) { return parseProbeReply(b, peer, p) }
	for _, before := range []bool{true, false} {
		t.Run(fmt.Sprintf("cancel-before=%v", before), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			if before {
				cancel()
			}
			hop, done, err := awaitProbeReply(ctx, time.Second, time.Now, func(time.Time) ([]byte, netip.Addr, error) {
				calls++
				cancel()
				return nil, netip.Addr{}, errRawProbeTimeout
			}, parse)
			if !errors.Is(err, context.Canceled) || hop.IP != "" || done || (before && calls != 0) || (!before && calls != 1) {
				t.Fatalf("calls=%d hop=%+v done=%v err=%v", calls, hop, done, err)
			}
		})
	}
	want := errors.New("fixture read failure")
	hop, done, err := awaitProbeReply(context.Background(), time.Second, time.Now, func(time.Time) ([]byte, netip.Addr, error) { return nil, netip.Addr{}, want }, parse)
	if !errors.Is(err, want) || hop.IP != "" || done {
		t.Fatalf("hop=%+v done=%v err=%v", hop, done, err)
	}
}

func TestAwaitProbeReplyContextDeadlineCapsBudget(t *testing.T) {
	start := time.Now()
	current := start
	ctx, cancel := context.WithDeadline(context.Background(), start.Add(10*time.Second))
	defer cancel()
	_, _, err := awaitProbeReply(ctx, 20*time.Second, func() time.Time { return current }, func(deadline time.Time) ([]byte, netip.Addr, error) {
		if deadline.After(start.Add(10 * time.Second)) {
			t.Fatal("ignored context deadline")
		}
		current = deadline
		return nil, netip.Addr{}, errRawProbeTimeout
	}, func([]byte, netip.Addr) (Hop, bool, error) { t.Fatal("parsed timeout"); return Hop{}, false, nil })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
}
