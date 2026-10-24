package app

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"

	"ipd/internal/config"
	"ipd/internal/nodes"
)

// Synthetic numeric response data only, never a server address, DNS name or dial
// target. All fixture sockets remain 127.0.0.1 and the helper enforces that.
func r1PublicPayload(n int) string { return fmt.Sprintf("11.22.33.%d", n) }

func TestCoreNodesR1NativeIdentity(t *testing.T) {
	bin := egressFixture(t)
	a, target := tlsEgressOrigin(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, r1PublicPayload(41)) })
	b, _ := tlsEgressOrigin(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, r1PublicPayload(42)) })
	cases := []struct {
		name          string
		backend       nodes.Backend
		first, second string
	}{
		{"json_literal_nel", nodes.BackendSingBox, "left\u0085right", "left right"},
		{"json_escaped_nel", nodes.BackendSingBox, `left\u0085right`, "left right"},
		{"json_line_separator", nodes.BackendSingBox, "left\u2028right", "left right"},
		{"json_paragraph_separator", nodes.BackendSingBox, "left\u2029right", "left right"},
		{"json_unpaired_high_surrogate", nodes.BackendSingBox, `left\ud800right`, "left right"},
		{"json_unpaired_low_surrogate", nodes.BackendSingBox, `left\udc00right`, "left right"},
		{"json_invalid_utf8", nodes.BackendSingBox, "left\xffright", "left right"},
		// YAML's native quoted-line folding is intentional. The runner and app must
		// both use that interpretation, not JSON rules or a shared normalization.
		{"yaml_literal_vs_escaped_nel", nodes.BackendMihomo, "left\u0085right", `left\u0085right`},
		{"yaml_folded_line_vs_escaped_nel", nodes.BackendMihomo, "left\nright", `left\u0085right`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := nativeEgressInput(tc.backend, []string{a.Listener.Addr().String(), b.Listener.Addr().String()})
			raw = strings.Replace(raw, "z-secret-name", tc.first, 1)
			raw = strings.Replace(raw, "a-secret-name1", tc.second, 1)
			rep, err := New(&config.Config{}, nil).coreNodes(context.Background(), raw, CoreNodeOptions{Backend: tc.backend, MihomoBin: bin, SingBoxBin: bin}, target)
			if err != nil {
				t.Fatalf("native metadata decode rejected runner-valid input: %v", err)
			}
			rows := egressRows(t, rep)
			if len(rows) != 2 || rep.Data.(map[string]any)["measurement_status"] != "completed" {
				t.Fatal("native identity batch not completed")
				return
			}
			for i, row := range rows {
				if row.Index != i+1 || row.Backend != tc.backend || row.Status != "observed" || row.EgressIP != r1PublicPayload(41+i) {
					t.Errorf("wrong original index/backend/egress attribution at index %d", i+1)
				}
			}
		})
	}
	assertEgressReaped(t, bin, 2*len(cases))
}

func TestCoreNodesR1RejectNonPublicAndScopedPayload(t *testing.T) {
	bin := egressFixture(t)
	cases := []struct{ name, body string }{
		{"cgnat", "100.64.0.1"}, {"benchmark", "198.18.0.1"}, {"reserved_v4", "240.0.0.1"},
		{"documentation_v4", "192.0.2.1"}, {"documentation_v6", "2001:db8::1"}, {"documentation_v6_new", "3fff::1"},
		{"benchmark_v6", "2001:2::1"}, {"reserved_v6", "4000::1"}, {"reserved_in_global_unicast", "2d00::1"},
		{"mapped_cgnat", "::ffff:100.64.0.1"}, {"mapped_benchmark", "::ffff:198.18.0.1"}, {"mapped_reserved", "::ffff:240.0.0.1"},
		{"mapped_documentation", "::ffff:192.0.2.1"},
		{"zone_credential", "2600:1234:5678:9abc::def0%secret-endpoint/password"},
		{"mapped_zone_credential", "::ffff:" + r1PublicPayload(41) + "%secret-endpoint/password"},
	}
	good, _ := tlsEgressOrigin(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, r1PublicPayload(41)) })
	launches := 0
	for _, backend := range []nodes.Backend{nodes.BackendMihomo, nodes.BackendSingBox} {
		for _, tc := range cases {
			t.Run(string(backend)+"/"+tc.name, func(t *testing.T) {
				bad, target := tlsEgressOrigin(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, tc.body) })
				raw := nativeEgressInput(backend, []string{good.Listener.Addr().String(), bad.Listener.Addr().String()})
				// Capture the app's stdout, stderr and standard logger, not just Report JSON.
				// A failed assertion never echoes the raw response/credential itself.
				rep, err, output := r1CaptureCoreOutput(t, func() (Report, error) {
					return New(&config.Config{}, nil).coreNodes(context.Background(), raw, CoreNodeOptions{Backend: backend, MihomoBin: bin, SingBoxBin: bin}, target)
				})
				launches += 2
				if err != nil {
					t.Error("invalid response escaped as an app error")
				}
				encoded, e := json.Marshal(rep)
				if e != nil {
					t.Fatal(e)
				}
				for _, surface := range []string{string(encoded), output, fmt.Sprint(err)} {
					if strings.Contains(surface, "secret-endpoint") || strings.Contains(surface, "password") {
						t.Error("response credential leaked to public output/error/log")
					}
				}
				if rep.Verdict != "abstain" || rep.Data.(map[string]any)["measurement_status"] != "unavailable" {
					t.Error("non-public/scoped response published as a completed batch")
				}
				for _, row := range egressRows(t, rep) {
					if row.Status != "unknown" || row.EgressIP != "" || row.Reason == "" {
						t.Error("invalid/partial batch retained an observation")
					}
				}
			})
		}
	}
	assertEgressReaped(t, bin, launches)
}

func r1CaptureCoreOutput(t *testing.T, run func() (Report, error)) (Report, error, string) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "app-output")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	oldOut, oldErr, oldLog := os.Stdout, os.Stderr, log.Writer()
	os.Stdout, os.Stderr = f, f
	log.SetOutput(f)
	defer func() { os.Stdout, os.Stderr = oldOut, oldErr; log.SetOutput(oldLog) }()
	rep, e := run()
	b, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	return rep, e, string(b)
}

// Pure classification examples are numeric policy inputs, not hosts or routing
// evidence. In particular documentation ranges are negative cases, never bypasses.
func TestCoreNodesR1PublicPolicy(t *testing.T) {
	nonPublicV4 := []string{
		"0.0.0.0", "0.255.255.255", "10.0.0.0", "10.255.255.255",
		"100.64.0.0", "100.127.255.255", "127.0.0.0", "127.255.255.255",
		"169.254.0.0", "169.254.255.255", "172.16.0.0", "172.31.255.255",
		"192.0.0.0", "192.0.0.255", "192.0.2.0", "192.0.2.255",
		"192.31.196.0", "192.31.196.255", "192.52.193.0", "192.52.193.255",
		"192.88.99.0", "192.88.99.255", "192.168.0.0", "192.168.255.255",
		"192.175.48.0", "192.175.48.255", "198.18.0.0", "198.19.255.255",
		"198.51.100.0", "198.51.100.255", "203.0.113.0", "203.0.113.255",
		"224.0.0.0", "239.255.255.255", "240.0.0.0", "255.255.255.255",
	}
	for _, text := range nonPublicV4 {
		for _, input := range []string{text, "::ffff:" + text} {
			if ip, ok := publicCoreEgressIP(input); ok || ip.IsValid() {
				t.Errorf("non-public IPv4/mapped numeric policy example accepted: %s", input)
			}
		}
	}
	nonPublicV6 := []string{
		"::", "::1", "::192.0.2.1", "64:ff9b::c000:201", "64:ff9b:1::1",
		"100::1", "100:0:0:1::1", "2001::1", "2001:1::1", "2001:2::1",
		"2001:10::1", "2001:20::1", "2001:30::1", "2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff",
		"2002::1", "2620:4f:8000::", "2620:4f:8000:ffff:ffff:ffff:ffff:ffff",
		"2d00::1", "3000::1", "3ffe::1", "3fff::1", "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff",
		"4000::1", "5f00::1", "fc00::1", "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "fe80::1", "fec0::1", "ff02::1",
		// Unallocated gaps even inside 2000::/3 fail closed, not just explicit docs.
		"2000::1", "2001:1000::1", "2001:4e00::1", "2003:4000::1", "2420::1", "261f::1",
	}
	for _, text := range nonPublicV6 {
		if ip, ok := publicCoreEgressIP(text); ok || ip.IsValid() {
			t.Errorf("non-public IPv6 numeric policy example accepted: %s", text)
		}
	}
	for _, input := range []string{"", "not-an-IP", r1PublicPayload(41) + "/32", "2600:1234:5678:9abc::def0%opaque-zone", "::ffff:" + r1PublicPayload(41) + "%opaque-zone"} {
		if ip, ok := publicCoreEgressIP(input); ok || ip.IsValid() {
			t.Error("invalid or scoped payload accepted")
		}
	}
	for _, text := range []string{r1PublicPayload(41), "100.63.255.255", "100.128.0.0", "198.17.255.255", "198.20.0.0", "192.0.1.0", "192.0.3.0", "223.255.255.254"} {
		for _, input := range []string{text, "::ffff:" + text} {
			if ip, ok := publicCoreEgressIP(input); !ok || ip.String() != text || !ip.Is4() || ip.Zone() != "" {
				t.Errorf("ordinary public IPv4/mapped numeric policy example rejected: %s", input)
			}
		}
	}
	for _, text := range []string{"2001:200::1234", "2001:3fff:ffff:ffff:ffff:ffff:ffff:ffff", "2001:bfff:ffff:ffff:ffff:ffff:ffff:ffff", "2003:3fff:ffff:ffff:ffff:ffff:ffff:ffff", "2410:1234::5678", "2600:1234:5678:9abc::def0", "2630:1234::5678", "2a10:1234::5678", "2c00:1234::5678"} {
		if ip, ok := publicCoreEgressIP(text); !ok || !ip.Is6() || ip.Zone() != "" {
			t.Errorf("ordinary allocated IPv6 numeric policy example rejected: %s", text)
		}
	}
}

func TestCoreNodesR1PublicPayloadForms(t *testing.T) {
	bin := egressFixture(t)
	cases := []struct{ name, body, want string }{
		{"numeric_v4", r1PublicPayload(41), r1PublicPayload(41)},
		{"mapped_numeric_v4", "::ffff:" + r1PublicPayload(42), r1PublicPayload(42)},
		{"numeric_v6", "2600:1234:5678:9abc::def0", "2600:1234:5678:9abc::def0"},
	}
	for _, backend := range []nodes.Backend{nodes.BackendMihomo, nodes.BackendSingBox} {
		for _, tc := range cases {
			t.Run(string(backend)+"/"+tc.name, func(t *testing.T) {
				origin, target := tlsEgressOrigin(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, tc.body) })
				rep, err := New(&config.Config{}, nil).coreNodes(context.Background(), nativeEgressInput(backend, []string{origin.Listener.Addr().String()}), CoreNodeOptions{Backend: backend, MihomoBin: bin, SingBoxBin: bin}, target)
				if err != nil {
					t.Fatal(err)
				}
				rows := egressRows(t, rep)
				if len(rows) != 1 || rows[0].Index != 1 || rows[0].Backend != backend || rows[0].Status != "observed" || rows[0].EgressIP != tc.want {
					t.Fatal("synthetic ordinary public payload rejected or attributed incorrectly")
				}
			})
		}
	}
	assertEgressReaped(t, bin, 2*len(cases))
}
