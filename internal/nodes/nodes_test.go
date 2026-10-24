package nodes

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fake struct{}

func (fake) Check(ctx context.Context, name, socks string) (string, string, string, string, error) {
	if strings.Contains(name, "down") {
		return "", "", "", "", errDown
	}
	return "1.1.1.1", "A", "yes", "yes", nil
}

type downErr string

func (e downErr) Error() string { return string(e) }

const errDown downErr = "down"

func TestFiftyNodes(t *testing.T) {
	var b strings.Builder
	b.WriteString("proxies:\n")
	for i := 0; i < 50; i++ {
		name := "n"
		if i%7 == 0 {
			name = "down"
		}
		b.WriteString("- {name: " + name + itoa(i) + ", type: ss, server: 198.51.100." + itoa(i%200) + ", port: 443}\n")
	}
	f, err := Parse(b.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Proxies) != 50 {
		t.Fatal(len(f.Proxies))
	}
	start := time.Now()
	out, yml, err := Run(context.Background(), f, fake{}, nil, nil, 8)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 3*time.Minute {
		t.Fatal("slow")
	}
	if len(out) != 50 {
		t.Fatal(len(out))
	}
	down := 0
	for _, o := range out {
		if strings.Contains(o.Name, "down") {
			down++
			if o.Error != "unreachable" {
				t.Fatal(o)
			}
		}
	}
	if down == 0 {
		t.Fatal("no down nodes")
	}
	f2, err := Parse(yml)
	if err != nil {
		t.Fatal(err)
	}
	if len(f2.Proxies) != 50 {
		t.Fatalf("renamed %d\n%s", len(f2.Proxies), yml)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func TestMihomoMissing(t *testing.T) {
	m := &Mihomo{Bin: "/nonexistent/mihomo"}
	_, err := m.Start(context.Background(), "nope")
	if err == nil {
		t.Fatal("expected missing binary")
	}
}

func TestRenameYAMLPreservesConfigAndInput(t *testing.T) {
	const config = `
mixed-port: 7890
mode: rule
proxies:
  - name: alpha
    type: ss
    server: 198.51.100.1
    port: 443
    cipher: aes-128-gcm
    password: public-fixture-password
    plugin-opts: {mode: websocket, host: example.com}
  - {name: beta, type: vmess, server: 198.51.100.2, port: 443, uuid: 00000000-0000-4000-8000-000000000000, ws-opts: {path: /alpha, headers: {Host: example.org}}}
  - {name: unchanged, type: ss, server: 198.51.100.3, port: 443}
  - {name: missing, type: ss, server: 198.51.100.4, port: 443}
proxy-groups:
  - {name: inner, type: url-test, proxies: [alpha, beta, DIRECT, alpha], url: https://example.com/check, interval: 300, tolerance: 50}
  - {name: outer, type: select, proxies: [inner, beta, unchanged, missing, REJECT, external], icon: https://example.com/icon.png}
  - {name: provider, type: select, use: [subscription], filter: alpha}
  - {name: empty, type: select, proxies: []}
proxy-providers:
  subscription: {type: file, path: ./public-fixture.yaml}
rules: ["DOMAIN,example.com,outer", "MATCH,DIRECT"]
dns: {nameserver: [https://example.com/dns-query], fake-ip-filter: [alpha]}
`
	f := parseRenameFixture(t, config)
	before, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	outcomes := []Outcome{
		{Name: "alpha", Renamed: "renamed alpha"},
		{Name: "beta", Renamed: "renamed beta"},
		{Name: "unchanged"},
		{Name: "inner", Renamed: "not a node"},
		{Name: "DIRECT", Renamed: "not direct"},
		{Name: "REJECT", Renamed: "not reject"},
		{Name: "external", Renamed: "not external"},
	}
	got, err := RenameYAML(f, outcomes)
	if err != nil {
		t.Fatal(err)
	}
	want := parseRenameFixture(t, config)
	ps := want.Raw["proxies"].([]any)
	ps[0].(map[string]any)["name"] = "renamed alpha"
	ps[1].(map[string]any)["name"] = "renamed beta"
	gs := want.Raw["proxy-groups"].([]any)
	gs[0].(map[string]any)["proxies"] = []any{"renamed alpha", "renamed beta", "DIRECT", "renamed alpha"}
	gs[1].(map[string]any)["proxies"] = []any{"inner", "renamed beta", "unchanged", "missing", "REJECT", "external"}
	if parsed := parseRenameFixture(t, got); !reflect.DeepEqual(parsed.Raw, want.Raw) {
		t.Fatalf("config differs beyond node names and references:\n%s", got)
	}
	after, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("RenameYAML mutated File.Raw or File.Proxies")
	}
	assertRenameRepeatable(t, f, outcomes, got)
}

func TestRenameYAMLCollisions(t *testing.T) {
	const config = `
proxies:
  - {name: alpha, type: ss, server: 198.51.100.1, port: 443}
  - {name: beta, type: ss, server: 198.51.100.2, port: 443}
  - {name: keep, type: ss, server: 198.51.100.3, port: 443}
  - {name: shared (2), type: ss, server: 198.51.100.4, port: 443}
proxy-groups:
  - {name: group, type: select, proxies: [alpha, beta, keep, shared (2), DIRECT, REJECT, external]}
  - {name: group (2), type: select, proxies: [group, alpha]}
`
	type renameCase struct {
		name     string
		outcomes []Outcome
		want     []string
	}
	tests := []renameCase{
		{"duplicate generated names", []Outcome{{Name: "alpha", Renamed: "shared"}, {Name: "beta", Renamed: "shared"}}, []string{"shared", "shared (3)", "keep", "shared (2)"}},
		{"existing node", []Outcome{{Name: "alpha", Renamed: "keep"}}, []string{"keep (2)", "beta", "keep", "shared (2)"}},
		{"renamed source stays reserved", []Outcome{{Name: "alpha", Renamed: "beta"}, {Name: "beta", Renamed: "away"}}, []string{"beta (2)", "away", "keep", "shared (2)"}},
		{"swap", []Outcome{{Name: "alpha", Renamed: "beta"}, {Name: "beta", Renamed: "alpha"}}, []string{"beta (2)", "alpha (2)", "keep", "shared (2)"}},
		{"group", []Outcome{{Name: "alpha", Renamed: "group"}}, []string{"group (3)", "beta", "keep", "shared (2)"}},
		{"external target", []Outcome{{Name: "alpha", Renamed: "external"}}, []string{"external (2)", "beta", "keep", "shared (2)"}},
		{"unmatched outcome source", []Outcome{{Name: "alpha", Renamed: "pending"}, {Name: "pending", Renamed: "other"}}, []string{"pending (2)", "beta", "keep", "shared (2)"}},
		{"unchanged", []Outcome{{Name: "alpha", Renamed: "alpha"}, {Name: "beta"}}, []string{"alpha", "beta", "keep", "shared (2)"}},
		{"no outcomes", nil, []string{"alpha", "beta", "keep", "shared (2)"}},
	}
	for _, reserved := range []string{"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"} {
		tests = append(tests, renameCase{reserved, []Outcome{{Name: "alpha", Renamed: reserved}}, []string{reserved + " (2)", "beta", "keep", "shared (2)"}})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := parseRenameFixture(t, config)
			got, err := RenameYAML(f, tt.outcomes)
			if err != nil {
				t.Fatal(err)
			}
			want := parseRenameFixture(t, config)
			for i, p := range want.Raw["proxies"].([]any) {
				p.(map[string]any)["name"] = tt.want[i]
			}
			groups := want.Raw["proxy-groups"].([]any)
			groups[0].(map[string]any)["proxies"] = []any{tt.want[0], tt.want[1], tt.want[2], tt.want[3], "DIRECT", "REJECT", "external"}
			groups[1].(map[string]any)["proxies"] = []any{"group", tt.want[0]}
			if parsed := parseRenameFixture(t, got); !reflect.DeepEqual(parsed.Raw, want.Raw) {
				t.Fatalf("collision changed config unexpectedly:\n%s", got)
			}
			assertRenameRepeatable(t, f, tt.outcomes, got)
		})
	}
}

func TestRenameYAMLRejectsAmbiguousSources(t *testing.T) {
	for _, config := range []string{
		"proxies: [{name: duplicate}, {name: duplicate}]",
		"proxies: [{name: first}, {name: duplicate}, {name: duplicate}]",
		"proxies: [{name: duplicate}]\nproxy-groups: [{name: duplicate, proxies: [duplicate]}]",
		"proxies: [{name: DIRECT}]\nproxy-groups: [{name: group, proxies: [DIRECT]}]",
	} {
		f := parseRenameFixture(t, config)
		before, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		var outcomes []Outcome
		for _, p := range f.Proxies {
			outcomes = append(outcomes, Outcome{Name: p.Name, Renamed: "new"})
		}
		got, err := RenameYAML(f, outcomes)
		if err == nil || !strings.Contains(err.Error(), "ambiguous proxy name") || got != "" {
			t.Fatalf("ambiguous source should fail without output: got %q, err %v", got, err)
		}
		after, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		if string(before) != string(after) {
			t.Fatal("failed rename mutated input")
		}
	}
}

func parseRenameFixture(t *testing.T, text string) File {
	t.Helper()
	f, err := Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func assertRenameRepeatable(t *testing.T, f File, outcomes []Outcome, want string) {
	t.Helper()
	for _, input := range []File{f, parseRenameFixture(t, want)} {
		got, err := RenameYAML(input, outcomes)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("repeated rename differs:\n%s\nwant:\n%s", got, want)
		}
	}
}

func TestRenameYAMLPolicyReferences(t *testing.T) {
	const config = `
proxies:
  - {name: alpha, type: ss, server: 198.51.100.1, port: 443, password: public-fixture-password, dialer-proxy: beta}
  - {name: beta, type: ss, server: 198.51.100.2, port: 443, dialer-proxy: DIRECT}
  - {name: gamma, type: ss, server: 198.51.100.3, port: 443, dialer-proxy: group}
proxy-groups:
  - {name: group, type: select, proxies: [alpha, beta, DIRECT], filter: alpha}
rules:
  - DOMAIN,example.com,alpha
  - MATCH,alpha
  - DOMAIN,alpha,beta
  - IP-CIDR,198.51.100.0/24,alpha,no-resolve,src
  - RULE-SET,alpha,beta,no-resolve
  - AND,((DOMAIN,alpha),(OR,((NETWORK,tcp),(DOMAIN,beta)))),alpha
  - NOT,((DOMAIN,alpha)),beta
  - DOMAIN-REGEX,^alpha{1,3}\.example$,alpha
  - PROCESS-NAME-REGEX,alpha{1,3},beta
  - PROCESS-PATH-REGEX,/alpha{1,3}/beta,alpha
  - ' domain , alpha , beta ,alpha'
  - SUB-RULE,(DOMAIN,alpha),alpha
  - MATCH,group
  - MATCH,DIRECT
  - MATCH,REJECT
  - FUTURE,alpha,alpha
sub-rules:
  alpha:
    - DOMAIN,beta,alpha
    - MATCH,beta
    - SUB-RULE,(NETWORK,tcp),beta
  beta:
    - MATCH,DIRECT
proxy-providers:
  fixture:
    type: inline
    override: {dialer-proxy: alpha, additional-prefix: alpha}
    payload:
      - {name: provider-node, type: ss, server: 198.51.100.4, port: 443, dialer-proxy: beta, password: public-fixture-password}
  other:
    type: inline
    override: {dialer-proxy: group}
    payload: [{name: other-node, type: ss, dialer-proxy: DIRECT}]
rule-providers:
  alpha: {type: inline, behavior: domain, payload: [alpha, beta]}
dns: {fake-ip-filter: [alpha], nameserver-policy: {alpha: beta}}
custom: {dialer-proxy: alpha, rules: ["MATCH,alpha"]}
`
	f := parseRenameFixture(t, config)
	before, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	outcomes := []Outcome{{Name: "alpha", Renamed: "renamed alpha"}, {Name: "beta", Renamed: "renamed beta"}}
	got, err := RenameYAML(f, outcomes)
	if err != nil {
		t.Fatal(err)
	}
	want := parseRenameFixture(t, config)
	ps := want.Raw["proxies"].([]any)
	ps[0].(map[string]any)["name"] = "renamed alpha"
	ps[0].(map[string]any)["dialer-proxy"] = "renamed beta"
	ps[1].(map[string]any)["name"] = "renamed beta"
	want.Raw["proxy-groups"].([]any)[0].(map[string]any)["proxies"] = []any{"renamed alpha", "renamed beta", "DIRECT"}
	want.Raw["rules"] = []any{
		"DOMAIN,example.com,renamed alpha", "MATCH,renamed alpha", "DOMAIN,alpha,renamed beta",
		"IP-CIDR,198.51.100.0/24,renamed alpha,no-resolve,src", "RULE-SET,alpha,renamed beta,no-resolve",
		"AND,((DOMAIN,alpha),(OR,((NETWORK,tcp),(DOMAIN,beta)))),renamed alpha",
		"NOT,((DOMAIN,alpha)),renamed beta", `DOMAIN-REGEX,^alpha{1,3}\.example$,renamed alpha`,
		"PROCESS-NAME-REGEX,alpha{1,3},renamed beta", "PROCESS-PATH-REGEX,/alpha{1,3}/beta,renamed alpha",
		" domain , alpha , renamed beta ,alpha", "SUB-RULE,(DOMAIN,alpha),alpha",
		"MATCH,group", "MATCH,DIRECT", "MATCH,REJECT", "FUTURE,alpha,alpha",
	}
	want.Raw["sub-rules"].(map[string]any)["alpha"] = []any{"DOMAIN,beta,renamed alpha", "MATCH,renamed beta", "SUB-RULE,(NETWORK,tcp),beta"}
	provider := want.Raw["proxy-providers"].(map[string]any)["fixture"].(map[string]any)
	provider["override"].(map[string]any)["dialer-proxy"] = "renamed alpha"
	provider["payload"].([]any)[0].(map[string]any)["dialer-proxy"] = "renamed beta"
	if parsed := parseRenameFixture(t, got); !reflect.DeepEqual(parsed.Raw, want.Raw) {
		t.Fatalf("policy references or unrelated data differ:\n%s", got)
	}
	after, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("rewriting policy references mutated input")
	}
	assertRenameRepeatable(t, f, outcomes, got)
}

func TestRenameYAMLPolicyTargetsStayReserved(t *testing.T) {
	for _, references := range []string{
		"rules: ['DOMAIN,example.com,external', 'MATCH,alpha']",
		"sub-rules: {sub: ['MATCH,external', 'MATCH,alpha']}",
		"proxy-providers: {fixture: {override: {dialer-proxy: external}}}",
		"proxy-providers: {fixture: {payload: [{name: provider-node, dialer-proxy: external}]}}",
	} {
		f := parseRenameFixture(t, "proxies: [{name: alpha, dialer-proxy: DIRECT}]\n"+references)
		got, err := RenameYAML(f, []Outcome{{Name: "alpha", Renamed: "external"}})
		if err != nil {
			t.Fatal(err)
		}
		if parsed := parseRenameFixture(t, got); parsed.Proxies[0].Name != "external (2)" {
			t.Fatalf("external policy target shadowed:\n%s", got)
		}
		assertRenameRepeatable(t, f, []Outcome{{Name: "alpha", Renamed: "external"}}, got)
	}
	f := parseRenameFixture(t, "proxies: [{name: alpha}, {name: beta, dialer-proxy: external}]")
	got, err := RenameYAML(f, []Outcome{{Name: "alpha", Renamed: "external"}})
	if err != nil {
		t.Fatal(err)
	}
	parsed := parseRenameFixture(t, got)
	if parsed.Proxies[0].Name != "external (2)" || parsed.Proxies[1].Extra["dialer-proxy"] != "external" {
		t.Fatalf("external dialer target shadowed:\n%s", got)
	}
}

func TestRunResolvedRenameOutcomes(t *testing.T) {
	const config = `
proxies: [{name: alpha}, {name: beta}, {name: unchanged}]
proxy-groups: [{name: shared, proxies: [alpha, beta, unchanged, DIRECT]}]
rules: ["DOMAIN,example.com,alpha", "MATCH,beta"]
`
	for _, requested := range []string{"shared", "DIRECT", "", "alpha"} {
		t.Run(requested, func(t *testing.T) {
			f := parseRenameFixture(t, config)
			out, got, err := Run(context.Background(), f, fake{}, nil, func(o Outcome) string {
				if o.Name == "unchanged" {
					return o.Name
				}
				return requested
			}, 2)
			if err != nil {
				t.Fatal(err)
			}
			parsed := parseRenameFixture(t, got)
			if len(out) != len(parsed.Proxies) {
				t.Fatal("outcome count differs from YAML proxy count")
			}
			for i, p := range parsed.Proxies {
				if out[i].Renamed != p.Name || out[i].Name != f.Proxies[i].Name {
					t.Fatalf("outcome does not describe allocated name: %#v, YAML name %q", out[i], p.Name)
				}
			}
			wantRules := []any{"DOMAIN,example.com," + out[0].Renamed, "MATCH," + out[1].Renamed}
			if !reflect.DeepEqual(parsed.Raw["rules"], wantRules) {
				t.Fatalf("rule policies differ from resolved outcomes: %#v", parsed.Raw["rules"])
			}
			replay, err := RenameYAML(f, out)
			if err != nil || replay != got {
				t.Fatalf("resolved outcomes cannot reproduce YAML: %v\n%s", err, replay)
			}
		})
	}
}

func TestRenameYAMLRejectsUnencodableRuleTargets(t *testing.T) {
	for _, name := range []string{"bad,name", " bad", "bad ", "bad\nname", "bad\rname"} {
		t.Run(name, func(t *testing.T) {
			f := parseRenameFixture(t, "proxies: [{name: alpha}]\nrules: ['MATCH,alpha']")
			before, err := json.Marshal(f)
			if err != nil {
				t.Fatal(err)
			}
			got, err := RenameYAML(f, []Outcome{{Name: "alpha", Renamed: name}})
			if err == nil || !strings.Contains(err.Error(), "rule policy target") || got != "" {
				t.Fatalf("unencodable rule target should fail without output: got %q, err %v", got, err)
			}
			after, err := json.Marshal(f)
			if err != nil {
				t.Fatal(err)
			}
			if string(before) != string(after) {
				t.Fatal("rejected rule target mutated input")
			}
		})
	}
}
