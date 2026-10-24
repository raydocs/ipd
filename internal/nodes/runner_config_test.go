package nodes

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestRunnerRejectsOriginalYAMLKeysAndAliases(t *testing.T) {
	prefix := "proxies: [" + fixtureSS + "]\n"
	cases := []string{
		prefix + "global: {a: 1, a: 2}",
		prefix + `global: {"a": 1, "\u0061": 2}`,
		prefix + "global: {1: a, '1': b}",
		prefix + "global: {true: a}",
		prefix + "global: {? [a, b]: x}",
		prefix + "global: {<<: {a: 1}}",
		prefix + "global: {'<<': {a: 1}}",
		prefix + "global: &x {a: *x}",
		prefix + "one: &x token\ntwo: *x",
		prefix + "one: &x {a: b}\ntwo: *x",
		prefix + "global: !custom {a: b}",
		prefix + "global: {a: !custom b}",
		prefix + "---\nproxies: []",
		prefix + "global: " + strings.Repeat("[", 70) + "0" + strings.Repeat("]", 70),
		"proxies: [{name: alpha, name: beta, type: ss, server: alpha.invalid, port: 443}]",
		"proxies: [&x " + fixtureSS + ", *x]",
		prefix + "global: {!!int '1': x, '1': y}",
	}
	root := t.TempDir()
	for i, text := range cases {
		m := &ExecRunner{Bin: coreFixture(t), TempRoot: root}
		_, err := m.Start(context.Background(), runnerInputConfig(t, text))
		if !errors.Is(err, ErrRunnerConfig) {
			t.Errorf("case %d: %v", i, err)
		}
		assertRootClean(t, root)
	}
	// Anchor declarations alone do not alias data and need not be refused.
	if _, _, err := runnerProxies([]byte(prefix + "global: &x {a: b}")); err != nil {
		t.Fatal(err)
	}
}

func TestRunnerRejectsOriginalJSONDuplicateKeys(t *testing.T) {
	base := backendFixtureInput(BackendSingBox, "public-fixture")
	cases := []string{
		`{"outbounds":[],"outbounds":[]}`,
		`{"outbounds":[],"out\u0062ounds":[]}`,
		strings.TrimSuffix(base, "}") + `,"ignored":{"key":1,"k\u0065y":2}}`,
		strings.TrimSuffix(base, "}") + `,"ignored":[{"key":1,"key":2}]}`,
		strings.Replace(base, `"server_port":443`, `"server_port":443,"server_port":8443`, 1),
		strings.Replace(base, `"server_port":443`, `"server_port":443.1`, 1),
		strings.Replace(base, `"server_port":443`, `"server_port":9007199254740993`, 1),
		base + " {}", base + " trailing", `{"outbounds":`,
		strings.TrimSuffix(base, "}") + `,"ignored":` + strings.Repeat("[", 70) + `0` + strings.Repeat("]", 70) + `}`,
	}
	for i, text := range cases {
		if _, err := SelectBackend([]byte(text), BackendAuto); !errors.Is(err, ErrRunnerConfig) {
			t.Errorf("case %d: %v", i, err)
		}
	}
}

func TestRunnerUnsupportedNeverDropsPathFields(t *testing.T) {
	yamlDoc, err := runnerDocument([]byte(fixtureSubscription("public-fixture")))
	if err != nil {
		t.Fatal(err)
	}
	yamlBase := yamlDoc["proxies"].([]any)[0].(map[string]any)
	jsonDoc, err := runnerJSON([]byte(backendFixtureInput(BackendSingBox, "public-fixture")))
	if err != nil {
		t.Fatal(err)
	}
	jsonBase := jsonDoc["outbounds"].([]any)[0].(map[string]any)
	for _, backend := range []Backend{BackendMihomo, BackendSingBox} {
		var opts []map[string]any
		if backend == BackendMihomo {
			opts = []map[string]any{
				{"type": "hy2"}, {"type": "tuic"}, {"type": "anytls"}, {"type": "wireguard"}, {"type": "unknown"},
				{"dialer-proxy": "other-node"}, {"interface-name": "en0"}, {"routing-mark": 42}, {"ip-version": "ipv4"},
				{"plugin": "obfs", "plugin-opts": map[string]any{"mode": "tls"}},
				{"certificate": "/do-not-read"}, {"private-key": "/do-not-read"}, {"script": "do-not-run"},
				{"type": "vless", "uuid": "public-fixture", "network": "xhttp", "xhttp-opts": map[string]any{"path": "/fixture"}},
				{"type": "vless", "uuid": "public-fixture", "network": "ws", "ws-opts": map[string]any{"path": "/fixture", "unknown-path": true}},
			}
		} else {
			opts = []map[string]any{
				{"type": "hy2"}, {"type": "wireguard"}, {"type": "shadowtls"}, {"type": "unknown"},
				{"detour": "other-node"}, {"bind_interface": "en0"}, {"routing_mark": 42}, {"domain_resolver": "custom"},
				{"plugin": "obfs-local", "plugin_opts": "exec=do-not-run"},
				{"tls": map[string]any{"enabled": true, "certificate_path": "/do-not-read"}},
				{"type": "trojan", "transport": map[string]any{"type": "ws", "path": "/fixture", "unknown_path": true}},
			}
		}
		for _, opt := range opts {
			base := yamlBase
			if backend == BackendSingBox {
				base = jsonBase
			}
			p := maps.Clone(base)
			// Protocol swaps must not fail merely because old protocol fields remain.
			if protocol, ok := opt["type"].(string); ok && protocol != base["type"] {
				for k := range p {
					if k != "name" && k != "tag" && k != "type" && k != "server" && k != "port" && k != "server_port" {
						delete(p, k)
					}
				}
			}
			maps.Copy(p, opt)
			var data []byte
			if backend == BackendMihomo {
				data, _ = yaml.Marshal(map[string]any{"proxies": []any{p}})
			} else {
				data, _ = json.Marshal(map[string]any{"outbounds": []any{p}})
			}
			if _, err := SelectBackend(data, BackendAuto); !errors.Is(err, ErrRunnerUnsupported) {
				t.Errorf("%s option %v: %v", backend, opt, err)
			}
		}
	}
}

func TestRunnerMalformedNodesRejectedBeforeLaunch(t *testing.T) {
	for _, text := range []string{
		"proxies: []", "proxies: [null]", "proxies: [" + fixtureSS + ", " + fixtureSS + "]",
		"proxies: [" + strings.Replace(fixtureSS, "port: 443", "port: '443'", 1) + "]",
		"proxies: [" + strings.Replace(fixtureSS, "port: 443", "port: 0", 1) + "]",
		"proxies: [" + strings.Replace(fixtureSS, "port: 443", "port: 65536", 1) + "]",
		"proxies: [" + strings.Replace(fixtureSS, "password: public-fixture", "password: ''", 1) + "]",
		`{"outbounds":[]}`, `{"outbounds":[null]}`,
		`{"outbounds":[],"endpoints":[{"type":"wireguard"}]}`,
	} {
		if _, err := SelectBackend([]byte(text), BackendAuto); err == nil {
			t.Errorf("accepted malformed nodes: %s", text)
		}
	}
	if _, err := SelectBackend([]byte(strings.Repeat("a", maxRunnerConfig+1)), BackendAuto); !errors.Is(err, ErrRunnerConfig) {
		t.Fatal(err)
	}
	nodes := strings.TrimSuffix(strings.Repeat(fixtureSS+",", maxRunnerNodes+1), ",")
	if _, err := SelectBackend([]byte("proxies: ["+nodes+"]"), BackendAuto); !errors.Is(err, ErrRunnerConfig) {
		t.Fatal(err)
	}
}

type runnerMustNotCheck struct{ t *testing.T }

func (c runnerMustNotCheck) Check(context.Context, string, string) (string, string, string, string, error) {
	c.t.Error("checker called for unsafe input")
	return "", "", "", "", ErrRunnerConfig
}
func TestRunPreservesOriginalValidation(t *testing.T) {
	for _, text := range []string{
		"proxies: [" + fixtureSS + "]\none: &x token\ntwo: *x",
		"proxies: [" + fixtureSS + "]\none: {a: b}\n---\ntwo: ignored",
		"proxies: [" + fixtureSS + "]\nunknown: {'<<': {a: b}}",
	} {
		f, err := Parse(text)
		if err != nil {
			t.Fatal(err)
		} // Compatibility parser accepts these.
		m := &ExecRunner{Bin: coreFixture(t), TempRoot: t.TempDir()}
		if _, _, err := Run(context.Background(), f, runnerMustNotCheck{t}, m, nil, 1); !errors.Is(err, ErrRunnerConfig) {
			t.Fatalf("raw YAML validation lost by serialization: %v", err)
		}
	}
	f, err := Parse("ss://public-fixture@alpha.invalid:443#alpha")
	if err != nil {
		t.Fatal(err)
	}
	m := &ExecRunner{Bin: coreFixture(t)}
	if _, err := m.StartFile(context.Background(), f); !errors.Is(err, ErrRunnerUnsupported) {
		t.Fatalf("lossy legacy URI must not become a different connection: %v", err)
	}
}
