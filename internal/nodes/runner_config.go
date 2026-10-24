package nodes

import (
	"errors"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

var (
	ErrRunnerConfig      = errors.New("invalid runner configuration")
	ErrRunnerUnsupported = errors.New("unsupported runner protocol or option")
)

const maxRunnerConfig = 4 << 20
const maxRunnerNodes = 64

// Inspect the original representation before map decoding can erase keys or
// expand aliases/merges. Even ignored global fields must pass this check.
func validRunnerYAML(n *yaml.Node) bool { return validRunnerYAMLDepth(n, 0) }
func validRunnerYAMLDepth(n *yaml.Node, depth int) bool {
	if depth > 64 {
		return false
	}
	switch n.Kind {
	case yaml.DocumentNode:
		return len(n.Content) == 1 && validRunnerYAMLDepth(n.Content[0], depth+1)
	case yaml.MappingNode:
		if n.Tag != "!!map" || len(n.Content)%2 != 0 {
			return false
		}
		seen := map[string]bool{}
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode || k.Tag != "!!str" || k.Value == "<<" || seen[k.Value] {
				return false
			}
			seen[k.Value] = true
			if !validRunnerYAMLDepth(n.Content[i+1], depth+1) {
				return false
			}
		}
		return true
	case yaml.SequenceNode:
		if n.Tag != "!!seq" {
			return false
		}
		for _, c := range n.Content {
			if !validRunnerYAMLDepth(c, depth+1) {
				return false
			}
		}
		return true
	case yaml.ScalarNode:
		switch n.Tag {
		case "!!str", "!!bool", "!!int", "!!float", "!!null":
			return true
		}
	}
	return false // Alias pointers are deliberately never followed.
}

func runnerDocument(data []byte) (map[string]any, error) {
	if len(data) > maxRunnerConfig {
		return nil, ErrRunnerConfig
	}
	d := yaml.NewDecoder(strings.NewReader(string(data)))
	var n, extra yaml.Node
	if d.Decode(&n) != nil || !validRunnerYAML(&n) || d.Decode(&extra) != io.EOF {
		return nil, ErrRunnerConfig
	}
	var doc map[string]any
	if n.Decode(&doc) != nil || doc == nil {
		return nil, ErrRunnerConfig
	}
	return doc, nil
}

// A deliberately bounded protocol subset. Unknown options (including nested
// options) fail closed instead of silently changing a transport or host route.
// All accepted values are forwarded unchanged, except the private proxy name.
type runnerFields map[string]func(any) bool

func runnerString(v any) bool { _, ok := v.(string); return ok }
func runnerBool(v any) bool   { _, ok := v.(bool); return ok }
func runnerInt(v any) bool    { _, ok := v.(int); return ok }
func runnerStrings(v any) bool {
	a, ok := v.([]any)
	if !ok {
		return false
	}
	for _, s := range a {
		if !runnerString(s) {
			return false
		}
	}
	return true
}
func runnerHeaders(v any) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	for _, v := range m {
		if !runnerString(v) {
			return false
		}
	}
	return true
}
func runnerObject(fields runnerFields) func(any) bool {
	return func(v any) bool {
		m, ok := v.(map[string]any)
		if !ok {
			return false
		}
		for k, v := range m {
			check, ok := fields[k]
			if !ok || !check(v) {
				return false
			}
		}
		return true
	}
}
func addRunnerFields(dst runnerFields, check func(any) bool, keys string) {
	for _, k := range strings.Fields(keys) {
		dst[k] = check
	}
}

func runnerProxyFields(protocol string) runnerFields {
	f := runnerFields{}
	addRunnerFields(f, runnerString, "name type server")
	addRunnerFields(f, runnerInt, "port")
	addRunnerFields(f, runnerBool, "udp tfo mptcp")
	switch protocol {
	case "vless", "vmess", "trojan":
		addRunnerFields(f, runnerString, "network client-fingerprint fingerprint name-cert-verify")
		addRunnerFields(f, runnerBool, "skip-cert-verify")
		f["alpn"] = runnerStrings
		f["ws-opts"] = runnerObject(runnerFields{"path": runnerString, "headers": runnerHeaders, "max-early-data": runnerInt, "early-data-header-name": runnerString, "v2ray-http-upgrade": runnerBool, "v2ray-http-upgrade-fast-open": runnerBool})
		f["grpc-opts"] = runnerObject(runnerFields{"grpc-service-name": runnerString})
		if protocol == "trojan" {
			addRunnerFields(f, runnerString, "password sni")
			break
		}
		addRunnerFields(f, runnerString, "uuid servername packet-encoding")
		addRunnerFields(f, runnerBool, "tls packet-addr xudp")
		f["reality-opts"] = runnerObject(runnerFields{"public-key": runnerString, "short-id": runnerString, "support-x25519mlkem768": runnerBool})
		f["http-opts"] = runnerObject(runnerFields{"method": runnerString, "path": runnerStrings, "headers": func(v any) bool {
			m, ok := v.(map[string]any)
			if !ok {
				return false
			}
			for _, v := range m {
				if !runnerStrings(v) {
					return false
				}
			}
			return true
		}})
		f["h2-opts"] = runnerObject(runnerFields{"host": runnerStrings, "path": runnerString})
		if protocol == "vless" {
			addRunnerFields(f, runnerString, "flow encryption")
		} else {
			addRunnerFields(f, runnerString, "cipher")
			addRunnerFields(f, runnerInt, "alterId")
			addRunnerFields(f, runnerBool, "global-padding authenticated-length")
		}
	case "hysteria2":
		addRunnerFields(f, runnerString, "password ports hop-interval up down obfs obfs-password sni fingerprint name-cert-verify")
		addRunnerFields(f, runnerBool, "skip-cert-verify")
		addRunnerFields(f, runnerInt, "obfs-min-packet-size obfs-max-packet-size cwnd udp-mtu handshake-timeout initial-stream-receive-window max-stream-receive-window initial-connection-receive-window max-connection-receive-window")
		addRunnerFields(f, runnerString, "bbr-profile")
		f["alpn"] = runnerStrings
	case "ss":
		addRunnerFields(f, runnerString, "password cipher client-fingerprint")
		addRunnerFields(f, runnerBool, "udp-over-tcp")
		addRunnerFields(f, runnerInt, "udp-over-tcp-version")
	default:
		return nil
	}
	return f
}

func runnerProxies(data []byte) ([]map[string]any, []string, error) {
	doc, err := runnerDocument(data)
	if err != nil {
		return nil, nil, err
	}
	raw, ok := doc["proxies"].([]any)
	if !ok || len(raw) == 0 || len(raw) > maxRunnerNodes {
		return nil, nil, ErrRunnerConfig
	}
	proxies := make([]map[string]any, 0, len(raw))
	names := make([]string, 0, len(raw))
	seen := map[string]bool{}
	for _, item := range raw {
		p, ok := item.(map[string]any)
		if !ok {
			return nil, nil, ErrRunnerConfig
		}
		name, nok := p["name"].(string)
		protocol, tok := p["type"].(string)
		server, sok := p["server"].(string)
		port, pok := p["port"].(int)
		if !nok || strings.TrimSpace(name) == "" || seen[name] || !tok || !sok || strings.TrimSpace(server) == "" || strings.ContainsAny(server, "/\\\x00\r\n") || !pok || port < 1 || port > 65535 {
			return nil, nil, ErrRunnerConfig
		}
		fields := runnerProxyFields(protocol)
		if fields == nil {
			return nil, nil, ErrRunnerUnsupported
		}
		for k, v := range p {
			check, ok := fields[k]
			if !ok {
				return nil, nil, ErrRunnerUnsupported
			}
			if !check(v) {
				return nil, nil, ErrRunnerUnsupported
			}
		}
		if network, ok := p["network"].(string); ok {
			switch network {
			case "", "tcp", "ws", "grpc":
			case "http", "h2":
				if protocol == "trojan" {
					return nil, nil, ErrRunnerUnsupported
				}
			default:
				return nil, nil, ErrRunnerUnsupported
			}
		}
		// Do not accept transport blocks that the selected network would ignore.
		for block, network := range map[string]string{"ws-opts": "ws", "grpc-opts": "grpc", "http-opts": "http", "h2-opts": "h2"} {
			if _, ok := p[block]; ok && p["network"] != network {
				return nil, nil, ErrRunnerUnsupported
			}
		}
		for _, key := range []string{"uuid", "password", "cipher"} {
			required := key == "uuid" && (protocol == "vless" || protocol == "vmess") || key == "password" && (protocol == "ss" || protocol == "trojan" || protocol == "hysteria2") || key == "cipher" && (protocol == "ss" || protocol == "vmess")
			if required && strings.TrimSpace(str(p[key])) == "" {
				return nil, nil, ErrRunnerConfig
			}
		}
		if protocol == "vmess" {
			if _, ok := p["alterId"].(int); !ok {
				return nil, nil, ErrRunnerConfig
			}
		}
		seen[name] = true
		names = append(names, name)
		p["name"] = "ipd-node"
		proxies = append(proxies, p)
	}
	return proxies, names, nil
}

func runnerConfig(proxy map[string]any, port int, user, password string) ([]byte, error) {
	return yaml.Marshal(map[string]any{
		"mode": "rule", "log-level": "silent", "allow-lan": false, "bind-address": "127.0.0.1",
		"find-process-mode": "off", "geo-auto-update": false, "ipv6": true,
		"dns": map[string]any{"enable": false}, "tun": map[string]any{"enable": false},
		"profile": map[string]any{"store-selected": false, "store-fake-ip": false},
		"proxies": []any{proxy}, "rules": []string{"MATCH,REJECT"},
		"listeners": []any{map[string]any{"name": "ipd-in", "type": "mixed", "listen": "127.0.0.1", "port": port, "udp": false, "proxy": "ipd-node", "users": []any{map[string]string{"username": user, "password": password}}}},
	})
}
