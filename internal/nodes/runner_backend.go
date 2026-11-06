package nodes

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"strings"
)

// Backend is selected before launching a process. There is no runtime fallback.
type Backend string

const (
	BackendAuto    Backend = ""
	BackendMihomo  Backend = "mihomo"
	BackendSingBox Backend = "sing-box"
)

// coreBackend separates core-specific parsing/config/argv from process lifetime.
// Each implementation must reject fields it cannot safely preserve.
type coreBackend interface {
	ID() Backend
	Nodes([]byte) ([]map[string]any, []string, error)
	Config(map[string]any, int, string, string) ([]byte, error)
	Args(string, string) []string
	Extension() string
}
type mihomoBackend struct{}

func (mihomoBackend) ID() Backend                                        { return BackendMihomo }
func (mihomoBackend) Nodes(b []byte) ([]map[string]any, []string, error) { return runnerProxies(b) }
func (mihomoBackend) Config(p map[string]any, port int, u, pw string) ([]byte, error) {
	return runnerConfig(p, port, u, pw)
}
func (mihomoBackend) Args(dir, file string) []string { return []string{"-d", dir, "-f", file} }
func (mihomoBackend) Extension() string              { return ".yaml" }

type singBoxBackend struct{}

func (singBoxBackend) ID() Backend                                        { return BackendSingBox }
func (singBoxBackend) Nodes(b []byte) ([]map[string]any, []string, error) { return singBoxProxies(b) }
func (singBoxBackend) Args(dir, file string) []string                     { return []string{"run", "-D", dir, "-c", file} }
func (singBoxBackend) Extension() string                                  { return ".json" }
func (singBoxBackend) Config(p map[string]any, port int, u, pw string) ([]byte, error) {
	return json.Marshal(map[string]any{
		"log":       map[string]any{"disabled": true},
		"inbounds":  []any{map[string]any{"type": "mixed", "tag": "ipd-in", "listen": "127.0.0.1", "listen_port": port, "set_system_proxy": false, "users": []any{map[string]string{"username": u, "password": pw}}}},
		"outbounds": []any{p},
		// A single outbound and an explicit final leave no DIRECT/default escape.
		"route": map[string]any{"final": "ipd-node", "auto_detect_interface": false},
	})
}

// SelectBackend validates the entire input and the supported protocol subset
// without starting a process. YAML defaults to mihomo, JSON to sing-box. A
// forced incompatible format returns unsupported: this increment does not
// translate protocol/config semantics between cores.
func SelectBackend(data []byte, requested Backend) (Backend, error) {
	driver, _, _, err := prepareRunner(data, requested)
	if err != nil {
		return BackendAuto, err
	}
	return driver.ID(), nil
}
func prepareRunner(data []byte, requested Backend) (coreBackend, []map[string]any, []string, error) {
	if len(data) > maxRunnerConfig {
		return nil, nil, nil, ErrRunnerConfig
	}
	text := bytes.TrimSpace(data)
	if len(text) == 0 {
		return nil, nil, nil, ErrRunnerConfig
	}
	// JSON requires quoted object keys. Plain-key YAML flow maps remain YAML;
	// malformed quoted JSON is never retried through the permissive YAML parser.
	jsonInput := text[0] == '[' || text[0] == '{' && (len(bytes.TrimSpace(text[1:])) == 0 || bytes.TrimSpace(text[1:])[0] == '"' || bytes.TrimSpace(text[1:])[0] == '}')
	var driver coreBackend = mihomoBackend{}
	if jsonInput {
		driver = singBoxBackend{}
	}
	if requested != BackendAuto && requested != BackendMihomo && requested != BackendSingBox {
		return nil, nil, nil, ErrRunnerUnsupported
	}
	if requested != BackendAuto && requested != driver.ID() {
		return nil, nil, nil, ErrRunnerUnsupported
	}
	proxies, names, err := driver.Nodes(data)
	return driver, proxies, names, err
}

// Decode the JSON token stream before map construction. json.Unmarshal alone
// would silently keep the last duplicate key, including escaped spellings.
func runnerJSON(data []byte) (map[string]any, error) {
	if len(data) > maxRunnerConfig {
		return nil, ErrRunnerConfig
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	value, err := runnerJSONValue(d, 0)
	if err != nil {
		return nil, ErrRunnerConfig
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, ErrRunnerConfig
	}
	doc, ok := value.(map[string]any)
	if !ok {
		return nil, ErrRunnerConfig
	}
	return doc, nil
}
func runnerJSONValue(d *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, ErrRunnerConfig
	}
	token, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch v := token.(type) {
	case json.Delim:
		switch v {
		case '{':
			m := map[string]any{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return nil, err
				}
				k, ok := key.(string)
				if !ok {
					return nil, ErrRunnerConfig
				}
				if _, exists := m[k]; exists {
					return nil, ErrRunnerConfig
				}
				value, err := runnerJSONValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				m[k] = value
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return nil, ErrRunnerConfig
			}
			return m, nil
		case '[':
			a := []any{}
			for d.More() {
				value, err := runnerJSONValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				a = append(a, value)
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return nil, ErrRunnerConfig
			}
			return a, nil
		}
		return nil, ErrRunnerConfig
	case json.Number:
		// Preserve integers exactly, never float-round a port or protocol parameter.
		n, err := strconv.ParseInt(string(v), 10, 64)
		if err != nil || int64(int(n)) != n {
			return v, nil
		}
		return int(n), nil
	default:
		return token, nil
	}
}

func singBoxTLS(v any) bool {
	return runnerObject(runnerFields{
		"enabled": runnerBool, "disable_sni": runnerBool, "server_name": runnerString, "insecure": runnerBool, "alpn": runnerStrings,
		"min_version": runnerString, "max_version": runnerString, "cipher_suites": runnerStrings,
		"utls":    runnerObject(runnerFields{"enabled": runnerBool, "fingerprint": runnerString}),
		"reality": runnerObject(runnerFields{"enabled": runnerBool, "public_key": runnerString, "short_id": runnerString}),
	})(v)
}
func singBoxTransport(v any) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	f := runnerFields{"type": runnerString}
	switch m["type"] {
	case "ws":
		addRunnerFields(f, runnerString, "path early_data_header_name")
		f["max_early_data"] = runnerInt
		f["headers"] = runnerHeaders
	case "grpc":
		addRunnerFields(f, runnerString, "service_name idle_timeout ping_timeout")
		f["permit_without_stream"] = runnerBool
	default:
		return false
	}
	return runnerObject(f)(v)
}
func singBoxFields(protocol string) runnerFields {
	f := runnerFields{}
	addRunnerFields(f, runnerString, "tag type server")
	f["server_port"] = runnerInt
	switch protocol {
	case "shadowsocks":
		addRunnerFields(f, runnerString, "method password")
	case "vless", "vmess", "trojan":
		f["tls"] = singBoxTLS
		f["transport"] = singBoxTransport
		if protocol == "trojan" {
			f["password"] = runnerString
			break
		}
		f["uuid"] = runnerString
		f["packet_encoding"] = runnerString
		if protocol == "vless" {
			f["flow"] = runnerString
		} else {
			f["security"] = runnerString
			f["alter_id"] = runnerInt
			addRunnerFields(f, runnerBool, "global_padding authenticated_length")
		}
	case "hysteria2":
		f["tls"] = singBoxTLS
		addRunnerFields(f, runnerString, "password hop_interval hop_interval_max bbr_profile")
		addRunnerFields(f, runnerInt, "up_mbps down_mbps")
		f["server_ports"] = runnerStrings
		f["obfs"] = func(v any) bool {
			m, ok := v.(map[string]any)
			return ok && m["type"] == "salamander" && runnerObject(runnerFields{"type": runnerString, "password": runnerString})(v)
		}
	case "tuic":
		f["tls"] = singBoxTLS
		addRunnerFields(f, runnerString, "uuid password congestion_control udp_relay_mode heartbeat")
		addRunnerFields(f, runnerBool, "udp_over_stream zero_rtt_handshake")
	case "anytls":
		f["tls"] = singBoxTLS
		addRunnerFields(f, runnerString, "password idle_session_check_interval idle_session_timeout client_metadata")
		f["min_idle_session"] = runnerInt
	default:
		return nil // WireGuard endpoints / ShadowTLS layering are not flattened.
	}
	return f
}
func singBoxProxies(data []byte) ([]map[string]any, []string, error) {
	doc, err := runnerJSON(data)
	if err != nil {
		return nil, nil, err
	}
	if err := runnerGlobals(doc, "outbounds"); err != nil {
		return nil, nil, err
	}
	raw, ok := doc["outbounds"].([]any)
	if !ok || len(raw) == 0 || len(raw) > maxRunnerNodes {
		return nil, nil, ErrRunnerConfig
	}
	seen := map[string]bool{}
	proxies := make([]map[string]any, 0, len(raw))
	names := make([]string, 0, len(raw))
	for _, item := range raw {
		p, ok := item.(map[string]any)
		if !ok {
			return nil, nil, ErrRunnerConfig
		}
		name, nok := p["tag"].(string)
		protocol, tok := p["type"].(string)
		server, sok := p["server"].(string)
		port, pok := p["server_port"].(int)
		if !nok || strings.TrimSpace(name) == "" || seen[name] || !tok || !sok || strings.TrimSpace(server) == "" || strings.ContainsAny(server, "/\\\x00\r\n") || !pok || port < 1 || port > 65535 {
			return nil, nil, ErrRunnerConfig
		}
		fields := singBoxFields(protocol)
		if fields == nil {
			return nil, nil, ErrRunnerUnsupported
		}
		for k, v := range p {
			check, ok := fields[k]
			if !ok || !check(v) {
				return nil, nil, ErrRunnerUnsupported
			}
		}
		for _, key := range []string{"uuid", "password", "method"} {
			required := key == "uuid" && (protocol == "vless" || protocol == "vmess" || protocol == "tuic") || key == "password" && (protocol == "trojan" || protocol == "hysteria2" || protocol == "shadowsocks" || protocol == "tuic" || protocol == "anytls") || key == "method" && protocol == "shadowsocks"
			if required && strings.TrimSpace(str(p[key])) == "" {
				return nil, nil, ErrRunnerConfig
			}
		}
		seen[name] = true
		names = append(names, name)
		p["tag"] = "ipd-node"
		proxies = append(proxies, p)
	}
	return proxies, names, nil
}
