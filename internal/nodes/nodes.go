// Package nodes checks a local proxy subscription. The server never fetches
// the subscription URL. Proxy cores, when used, are external processes and
// are not linked.
package nodes

import (
	"context"
	"encoding/base64"
	"fmt"
	"maps"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Proxy is one clash/mihomo proxy.
type Proxy struct {
	Name   string         `json:"name" yaml:"name"`
	Type   string         `json:"type" yaml:"type"`
	Server string         `json:"server" yaml:"server"`
	Port   int            `json:"port" yaml:"port"`
	Extra  map[string]any `json:"-" yaml:",inline"`
}

// Outcome is one node's check.
type Outcome struct {
	Backend   Backend `json:"backend,omitempty"`
	Name      string  `json:"name"`
	Server    string  `json:"server"`
	EgressIP  string  `json:"egress_ip,omitempty"`
	Grade     string  `json:"grade,omitempty"`
	AI        string  `json:"ai,omitempty"`
	TikTok    string  `json:"tiktok,omitempty"`
	Reachable bool    `json:"reachable"`
	Error     string  `json:"error,omitempty"`
	Renamed   string  `json:"renamed"`
}

// Checker scores one local SOCKS endpoint. ExecRunner supplies an authenticated
// socks5:// URL (including credentials); callers must not log it. Tests substitute a fake.
type Checker interface {
	Check(ctx context.Context, name, socks string) (egress, grade, ai, tiktok string, err error)
}

// Runner starts and stops an external proxy core. A nil runner means "do not
// start a process"; the checker is then called with an empty socks address
// and may still classify the node as unreachable.
type Runner interface {
	Start(ctx context.Context, configPath string) (socksByName map[string]string, err error)
	Stop()
}

// File is a parsed clash document.
type File struct {
	Raw     map[string]any
	Proxies []Proxy
	// Preserve representation-tree safety across Parse -> Run serialization.
	runnerYAMLInvalid bool
	runnerURI         bool
}

// Parse accepts clash YAML, a raw proxy URI, or a base64 subscription body.
func Parse(text string) (File, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return File{}, fmt.Errorf("empty subscription")
	}
	if decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(text, "\n", "")); err == nil && strings.Contains(string(decoded), "://") {
		text = string(decoded)
	}
	if strings.Contains(text, "://") && !strings.Contains(text, "proxies:") {
		var proxies []Proxy
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			p, err := parseURI(line)
			if err != nil {
				return File{}, err
			}
			proxies = append(proxies, p)
		}
		return File{Raw: map[string]any{"proxies": proxiesToMaps(proxies)}, Proxies: proxies, runnerURI: true}, nil
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		return File{}, err
	}
	raw, _ := doc["proxies"].([]any)
	var proxies []Proxy
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		p := Proxy{
			Name:   str(m["name"]),
			Type:   str(m["type"]),
			Server: str(m["server"]),
			Port:   num(m["port"]),
			Extra:  m,
		}
		proxies = append(proxies, p)
	}
	if len(proxies) == 0 {
		return File{}, fmt.Errorf("no proxies in document")
	}
	_, runnerErr := runnerDocument([]byte(text))
	return File{Raw: doc, Proxies: proxies, runnerYAMLInvalid: runnerErr != nil}, nil
}

func parseURI(line string) (Proxy, error) {
	u, err := url.Parse(line)
	if err != nil {
		return Proxy{}, err
	}
	name := u.Fragment
	if name == "" {
		name = u.Host
	}
	port := 0
	fmt.Sscanf(u.Port(), "%d", &port)
	host := u.Hostname()
	return Proxy{Name: name, Type: u.Scheme, Server: host, Port: port, Extra: map[string]any{
		"name": name, "type": u.Scheme, "server": host, "port": port,
	}}, nil
}

// Run checks every proxy. Unreachable nodes are marked and do not stop the batch.
func Run(ctx context.Context, f File, checker Checker, runner Runner, rename func(Outcome) string, parallelism int) ([]Outcome, string, error) {
	if parallelism <= 0 {
		parallelism = 8
	}
	socks := map[string]string{}
	if runner != nil {
		var err error
		if fileRunner, ok := runner.(interface {
			StartFile(context.Context, File) (map[string]string, error)
		}); ok {
			socks, err = fileRunner.StartFile(ctx, f)
		} else {
			path, writeErr := writeTemp(f)
			if writeErr != nil {
				return nil, "", writeErr
			}
			defer os.Remove(path)
			socks, err = runner.Start(ctx, path)
		}
		if err != nil {
			return nil, "", err
		}
		defer runner.Stop()
	}
	var backend Backend
	if identity, ok := runner.(interface{ SelectedBackend() Backend }); ok {
		backend = identity.SelectedBackend()
	}
	if checker == nil {
		checker = unreachable{}
	}
	out := make([]Outcome, len(f.Proxies))
	sem := make(chan struct{}, parallelism)
	var wg sync.WaitGroup
	for i, p := range f.Proxies {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, p Proxy) {
			defer wg.Done()
			defer func() { <-sem }()
			o := Outcome{Name: p.Name, Server: p.Server, Backend: backend}
			addr := socks[p.Name]
			egress, grade, ai, tt, err := checker.Check(ctx, p.Name, addr)
			if err != nil || egress == "" {
				o.Reachable = false
				o.Error = "unreachable"
				if err != nil {
					o.Error = "unreachable"
				}
				o.Grade = "-"
			} else {
				o.Reachable = true
				o.EgressIP = egress
				o.Grade = grade
				o.AI = ai
				o.TikTok = tt
			}
			if rename != nil {
				o.Renamed = rename(o)
			} else {
				o.Renamed = DefaultRename(o)
			}
			out[i] = o
		}(i, p)
	}
	wg.Wait()
	yamlOut, renames, err := renameYAML(f, out)
	if err == nil {
		for i := range out {
			out[i].Renamed = out[i].Name
			if name, ok := renames[out[i].Name]; ok {
				out[i].Renamed = name
			}
		}
	}
	return out, yamlOut, err
}

type unreachable struct{}

func (unreachable) Check(ctx context.Context, name, socks string) (string, string, string, string, error) {
	return "", "", "", "", fmt.Errorf("unreachable")
}

// DefaultRename is the stock template.
func DefaultRename(o Outcome) string {
	if !o.Reachable {
		return "❌ " + o.Name + " | unreachable"
	}
	res := "否"
	return fmt.Sprintf("%s | 家宽? %s | %s | Claude%s GPT%s TT%s", o.Name, res, o.Grade, mark(o.AI), mark(o.AI), flagOf(o.TikTok))
}

func mark(s string) string {
	switch s {
	case "yes", "ok", "✅":
		return "✅"
	case "no", "blocked":
		return "❌"
	default:
		if s == "" {
			return "·"
		}
		return s
	}
}

func flagOf(region string) string {
	if len(region) == 2 {
		return region
	}
	return "·"
}

// RenameYAML rewrites proxy names and supported policy references without mutating f.
// Generated names get deterministic suffixes when they collide with existing
// targets. Ambiguous source names cannot be safely rewritten and return an error.
func RenameYAML(f File, outcomes []Outcome) (string, error) {
	text, _, err := renameYAML(f, outcomes)
	return text, err
}

func renameYAML(f File, outcomes []Outcome) (string, map[string]string, error) {
	byName := map[string]string{}
	for _, o := range outcomes {
		byName[o.Name] = o.Renamed
	}
	reserved := map[string]bool{
		"DIRECT": true, "REJECT": true, "REJECT-DROP": true,
		"PASS": true, "COMPATIBLE": true, "GLOBAL": true,
	}
	used := maps.Clone(reserved)
	for name := range byName {
		// A generated name must not become another outcome's source on replay.
		used[name] = true
	}
	groupNames := map[string]bool{}
	groups, _ := f.Raw["proxy-groups"].([]any)
	for _, item := range groups {
		g, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name := str(g["name"])
		groupNames[name], used[name] = true, true
	}
	// Reserve external targets in every supported reference field, not just groups.
	if _, err := rewritePolicyReferences(f.Raw, func(name string) string {
		used[name] = true
		return name
	}); err != nil {
		return "", nil, err
	}
	proxies, _ := f.Raw["proxies"].([]any)
	counts := map[string]int{}
	for _, item := range proxies {
		if p, ok := item.(map[string]any); ok {
			name := str(p["name"])
			counts[name]++
			used[name] = true
		}
	}
	renames := map[string]string{}
	proxies = slices.Clone(proxies)
	for i, item := range proxies {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		old := str(m["name"])
		requested := byName[old]
		if requested == "" || requested == old {
			continue
		}
		if counts[old] > 1 || reserved[old] || groupNames[old] {
			return "", nil, fmt.Errorf("cannot rename ambiguous proxy name %q", old)
		}
		name := requested
		for suffix := 2; used[name]; suffix++ {
			name = fmt.Sprintf("%s (%d)", requested, suffix)
		}
		used[name] = true
		renames[old] = name
		m = maps.Clone(m)
		m["name"] = name
		proxies[i] = m
	}
	doc := maps.Clone(f.Raw)
	if _, ok := doc["proxies"].([]any); ok {
		doc["proxies"] = proxies
	}
	doc, err := rewritePolicyReferences(doc, func(old string) string {
		if name, ok := renames[old]; ok {
			return name
		}
		return old
	})
	if err != nil {
		return "", nil, err
	}
	b, err := yaml.Marshal(doc)
	return string(b), renames, err
}

// Only visit documented reference locations, never arbitrary strings or map keys.
func rewritePolicyReferences(raw map[string]any, replace func(string) string) (map[string]any, error) {
	doc := maps.Clone(raw)
	if proxies, ok := doc["proxies"]; ok {
		doc["proxies"] = rewriteDialerList(proxies, replace)
	}
	groups, hasGroups := doc["proxy-groups"].([]any)
	groups = slices.Clone(groups)
	for i, item := range groups {
		g, ok := item.(map[string]any)
		if !ok {
			continue
		}
		members, ok := g["proxies"].([]any)
		if !ok {
			continue
		}
		members = slices.Clone(members)
		for j, member := range members {
			if name, ok := member.(string); ok {
				members[j] = replace(name)
			}
		}
		g = maps.Clone(g)
		g["proxies"] = members
		groups[i] = g
	}
	if hasGroups {
		doc["proxy-groups"] = groups
	}
	if rules, ok := doc["rules"]; ok {
		rewritten, err := rewriteRuleList(rules, replace)
		if err != nil {
			return nil, err
		}
		doc["rules"] = rewritten
	}
	if subRules, ok := doc["sub-rules"].(map[string]any); ok {
		subRules = maps.Clone(subRules)
		for name, rules := range subRules {
			rewritten, err := rewriteRuleList(rules, replace)
			if err != nil {
				return nil, err
			}
			subRules[name] = rewritten
		}
		doc["sub-rules"] = subRules
	}
	if providers, ok := doc["proxy-providers"].(map[string]any); ok {
		providers = maps.Clone(providers)
		for name, item := range providers {
			p, ok := item.(map[string]any)
			if !ok {
				continue
			}
			p = maps.Clone(p)
			if override, ok := p["override"].(map[string]any); ok {
				p["override"] = rewriteDialer(override, replace)
			}
			if payload, ok := p["payload"]; ok {
				p["payload"] = rewriteDialerList(payload, replace)
			}
			providers[name] = p
		}
		doc["proxy-providers"] = providers
	}
	return doc, nil
}

func rewriteDialerList(raw any, replace func(string) string) any {
	items, ok := raw.([]any)
	if !ok {
		return raw
	}
	items = slices.Clone(items)
	for i, item := range items {
		if p, ok := item.(map[string]any); ok {
			items[i] = rewriteDialer(p, replace)
		}
	}
	return items
}

func rewriteDialer(p map[string]any, replace func(string) string) map[string]any {
	if name, ok := p["dialer-proxy"].(string); ok {
		p = maps.Clone(p)
		p["dialer-proxy"] = replace(name)
	}
	return p
}

func rewriteRuleList(raw any, replace func(string) string) (any, error) {
	rules, ok := raw.([]any)
	if !ok {
		return raw, nil
	}
	rules = slices.Clone(rules)
	for i, item := range rules {
		if rule, ok := item.(string); ok {
			rewritten, err := rewriteRule(rule, replace)
			if err != nil {
				return nil, err
			}
			rules[i] = rewritten
		}
	}
	return rules, nil
}

func rewriteRule(rule string, replace func(string) string) (string, error) {
	parts := strings.Split(rule, ",")
	var target int
	// Match mihomo's policy position, including comma-containing logic/regex
	// payloads and trailing options. SUB-RULE targets belong to another namespace.
	switch strings.ToUpper(strings.TrimSpace(parts[0])) {
	case "MATCH":
		target = 1
	case "AND", "OR", "NOT", "DOMAIN-REGEX", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX":
		if len(parts) < 3 {
			return rule, nil
		}
		target = len(parts) - 1
	case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD", "GEOSITE",
		"GEOIP", "SRC-GEOIP", "IP-ASN", "SRC-IP-ASN", "IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR",
		"IP-SUFFIX", "SRC-IP-SUFFIX", "SRC-PORT", "DST-PORT", "IN-PORT", "DSCP",
		"PROCESS-NAME", "PROCESS-PATH", "PROCESS-NAME-WILDCARD", "PROCESS-PATH-WILDCARD",
		"NETWORK", "UID", "IN-TYPE", "IN-USER", "IN-NAME", "REMATCH-NAME", "RULE-SET":
		target = 2
	default:
		return rule, nil
	}
	if len(parts) <= target {
		return rule, nil
	}
	field := parts[target]
	old := strings.TrimSpace(field)
	name := replace(old)
	if name == old {
		return rule, nil
	}
	if strings.ContainsAny(name, ",\r\n") || strings.TrimSpace(name) != name {
		return "", fmt.Errorf("cannot encode renamed proxy %q as rule policy target", name)
	}
	start := strings.Index(field, old)
	end := start + len(old)
	parts[target] = field[:start] + name + field[end:]
	return strings.Join(parts, ","), nil
}

func writeTemp(f File) (string, error) {
	b, err := yaml.Marshal(f.Raw)
	if err != nil {
		return "", err
	}
	fh, err := os.CreateTemp("", "ipd-clash-*.yaml")
	if err != nil {
		return "", err
	}
	if _, err := fh.Write(b); err != nil {
		fh.Close()
		return "", err
	}
	fh.Close()
	return fh.Name(), nil
}

func proxiesToMaps(ps []Proxy) []any {
	var out []any
	for _, p := range ps {
		m := map[string]any{}
		for k, v := range p.Extra {
			m[k] = v
		}
		m["name"] = p.Name
		m["type"] = p.Type
		m["server"] = p.Server
		m["port"] = p.Port
		out = append(out, m)
	}
	return out
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func num(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case uint64:
		return int(n)
	default:
		return 0
	}
}
