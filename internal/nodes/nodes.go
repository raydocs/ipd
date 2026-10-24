// Package nodes checks a local proxy subscription. The server never fetches
// the subscription URL. mihomo, when used, is an external process and is not
// linked.
package nodes

import (
	"context"
	"encoding/base64"
	"fmt"
	"maps"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"time"

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
	Name      string `json:"name"`
	Server    string `json:"server"`
	EgressIP  string `json:"egress_ip,omitempty"`
	Grade     string `json:"grade,omitempty"`
	AI        string `json:"ai,omitempty"`
	TikTok    string `json:"tiktok,omitempty"`
	Reachable bool   `json:"reachable"`
	Error     string `json:"error,omitempty"`
	Renamed   string `json:"renamed"`
}

// Checker scores one local SOCKS endpoint. Tests substitute a fake.
type Checker interface {
	Check(ctx context.Context, name, socks string) (egress, grade, ai, tiktok string, err error)
}

// Runner starts and stops an external mihomo. A nil runner means "do not
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
		return File{Raw: map[string]any{"proxies": proxiesToMaps(proxies)}, Proxies: proxies}, nil
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
	return File{Raw: doc, Proxies: proxies}, nil
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
		path, err := writeTemp(f)
		if err != nil {
			return nil, "", err
		}
		defer os.Remove(path)
		socks, err = runner.Start(ctx, path)
		if err != nil {
			return nil, "", err
		}
		defer runner.Stop()
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
			o := Outcome{Name: p.Name, Server: p.Server}
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
	yamlOut, err := RenameYAML(f, out)
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

// RenameYAML rewrites proxy names and proxy-group members without mutating f.
// Generated names get deterministic suffixes when they collide with existing
// targets. Ambiguous source names cannot be safely rewritten and return an error.
func RenameYAML(f File, outcomes []Outcome) (string, error) {
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
		members, _ := g["proxies"].([]any)
		for _, member := range members {
			if name, ok := member.(string); ok {
				// Provider/external targets must not be shadowed either.
				used[name] = true
			}
		}
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
			return "", fmt.Errorf("cannot rename ambiguous proxy name %q", old)
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
			if old, ok := member.(string); ok {
				if name, ok := renames[old]; ok {
					members[j] = name
				}
			}
		}
		g = maps.Clone(g)
		g["proxies"] = members
		groups[i] = g
	}
	doc := maps.Clone(f.Raw)
	if _, ok := doc["proxies"].([]any); ok {
		doc["proxies"] = proxies
	}
	if _, ok := doc["proxy-groups"].([]any); ok {
		doc["proxy-groups"] = groups
	}
	b, err := yaml.Marshal(doc)
	return string(b), err
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

// Mihomo is an external-process runner. It is not linked into ipd.
type Mihomo struct {
	Bin string
	cmd *exec.Cmd
	mu  sync.Mutex
}

func (m *Mihomo) Start(ctx context.Context, configPath string) (map[string]string, error) {
	bin := m.Bin
	if bin == "" {
		bin = "mihomo"
	}
	if _, err := exec.LookPath(bin); err != nil {
		return nil, fmt.Errorf("mihomo not on PATH (it is an external GPL process and is not bundled): %w", err)
	}
	// -t validates. The real listener ports are assigned by the caller via a
	// generated config; this starter only checks the binary can be executed.
	c := exec.CommandContext(ctx, bin, "-t", "-f", configPath)
	c.WaitDelay = 2 * time.Second
	if out, err := c.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("mihomo -t: %v %s", err, out)
	}
	return map[string]string{}, nil
}

func (m *Mihomo) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd != nil && m.cmd.Process != nil {
		_ = m.cmd.Process.Kill()
	}
}
