package mcp_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"ipd/internal/app"
	ipdmcp "ipd/internal/mcp"
	"ipd/internal/probe"
	"ipd/internal/route"
	"ipd/internal/unlock"
)

// These are requests for selection/overrides, not permission to silently use
// the fixed defaults. Include values that might otherwise look like defaults.
var unsupportedOptions = []struct {
	tool, option string
	args         map[string]any
	values       []any
	zero         any
	advice       string
}{
	{"ip_lookup", "fields", map[string]any{"ip": "1.1.1.1"}, []any{[]string{"asn"}, []string{""}}, []string{}, "full report"},
	{"ip_batch", "fields", map[string]any{"ips": []string{"1.1.1.1"}}, []any{[]string{"asn"}}, []string{}, "full report"},
	{"google_region_check", "proxy", map[string]any{}, []any{"http://user:private@proxy.invalid:8080", " "}, "", "IPD_PROXY"},
	{"unlock_check", "proxy", map[string]any{}, []any{"http://proxy.invalid:8080"}, "", "IPD_PROXY"},
	{"ai_env_check", "proxy", map[string]any{}, []any{"http://proxy.invalid:8080"}, "", "IPD_PROXY"},
	{"route_forward", "proto", map[string]any{"target": "1.1.1.1"}, []any{"tcp", "icmp"}, "", "provider default"},
	{"latency_map", "regions", map[string]any{"target": "1.1.1.1"}, []any{[]string{"US"}, []string{""}}, []string{}, "IPD_VANTAGE"},
	{"port_check", "from", map[string]any{"target": "1.1.1.1", "port": 8443}, []any{"US", "global"}, "", "IPD_VANTAGE"},
	{"node_batch_check", "checks", map[string]any{"source": "proxies: []"}, []any{[]string{"ai"}}, []string{}, "fixed checks"},
	{"node_batch_check", "rename_template", map[string]any{"source": "proxies: []"}, []any{"{name}"}, "", "stock rename"},
	{"watch_create", "checks", map[string]any{"target": "1.1.1.1"}, []any{[]string{"gfw"}, []string{"risk"}}, []string{}, "fixed risk"},
	{"gfw_check", "wait", map[string]any{"target": "1.1.1.1"}, []any{true}, false, "synchronous"},
	{"job_get", "wait_s", map[string]any{"job_id": "fixture-job"}, []any{1, -1}, 0, "poll job_get"},
}

type contractVantage struct {
	mu      sync.Mutex
	queries []probe.Query
}

func (*contractVantage) Name() string  { return "fixture" }
func (*contractVantage) Enabled() bool { return true }
func (v *contractVantage) Measure(_ context.Context, q probe.Query) ([]probe.Sample, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.queries = append(v.queries, q)
	return []probe.Sample{{Network: "ct", ASN: 4134, City: "fixture", Healthy: true, ICMP: "ok", TCP: map[int]string{q.Port: "ok"}}}, nil
}

func (v *contractVantage) take() []probe.Query {
	v.mu.Lock()
	defer v.mu.Unlock()
	queries := v.queries
	v.queries = nil
	return queries
}

type contractGetter struct {
	mu    sync.Mutex
	calls int
}

func (g *contractGetter) Get(_ context.Context, rawURL string, _ map[string]string) unlock.Response {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls++
	return unlock.Response{Status: 200, Body: "loc=US\n", FinalURL: rawURL}
}

func (g *contractGetter) count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.calls
}

func contractClient(t *testing.T, mode string) (*mcp.ClientSession, *app.Service, *contractVantage, *contractGetter) {
	t.Helper()
	service := svc(t)
	v, g := &contractVantage{}, &contractGetter{}
	service.Vantage = v
	service.Checks = &unlock.Engine{Get: g}
	service.Tracer = nil
	service.Egress = func(context.Context) (string, string) { return "1.1.1.1", "" }
	if err := service.DB.CreateJob("fixture-job", "fixture", "{}", time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	s := ipdmcp.Server(service, mode)
	st, ct := mcp.NewInMemoryTransports()
	ss, err := s.Connect(ctx, st, nil)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "contract-test", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		ss.Close()
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close(); ss.Close(); cancel() })
	return cs, service, v, g
}

func callContract(t *testing.T, cs *mcp.ClientSession, tool string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func contractText(res *mcp.CallToolResult) string {
	var text strings.Builder
	for _, c := range res.Content {
		if c, ok := c.(*mcp.TextContent); ok {
			text.WriteString(c.Text)
		}
	}
	return text.String()
}

func contractOut(t *testing.T, res *mcp.CallToolResult) ipdmcp.Out {
	t.Helper()
	if res.IsError {
		t.Fatalf("unexpected tool error: %s", contractText(res))
	}
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var out ipdmcp.Out
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestUnsupportedOptions(t *testing.T) {
	cs, service, v, g := contractClient(t, ipdmcp.ModeStdio)
	for _, tc := range unsupportedOptions {
		for i, value := range tc.values {
			t.Run(fmt.Sprintf("%s/%s/%d", tc.tool, tc.option, i), func(t *testing.T) {
				args := cloneArgs(tc.args)
				args[tc.option] = value
				res := callContract(t, cs, tc.tool, args)
				text := contractText(res)
				if !res.IsError || !strings.Contains(text, "unsupported_option: "+tc.option) || !strings.Contains(text, tc.advice) {
					t.Errorf("want explicit unsupported_option with advice, got error=%v text=%q", res.IsError, text)
				}
				if strings.Contains(text, "private@") || strings.Contains(text, "proxy.invalid") {
					t.Error("error echoed proxy credentials/address")
				}
			})
		}
	}
	if queries := v.take(); len(queries) != 0 || g.count() != 0 {
		t.Errorf("rejected options executed probes: queries=%d HTTP=%d", len(queries), g.count())
	}
	ws, err := service.DB.ListWatches()
	if err != nil || len(ws) != 0 {
		t.Errorf("rejected watch options wrote state: %v, %v", ws, err)
	}
}

func cloneArgs(args map[string]any) map[string]any {
	copy := make(map[string]any, len(args)+1)
	for k, v := range args {
		copy[k] = v
	}
	return copy
}

func TestOptionDefaults(t *testing.T) {
	cs, _, _, _ := contractClient(t, ipdmcp.ModeStdio)
	for _, tc := range unsupportedOptions {
		variants := []string{"omitted", "zero"}
		if _, array := tc.zero.([]string); array {
			variants = append(variants, "null")
		}
		for _, variant := range variants {
			t.Run(fmt.Sprintf("%s/%s/%s", tc.tool, tc.option, variant), func(t *testing.T) {
				args := cloneArgs(tc.args)
				if tc.tool == "node_batch_check" {
					args["source"] = "proxies:\n  - {name: fixture, type: socks5, server: example.invalid, port: 1080}"
				}
				if variant == "zero" {
					args[tc.option] = tc.zero
				} else if variant == "null" {
					args[tc.option] = nil
				}
				out := contractOut(t, callContract(t, cs, tc.tool, args))
				if out.Verdict == "" {
					t.Error("missing default result")
				}
			})
		}
	}
}

func TestOptionSchemas(t *testing.T) {
	cs, _, _, _ := contractClient(t, ipdmcp.ModeStdio)
	listed, err := cs.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	tools := map[string]*mcp.Tool{}
	for _, tool := range listed.Tools {
		tools[tool.Name] = tool
	}
	for _, tc := range unsupportedOptions {
		t.Run(tc.tool+"/"+tc.option, func(t *testing.T) {
			tool := tools[tc.tool]
			b, _ := json.Marshal(tool.InputSchema)
			var schema struct {
				Properties map[string]struct{ Description string }
				Required   []string
			}
			if err := json.Unmarshal(b, &schema); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(strings.ToLower(schema.Properties[tc.option].Description), "unsupported") || !strings.Contains(strings.ToLower(tool.Description), "unsupported") {
				t.Errorf("tool/schema must disclose unsupported %s: %s; %s", tc.option, tool.Description, b)
			}
			for _, required := range schema.Required {
				if required == tc.option {
					t.Errorf("default option must remain optional: %s", required)
				}
			}
		})
	}
}

func TestHTTPEgressContract(t *testing.T) {
	cs, _, v, g := contractClient(t, ipdmcp.ModeHTTP)
	for _, tc := range []struct {
		tool, hint string
		args       map[string]any
	}{
		{"whoami", "ipd", map[string]any{}},
		{"google_region_check", "ipd unlock google_region youtube_premium", map[string]any{"proxy": "http://proxy.invalid:8080"}},
		{"unlock_check", "ipd unlock", map[string]any{"proxy": "http://proxy.invalid:8080"}},
		{"ai_env_check", "ipd ai", map[string]any{"proxy": "http://proxy.invalid:8080"}},
		{"node_batch_check", "ipd nodes <source>", map[string]any{"source": "missing", "checks": []string{"ai"}, "rename_template": "{name}"}},
		{"route_return", "ipd route --return", map[string]any{}},
		{"dns_leak_test", "ipd leak", map[string]any{}},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			defaults := cloneArgs(tc.args)
			for _, key := range []string{"proxy", "checks", "rename_template"} {
				delete(defaults, key)
			}
			for _, args := range []map[string]any{defaults, tc.args} {
				res := callContract(t, cs, tc.tool, args)
				text := contractText(res)
				if !res.IsError || !strings.Contains(text, "requires_egress_run: "+tc.hint) || strings.Contains(text, "unsupported_option") {
					t.Errorf("HTTP egress guard must win with a valid CLI hint: %q", text)
				}
			}
		})
	}
	if queries := v.take(); len(queries) != 0 || g.count() != 0 {
		t.Fatal("HTTP egress tools executed local checks")
	}
	contractOut(t, callContract(t, cs, "ip_lookup", map[string]any{"ip": "1.1.1.1"}))
	res := callContract(t, cs, "ip_lookup", map[string]any{"ip": "1.1.1.1", "fields": []string{"asn"}})
	if !res.IsError || !strings.Contains(contractText(res), "unsupported_option: fields") {
		t.Fatal("HTTP non-egress option was ignored")
	}
}

func TestSupportedOptionsStillForwarded(t *testing.T) {
	cs, _, v, _ := contractClient(t, ipdmcp.ModeStdio)
	contractOut(t, callContract(t, cs, "route_forward", map[string]any{"target": "1.1.1.1", "carriers": []string{"cu"}}))
	queries := v.take()
	if len(queries) != 1 || strings.Join(queries[0].Carriers, ",") != "cu" || queries[0].Target != "1.1.1.1" {
		t.Fatalf("carriers not forwarded: %+v", queries)
	}
	contractOut(t, callContract(t, cs, "gfw_check", map[string]any{"target": "1.1.1.1", "ports": []int{8443}}))
	queries = v.take()
	if len(queries) != 2 || queries[1].Kind != probe.KindTCP || queries[1].Port != 8443 {
		t.Fatalf("ports not forwarded: %+v", queries)
	}
	out := contractOut(t, callContract(t, cs, "unlock_check", map[string]any{"services": []string{"google_region"}}))
	results, ok := out.Data["results"].([]any)
	if !ok || len(results) != 1 || results[0].(map[string]any)["service"] != "google_region" {
		t.Fatalf("services not forwarded: %+v", out.Data)
	}
}

func TestSummaryUTF8OverMCP(t *testing.T) {
	cs, service, _, _ := contractClient(t, ipdmcp.ModeStdio)
	for _, tail := range []string{"short中文🙂", strings.Repeat("a", 800), strings.Repeat("中", 220), "a" + strings.Repeat("中文", 120), strings.Repeat("🙂", 180)} {
		t.Run(fmt.Sprintf("bytes=%d", len(tail)), func(t *testing.T) {
			service.Tracer = func(context.Context, string) ([]route.Hop, error) { return nil, errors.New(tail) }
			res := callContract(t, cs, "route_return", map[string]any{})
			out := contractOut(t, res)
			// Route wording belongs to the app. This test covers the wire contract;
			// exact truncation of controlled reports is checked by TestToOutSummaryUTF8.
			if out.SummaryMD == "" || !utf8.ValidString(out.SummaryMD) || len(out.SummaryMD) > 600 || strings.Contains(out.SummaryMD, "\ufffd") {
				t.Errorf("MCP summary must be non-empty, intact UTF-8 within 600 bytes; got %q", out.SummaryMD)
			}
			if !utf8.ValidString(contractText(res)) || strings.Contains(contractText(res), "\ufffd") {
				t.Error("short text contains damaged UTF-8")
			}
		})
	}
}
