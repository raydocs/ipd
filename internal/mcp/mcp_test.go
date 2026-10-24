package mcp_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"ipd/internal/api"
	"ipd/internal/app"
	"ipd/internal/config"
	ipdmcp "ipd/internal/mcp"
	"ipd/internal/store"
)

func svc(t *testing.T) *app.Service {
	t.Helper()
	cfg := config.FromEnv()
	cfg.Offline = true
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return app.New(cfg, db)
}

func TestToolsSchemaAndLookup(t *testing.T) {
	s := ipdmcp.Server(svc(t), ipdmcp.ModeStdio)
	ctx := context.Background()
	c := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	st, ct := mcp.NewInMemoryTransports()
	ss, err := s.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := c.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	listed, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Tools) < 19 {
		t.Fatalf("tools %d", len(listed.Tools))
	}
	names := map[string]bool{}
	for _, tool := range listed.Tools {
		names[tool.Name] = true
		raw, _ := json.Marshal(tool.OutputSchema)
		for _, key := range []string{"verdict", "summary_md", "data", "sources", "cached_at"} {
			if !strings.Contains(string(raw), key) {
				t.Fatalf("%s output schema missing %s: %s", tool.Name, key, raw)
			}
		}
		if strings.Contains(string(raw), "candidate_ip") {
			t.Fatalf("%s schema stores webrtc ip", tool.Name)
		}
		if tool.Annotations == nil {
			t.Fatalf("%s annotations", tool.Name)
		}
	}
	for _, n := range []string{"whoami", "ip_lookup", "ip_risk_explain", "ai_env_check", "gfw_check", "route_return", "unlock_check", "watch_create", "sources_status"} {
		if !names[n] {
			t.Fatalf("missing %s", n)
		}
	}
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "ip_lookup", Arguments: map[string]any{"ip": "1.1.1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("lookup error %#v", res.Content)
	}
	b, _ := json.Marshal(res.StructuredContent)
	var out struct {
		Verdict   string         `json:"verdict"`
		SummaryMD string         `json:"summary_md"`
		Data      map[string]any `json:"data"`
		Sources   []any          `json:"sources"`
		CachedAt  string         `json:"cached_at"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.Verdict == "" || out.SummaryMD == "" || out.Data["ip"] != "1.1.1.1" || out.CachedAt == "" {
		t.Fatalf("%s", b)
	}
	if len(out.SummaryMD) > 600 {
		t.Fatal("summary too long")
	}
	prompts, err := cs.ListPrompts(ctx, nil)
	if err != nil || len(prompts.Prompts) < 2 {
		t.Fatal(err, prompts)
	}
	resources, err := cs.ListResources(ctx, nil)
	if err != nil || len(resources.Resources) < 2 {
		t.Fatal(err)
	}
}

func TestHTTPLocalRequiresEgress(t *testing.T) {
	service := svc(t)
	ts := httptest.NewServer(api.New(service).Handler())
	defer ts.Close()
	ctx := context.Background()
	c := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	cs, err := c.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: ts.URL + "/mcp", DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "ai_env_check", Arguments: map[string]any{}})
	if err != nil && (res == nil || !res.IsError) {
		// protocol error is also acceptable if the text is on err
		if !strings.Contains(err.Error(), "requires_egress_run") {
			t.Fatal(err)
		}
		return
	}
	blob, _ := json.Marshal(res)
	if !strings.Contains(string(blob), "requires_egress_run") {
		t.Fatalf("%s", blob)
	}
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "ip_lookup", Arguments: map[string]any{"ip": "8.8.8.8"}})
	if err != nil || res.IsError {
		t.Fatal(err, res)
	}
}
