// Package mcp exposes ipd tools over stdio and Streamable HTTP.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"ipd/internal/app"
	"ipd/internal/version"
)

// ModeHTTP makes egress-side tools return requires_egress_run.
const ModeHTTP = "http"

// ModeStdio runs egress-side tools in-process.
const ModeStdio = "stdio"

// Out is the structured tool result. Every tool returns this shape.
type Out struct {
	Verdict   string         `json:"verdict"`
	SummaryMD string         `json:"summary_md"`
	Data      map[string]any `json:"data"`
	Sources   []app.Source   `json:"sources"`
	CachedAt  string         `json:"cached_at"`
}

// Server builds an MCP server bound to svc.
func Server(svc *app.Service, mode string) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "ipd", Version: version.Version, Title: "ipd"}, nil)
	ro := &mcp.ToolAnnotations{ReadOnlyHint: true, Title: ""}
	no := false
	write := &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: &no}

	add(s, svc, mode, "whoami", "Show the egress identity, ASN, country, type, and purity.", true, "ipd", ro, func(ctx context.Context, in struct {
		IPVersion string `json:"ip_version,omitempty" jsonschema:"4, 6, or both"`
	}) (app.Report, error) {
		return svc.WhoAmI(ctx, "", in.IPVersion)
	})
	add(s, svc, mode, "ip_lookup", "Look up geo, ASN, registry country, and source disagreements for an IP.", false, "", ro, func(ctx context.Context, in struct {
		IP     string   `json:"ip" jsonschema:"IPv4 or IPv6 address"`
		Fields []string `json:"fields,omitempty"`
	}) (app.Report, error) {
		return svc.LookupIP(ctx, in.IP)
	})
	add(s, svc, mode, "ip_risk_explain", "Explain purity, residential class, and native versus broadcast.", false, "", ro, func(ctx context.Context, in struct {
		IP          string `json:"ip"`
		IncludeLive bool   `json:"include_live,omitempty"`
	}) (app.Report, error) {
		return svc.Risk(ctx, in.IP, in.IncludeLive && !svc.Cfg.Offline)
	})
	add(s, svc, mode, "ip_batch", "Look up to 1000 addresses.", false, "", ro, func(ctx context.Context, in struct {
		IPs    []string `json:"ips"`
		Fields []string `json:"fields,omitempty"`
	}) (app.Report, error) {
		return svc.Batch(ctx, in.IPs)
	})
	add(s, svc, mode, "asn_lookup", "Describe an autonomous system.", false, "", ro, func(ctx context.Context, in struct {
		ASN int `json:"asn"`
	}) (app.Report, error) {
		return svc.ASN(in.ASN), nil
	})
	add(s, svc, mode, "prefix_neighbors", "Summarise a prefix, usually a /24.", false, "", ro, func(ctx context.Context, in struct {
		CIDR string `json:"cidr"`
	}) (app.Report, error) {
		return svc.Prefix(in.CIDR)
	})
	add(s, svc, mode, "ip_history", "Show how an address changed.", false, "", ro, func(ctx context.Context, in struct {
		IP   string `json:"ip"`
		Days int    `json:"days,omitempty"`
	}) (app.Report, error) {
		return svc.History(in.IP, in.Days)
	})
	add(s, svc, mode, "gfw_check", "Decide whether a target is blocked from China, and how.", false, "", ro, func(ctx context.Context, in struct {
		Target string `json:"target"`
		Ports  []int  `json:"ports,omitempty"`
		Wait   bool   `json:"wait,omitempty"`
	}) (app.Report, error) {
		return svc.GFW(ctx, in.Target, in.Ports)
	})
	add(s, svc, mode, "google_region_check", "Detect whether Google treats this egress as mainland China (送中).", true, "ipd gfw", ro, func(ctx context.Context, in struct {
		Proxy string `json:"proxy,omitempty"`
	}) (app.Report, error) {
		return svc.GoogleRegion(ctx), nil
	})
	add(s, svc, mode, "route_forward", "Trace from China carriers toward a target and classify the path.", false, "", ro, func(ctx context.Context, in struct {
		Target   string   `json:"target"`
		Carriers []string `json:"carriers,omitempty"`
		Proto    string   `json:"proto,omitempty"`
	}) (app.Report, error) {
		return svc.RouteForward(ctx, in.Target, in.Carriers)
	})
	add(s, svc, mode, "route_return", "Trace from this machine toward China and classify the return path.", true, "ipd route --return", ro, func(ctx context.Context, in struct {
		Targets string `json:"targets,omitempty"`
		Claimed string `json:"claimed,omitempty"`
	}) (app.Report, error) {
		scope := in.Targets
		if scope == "" {
			scope = "core"
		}
		return svc.RouteReturn(ctx, scope, in.Claimed)
	})
	add(s, svc, mode, "latency_map", "Ping a target from several vantages.", false, "", ro, func(ctx context.Context, in struct {
		Target  string   `json:"target"`
		Regions []string `json:"regions,omitempty"`
	}) (app.Report, error) {
		return svc.Latency(ctx, in.Target)
	})
	add(s, svc, mode, "port_check", "See which vantages can open a TCP port.", false, "", ro, func(ctx context.Context, in struct {
		Target string `json:"target"`
		Port   int    `json:"port"`
		From   string `json:"from,omitempty"`
	}) (app.Report, error) {
		return svc.PortCheck(ctx, in.Target, in.Port, in.From)
	})
	add(s, svc, mode, "unlock_check", "Check AI and streaming services from this egress.", true, "ipd unlock", ro, func(ctx context.Context, in struct {
		Services []string `json:"services,omitempty"`
		Proxy    string   `json:"proxy,omitempty"`
	}) (app.Report, error) {
		return svc.Unlock(ctx, in.Services), nil
	})
	add(s, svc, mode, "ai_env_check", "Decide whether this egress is safe for Claude, ChatGPT, and the other AI apps, and what to fix first.", true, "ipd ai", ro, func(ctx context.Context, in struct {
		Proxy             string `json:"proxy,omitempty"`
		IncludeCLIRuntime bool   `json:"include_cli_runtime,omitempty"`
	}) (app.Report, error) {
		return svc.AIEnv(ctx, in.IncludeCLIRuntime), nil
	})
	add(s, svc, mode, "dns_leak_test", "Compare the system resolver with the egress country.", true, "ipd leak", ro, func(ctx context.Context, in struct {
		Rounds int `json:"rounds,omitempty"`
	}) (app.Report, error) {
		return svc.DNSLeak(ctx, in.Rounds), nil
	})
	add(s, svc, mode, "node_batch_check", "Check a local Clash subscription and rename the nodes. Credentials stay on this machine.", true, "ipd nodes", ro, func(ctx context.Context, in struct {
		Source         string   `json:"source"`
		Checks         []string `json:"checks,omitempty"`
		RenameTemplate string   `json:"rename_template,omitempty"`
	}) (app.Report, error) {
		return svc.Nodes(ctx, in.Source, nil)
	})
	add(s, svc, mode, "job_get", "Fetch an async job.", false, "", ro, func(ctx context.Context, in struct {
		JobID string `json:"job_id"`
		WaitS int    `json:"wait_s,omitempty"`
	}) (app.Report, error) {
		return svc.Job(in.JobID)
	})
	add(s, svc, mode, "sources_status", "List dataset versions, licenses, and attribution.", false, "", ro, func(ctx context.Context, in struct{}) (app.Report, error) {
		return svc.Sources(), nil
	})
	add(s, svc, mode, "watch_create", "Watch an address and POST a signed webhook when it changes.", false, "", write, func(ctx context.Context, in struct {
		Target  string   `json:"target"`
		Checks  []string `json:"checks,omitempty"`
		Webhook string   `json:"webhook,omitempty"`
	}) (app.Report, error) {
		return svc.CreateWatch(in.Target, strings.Join(in.Checks, ","), in.Webhook)
	})
	add(s, svc, mode, "watch_list", "List watches.", false, "", ro, func(ctx context.Context, in struct{}) (app.Report, error) {
		return svc.ListWatches()
	})
	add(s, svc, mode, "watch_delete", "Delete a watch.", false, "", write, func(ctx context.Context, in struct {
		WatchID string `json:"watch_id"`
	}) (app.Report, error) {
		if err := svc.DeleteWatch(in.WatchID); err != nil {
			return app.Report{}, err
		}
		return app.Report{Verdict: "ok", Summary: "deleted " + in.WatchID, Data: map[string]any{"watch_id": in.WatchID}, Sources: []app.Source{}, CachedAt: time.Now().UTC()}, nil
	})

	s.AddResource(&mcp.Resource{URI: "ipd://methodology", Name: "methodology", MIMEType: "text/markdown", Description: "How ipd scores and when it abstains"}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{
			URI: "ipd://methodology", MIMEType: "text/markdown", Text: Methodology(),
		}}}, nil
	})
	s.AddResource(&mcp.Resource{URI: "ipd://sources", Name: "sources", MIMEType: "application/json", Description: "Dataset versions and licenses"}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		rep := svc.Sources()
		b, _ := json.Marshal(rep.Data)
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{
			URI: "ipd://sources", MIMEType: "application/json", Text: string(b),
		}}}, nil
	})
	s.AddPrompt(&mcp.Prompt{Name: "diagnose_ai_ban", Description: "Figure out why Claude or ChatGPT is failing on this egress", Arguments: []*mcp.PromptArgument{{Name: "notes", Description: "What the user already tried"}}}, func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		notes := ""
		if req.Params != nil && req.Params.Arguments != nil {
			notes = req.Params.Arguments["notes"]
		}
		return &mcp.GetPromptResult{Messages: []*mcp.PromptMessage{{
			Role:    "user",
			Content: &mcp.TextContent{Text: "Call ai_env_check, then ip_risk_explain on the egress IP. Lead with the verdict and the first fix. Notes: " + notes},
		}}}, nil
	})
	s.AddPrompt(&mcp.Prompt{Name: "vet_vps_before_buy", Description: "Check route, block status, and IP quality before buying a VPS"}, func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		return &mcp.GetPromptResult{Messages: []*mcp.PromptMessage{{
			Role:    "user",
			Content: &mcp.TextContent{Text: "Call ip_risk_explain, route_forward, and gfw_check. Compare route_class with the seller's claim. Say whether the address is blocked, partially blocked, or just congested, and do not confuse that with 送中."},
		}}}, nil
	})
	return s
}

func add[In any](s *mcp.Server, svc *app.Service, mode, name, desc string, local bool, hint string, ann *mcp.ToolAnnotations, fn func(context.Context, In) (app.Report, error)) {
	mcp.AddTool(s, &mcp.Tool{Name: name, Description: desc, Annotations: ann}, func(ctx context.Context, req *mcp.CallToolRequest, in In) (*mcp.CallToolResult, Out, error) {
		if mode == ModeHTTP && local {
			cmd := hint
			if cmd == "" {
				cmd = "ipd " + strings.ReplaceAll(name, "_", " ")
			}
			return nil, Out{}, fmt.Errorf("requires_egress_run: %s", cmd)
		}
		rep, err := fn(ctx, in)
		if err != nil {
			return nil, Out{}, err
		}
		out, err := toOut(rep)
		if err != nil {
			return nil, Out{}, err
		}
		text := "VERDICT: " + out.Verdict + " — " + oneLine(out.SummaryMD)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, out, nil
	})
}

func toOut(r app.Report) (Out, error) {
	b, err := json.Marshal(r.Data)
	if err != nil {
		return Out{}, err
	}
	var m map[string]any
	if len(b) > 0 && string(b) != "null" {
		if err := json.Unmarshal(b, &m); err != nil {
			m = map[string]any{"value": json.RawMessage(b)}
		}
	}
	if m == nil {
		m = map[string]any{}
	}
	src := r.Sources
	if src == nil {
		src = []app.Source{}
	}
	sum := r.Summary
	if len(sum) > 600 {
		sum = sum[:600]
	}
	return Out{Verdict: r.Verdict, SummaryMD: sum, Data: m, Sources: src, CachedAt: r.CachedAtRFC()}, nil
}

func oneLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// Handler is the Streamable HTTP endpoint mounted at /mcp.
func Handler(svc *app.Service) http.Handler {
	server := Server(svc, ModeHTTP)
	return mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{
		Stateless:                  true,
		JSONResponse:               true,
		DisableLocalhostProtection: true,
	})
}

// ServeStdio blocks, serving MCP on stdin/stdout.
func ServeStdio(ctx context.Context, svc *app.Service) error {
	return Server(svc, ModeStdio).Run(ctx, &mcp.StdioTransport{})
}

// Methodology is the short scoring note served as a resource.
func Methodology() string {
	return strings.TrimSpace(`
# ipd methodology

Purity starts at 100. Each factor in models/purity.yaml subtracts a published weight. There is no paid adjustment.

Residential class is a hard rule followed by the tree in models/residential.json. If the winning probability is below 0.55 the class is abstain (无法判定). A prefix registered to an access ISP but announced by a hoster, colocated with a datacenter, or missing rDNS is isp_static with suspected_fake_residential.

Native means the RIR country, the geo country, the announcer country, and geofeed agree, and RTT does not put the address somewhere else. Otherwise the call is broadcast, or abstain when the inputs are missing.

被墙 means China probes cannot reach the target while an overseas control can. 送中 means Google sends the egress to google.cn or google.com.hk. They are different faults.

WebRTC candidate addresses are judged in the browser and are not stored.
`)
}
