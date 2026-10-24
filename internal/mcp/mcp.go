// Package mcp exposes ipd tools over stdio and Streamable HTTP.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

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
	Verdict            string         `json:"verdict"`
	SummaryMD          string         `json:"summary_md"`
	Data               map[string]any `json:"data"`
	Sources            []app.Source   `json:"sources"`
	CachedAt           string         `json:"cached_at"`
	SnapshotAt         string         `json:"snapshot_at"`
	SnapshotAgeSeconds int64          `json:"snapshot_age_seconds"`
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
	add(s, svc, mode, "ip_lookup", "Look up geo, ASN, registry country, and source disagreements for an IP. Field selection is unsupported; returns the full report.", false, "", ro, func(ctx context.Context, in struct {
		IP     string   `json:"ip" jsonschema:"IPv4 or IPv6 address"`
		Fields []string `json:"fields,omitempty" jsonschema:"Unsupported selection; omit or pass an empty array for the full report. Non-empty values return unsupported_option."`
	}) (app.Report, error) {
		if len(in.Fields) != 0 {
			return app.Report{}, unsupportedOption("fields", "omit fields to receive the full report and select fields client-side")
		}
		return svc.LookupIP(ctx, in.IP)
	})
	add(s, svc, mode, "ip_risk_explain", "Explain purity, residential class, and native versus broadcast.", false, "", ro, func(ctx context.Context, in struct {
		IP          string `json:"ip"`
		IncludeLive bool   `json:"include_live,omitempty"`
	}) (app.Report, error) {
		return svc.Risk(ctx, in.IP, in.IncludeLive && !svc.Cfg.Offline)
	})
	add(s, svc, mode, "ip_batch", "Look up to 1000 addresses. Field selection is unsupported; returns the full report.", false, "", ro, func(ctx context.Context, in struct {
		IPs    []string `json:"ips"`
		Fields []string `json:"fields,omitempty" jsonschema:"Unsupported selection; omit or pass an empty array for the full report. Non-empty values return unsupported_option."`
	}) (app.Report, error) {
		if len(in.Fields) != 0 {
			return app.Report{}, unsupportedOption("fields", "omit fields to receive the full report and select fields client-side")
		}
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
	add(s, svc, mode, "gfw_check", "Decide whether a target is blocked from China, and how. Always synchronous; the wait option is unsupported.", false, "", ro, func(ctx context.Context, in struct {
		Target string `json:"target"`
		Ports  []int  `json:"ports,omitempty"`
		Wait   bool   `json:"wait,omitempty" jsonschema:"Unsupported wait mode; omit or pass false to retain synchronous behavior. True returns unsupported_option; false does not request an async job."`
	}) (app.Report, error) {
		if in.Wait {
			return app.Report{}, unsupportedOption("wait", "omit wait or pass false; gfw_check is synchronous, as is ipd gfw <target>")
		}
		return svc.GFW(ctx, in.Target, in.Ports)
	})
	add(s, svc, mode, "google_region_check", "Detect whether Google treats this egress as mainland China (送中). Per-call proxy overrides are unsupported; uses the process proxy configuration.", true, "ipd unlock google_region youtube_premium", ro, func(ctx context.Context, in struct {
		Proxy string `json:"proxy,omitempty" jsonschema:"Unsupported per-call override; omit or pass an empty string to use process configuration. Set IPD_PROXY before starting ipd mcp. Non-empty values return unsupported_option."`
	}) (app.Report, error) {
		if in.Proxy != "" {
			return app.Report{}, unsupportedOption("proxy", proxyAdvice)
		}
		return svc.GoogleRegion(ctx), nil
	})
	add(s, svc, mode, "route_forward", "Trace from China carriers toward a target and classify the path. Protocol selection is unsupported; uses the provider default.", false, "", ro, func(ctx context.Context, in struct {
		Target   string   `json:"target"`
		Carriers []string `json:"carriers,omitempty"`
		Proto    string   `json:"proto,omitempty" jsonschema:"Unsupported protocol selection; omit or pass an empty string for the provider default. Any non-empty value returns unsupported_option."`
	}) (app.Report, error) {
		if in.Proto != "" {
			return app.Report{}, unsupportedOption("proto", "omit proto to use the provider default; ipd route <target> also uses that default, with no CLI protocol selector")
		}
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
	add(s, svc, mode, "latency_map", "Ping a target from the configured China-carrier and overseas-control vantages. Region selection is unsupported.", false, "", ro, func(ctx context.Context, in struct {
		Target  string   `json:"target"`
		Regions []string `json:"regions,omitempty" jsonschema:"Unsupported region selection; omit or pass an empty array for fixed vantages. Non-empty values return unsupported_option. IPD_VANTAGE selects a provider, not regions."`
	}) (app.Report, error) {
		if len(in.Regions) != 0 {
			return app.Report{}, unsupportedOption("regions", "omit regions to use fixed China-carrier and overseas-control probes; IPD_VANTAGE selects the provider, not regions; no CLI region selector is available")
		}
		return svc.Latency(ctx, in.Target)
	})
	add(s, svc, mode, "port_check", "See which configured China-carrier and overseas-control vantages can open a TCP port. The from selector is unsupported.", false, "", ro, func(ctx context.Context, in struct {
		Target string `json:"target"`
		Port   int    `json:"port"`
		From   string `json:"from,omitempty" jsonschema:"Unsupported vantage selection; omit or pass an empty string for fixed vantages. Any non-empty value, including global, returns unsupported_option. IPD_VANTAGE selects a provider, not locations."`
	}) (app.Report, error) {
		if in.From != "" {
			return app.Report{}, unsupportedOption("from", "omit from to use fixed China-carrier and overseas-control probes; IPD_VANTAGE selects the provider, not locations; no CLI location selector is available")
		}
		return svc.PortCheck(ctx, in.Target, in.Port, in.From)
	})
	add(s, svc, mode, "unlock_check", "Check AI and streaming services from this egress. Per-call proxy overrides are unsupported; uses the process proxy configuration.", true, "ipd unlock", ro, func(ctx context.Context, in struct {
		Services []string `json:"services,omitempty"`
		Proxy    string   `json:"proxy,omitempty" jsonschema:"Unsupported per-call override; omit or pass an empty string to use process configuration. Set IPD_PROXY before starting ipd mcp. Non-empty values return unsupported_option."`
	}) (app.Report, error) {
		if in.Proxy != "" {
			return app.Report{}, unsupportedOption("proxy", proxyAdvice)
		}
		return svc.Unlock(ctx, in.Services), nil
	})
	add(s, svc, mode, "ai_env_check", "Decide whether this egress is safe for Claude, ChatGPT, and the other AI apps, and what to fix first. Per-call proxy overrides are unsupported; uses the process proxy configuration.", true, "ipd ai", ro, func(ctx context.Context, in struct {
		Proxy             string `json:"proxy,omitempty" jsonschema:"Unsupported per-call override; omit or pass an empty string to use process configuration. Set IPD_PROXY before starting ipd mcp. Non-empty values return unsupported_option."`
		IncludeCLIRuntime bool   `json:"include_cli_runtime,omitempty"`
	}) (app.Report, error) {
		if in.Proxy != "" {
			return app.Report{}, unsupportedOption("proxy", proxyAdvice)
		}
		return svc.AIEnv(ctx, in.IncludeCLIRuntime), nil
	})
	add(s, svc, mode, "dns_leak_test", "Compare the system resolver with the egress country.", true, "ipd leak", ro, func(ctx context.Context, in struct {
		Rounds int `json:"rounds,omitempty"`
	}) (app.Report, error) {
		return svc.DNSLeak(ctx, in.Rounds), nil
	})
	add(s, svc, mode, "node_batch_check", "Check a local Clash subscription using the existing fixed checks and stock rename. Custom checks and rename_template are unsupported. Credentials stay on this machine.", true, "ipd nodes <source>", ro, func(ctx context.Context, in struct {
		Source         string   `json:"source"`
		Checks         []string `json:"checks,omitempty" jsonschema:"Unsupported check selection; omit or pass an empty array for fixed checks. Non-empty values return unsupported_option."`
		RenameTemplate string   `json:"rename_template,omitempty" jsonschema:"Unsupported rename customization; omit or pass an empty string for stock rename. Non-empty values return unsupported_option."`
	}) (app.Report, error) {
		if len(in.Checks) != 0 {
			return app.Report{}, unsupportedOption("checks", "omit checks to use fixed checks; ipd nodes <source> uses the same pipeline, with no CLI check selector")
		}
		if in.RenameTemplate != "" {
			return app.Report{}, unsupportedOption("rename_template", "omit rename_template to use the stock rename; ipd nodes <source> uses the same naming, with no CLI template selector")
		}
		return svc.Nodes(ctx, in.Source, nil)
	})
	add(s, svc, mode, "job_get", "Fetch an async job's current state once. Long polling with wait_s is unsupported.", false, "", ro, func(ctx context.Context, in struct {
		JobID string `json:"job_id"`
		WaitS int    `json:"wait_s,omitempty" jsonschema:"Unsupported long polling; omit or pass 0 for an immediate snapshot. Any nonzero value returns unsupported_option; poll job_get client-side instead."`
	}) (app.Report, error) {
		if in.WaitS != 0 {
			return app.Report{}, unsupportedOption("wait_s", "omit wait_s or use 0 for an immediate snapshot; poll job_get client-side with job_id; no CLI wait flag is available")
		}
		return svc.Job(in.JobID)
	})
	add(s, svc, mode, "sources_status", "List dataset versions, licenses, and attribution.", false, "", ro, func(ctx context.Context, in struct{}) (app.Report, error) {
		return svc.Sources(), nil
	})
	add(s, svc, mode, "watch_create", "Watch an address's fixed risk snapshot and POST a signed webhook when it changes. Custom checks are unsupported.", false, "", write, func(ctx context.Context, in struct {
		Target  string   `json:"target"`
		Checks  []string `json:"checks,omitempty" jsonschema:"Unsupported check selection; omit or pass an empty array for the fixed risk snapshot. Non-empty values return unsupported_option; storing a selector would not execute it."`
		Webhook string   `json:"webhook,omitempty"`
	}) (app.Report, error) {
		if len(in.Checks) != 0 {
			return app.Report{}, unsupportedOption("checks", "omit checks to watch the fixed risk snapshot; ipd watch add <ip> [webhook] uses the same check, with no CLI check selector")
		}
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

const proxyAdvice = "omit proxy and configure IPD_PROXY before starting ipd mcp, or use the CLI global --proxy URL flag; no per-call proxy is applied"

func unsupportedOption(name, advice string) error {
	// Do not echo values: proxy URLs and subscription options may hold secrets.
	return fmt.Errorf("unsupported_option: %s is not supported by this MCP tool; %s", name, advice)
}

func add[In any](s *mcp.Server, svc *app.Service, mode, name, desc string, local bool, hint string, ann *mcp.ToolAnnotations, fn func(context.Context, In) (app.Report, error)) {
	mcp.AddTool(s, &mcp.Tool{Name: name, Description: desc, Annotations: ann}, func(ctx context.Context, req *mcp.CallToolRequest, in In) (*mcp.CallToolResult, Out, error) {
		if mode == ModeHTTP && local {
			cmd := hint
			if cmd == "" {
				cmd = "ipd " + strings.ReplaceAll(name, "_", " ")
			}
			return nil, Out{}, fmt.Errorf("requires_egress_run: %s (run on the egress machine; HTTP has not applied any per-call options)", cmd)
		}
		rep, err := fn(ctx, in)
		if err != nil {
			return nil, Out{}, err
		}
		rep = svc.WithSnapshot(rep)
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
		end := 600
		for !utf8.RuneStart(sum[end]) {
			end--
		}
		sum = sum[:end]
	}
	at := ""
	if !r.SnapshotAt.IsZero() {
		at = r.SnapshotAt.UTC().Format(time.RFC3339)
	}
	return Out{Verdict: r.Verdict, SummaryMD: sum, Data: m, Sources: src, CachedAt: r.CachedAtRFC(), SnapshotAt: at, SnapshotAgeSeconds: r.SnapshotAgeSeconds}, nil
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

Residential class is a hard rule followed by the tree in models/residential.json, then an evidence gate. rDNS patterns, prefix age, neighbour signals, and RIR org type have to support the call. Below 0.70 confidence, or with only one weak feature, the class is "cannot determine" (无法判定). A prefix registered to an access ISP but announced by a hoster is isp_static with suspected_fake_residential. Country, ASN, and city conflicts are listed with source weights. 1.1.1.0/24 is anycast even though Cloudflare's published proxy ranges omit it.

被墙 requires two healthy probes on a carrier and two carriers. One failed probe is insufficient_sample. Globalping stays inside 250 anonymous measurements per hour (500 with a token) and 50 probes per measurement.

Native means the RIR country, the geo country, the announcer country, and geofeed agree, and RTT does not put the address somewhere else. Otherwise the call is broadcast, or abstain when the inputs are missing.

被墙 means China probes cannot reach the target while an overseas control can. 送中 means Google sends the egress to google.cn or google.com.hk. They are different faults.

WebRTC candidate addresses are judged in the browser and are not stored.
`)
}
