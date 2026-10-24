package api

import (
	"encoding/json"
	"fmt"
	"strings"
)

// OpenAPI is the OpenAPI 3.1 document for the HTTP surface.
func OpenAPI() []byte {
	doc := map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title":       "ipd",
			"version":     "0.9.0",
			"summary":     "Agent-first IP intelligence and network-quality checks.",
			"description": "Passive lookups may name any public IP. Egress checks (AI, unlock, leak, return route) must run on the egress via the CLI or MCP stdio. The server never fetches a user-supplied URL.",
		},
		"paths": paths(),
		"components": map[string]any{
			"schemas": map[string]any{
				"Report": map[string]any{
					"type":     "object",
					"required": []string{"verdict", "summary_md", "data", "sources"},
					"properties": map[string]any{
						"verdict":     map[string]any{"type": "string"},
						"summary_md":  map[string]any{"type": "string"},
						"data":        map[string]any{"type": "object"},
						"sources":     map[string]any{"type": "array"},
						"cached_at":   map[string]any{"type": "string"},
						"attribution": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					},
				},
			},
		},
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return []byte(`{"openapi":"3.1.0","info":{"title":"ipd","version":"0.9.0"},"paths":{}}`)
	}
	return append(b, '\n')
}

func paths() map[string]any {
	rep := map[string]any{"description": "Negotiated report", "content": map[string]any{
		"text/plain":       map[string]any{"schema": map[string]any{"type": "string"}},
		"application/json": map[string]any{"schema": map[string]any{"$ref": "#/components/schemas/Report"}},
		"text/markdown":    map[string]any{"schema": map[string]any{"type": "string"}},
	}}
	ok := map[string]any{"200": rep}
	get := func(summary string) map[string]any {
		return map[string]any{"get": map[string]any{"summary": summary, "responses": ok}}
	}
	post := func(summary string) map[string]any {
		return map[string]any{"post": map[string]any{"summary": summary, "responses": ok}}
	}
	return map[string]any{
		"/":                   get("Caller verdict, or the HTML UI for browsers"),
		"/healthz":            get("Liveness"),
		"/metrics":            get("Prometheus text, intranet by default"),
		"/openapi.json":       get("This document"),
		"/llms.txt":           get("LLM usage card"),
		"/llms-full.txt":      get("Usage card plus methodology"),
		"/v1/methodology":     get("Scoring methodology"),
		"/v1/sources":         get("Dataset versions, licenses, attribution"),
		"/v1/me":              get("Egress profile of the caller"),
		"/v1/ip/{ip}":         get("Geo, ASN, and disagreements"),
		"/v1/ip/{ip}/risk":    get("Purity, residential class, native versus broadcast"),
		"/v1/ip/{ip}/history": get("Field change timeline"),
		"/v1/asn/{asn}":       get("Autonomous system"),
		"/v1/prefix/{cidr}":   get("Prefix neighbour composition"),
		"/v1/batch":           post("Up to 1000 addresses"),
		"/v1/gfw":             post("China reachability state machine"),
		"/v1/route":           post("Forward route from China"),
		"/v1/route/targets":   get("Return-path target list"),
		"/v1/latency":         post("Latency map"),
		"/v1/jobs/{id}":       get("Async job"),
		"/v1/dnsleak/{token}": get("DNS leak token"),
		"/v1/report":          post("Upload a redacted egress report when sharing is enabled"),
		"/r/{id}":             get("Shared report"),
		"/v1/watch":           post("Create a watch"),
		"/v1/watch/{id}":      map[string]any{"get": map[string]any{"summary": "List watches", "responses": ok}, "delete": map[string]any{"summary": "Delete a watch", "responses": ok}},
		"/v1/label":           post("Opt-in training label, feature-flagged"),
		"/v1/leak/webrtc":     post("Store a local WebRTC verdict without candidate IPs"),
		"/v1/fingerprint":     get("JA3, JA4, and TCP fingerprint last seen"),
		"/v1/pow":             get("Proof-of-work challenge for heavy tasks"),
		"/mcp":                map[string]any{"post": map[string]any{"summary": "MCP Streamable HTTP", "responses": map[string]any{"200": map[string]any{"description": "JSON-RPC"}}}},
	}
}

// LintOpenAPI checks the structural rules we require of the document.
func LintOpenAPI(doc []byte) error {
	var v map[string]any
	if err := json.Unmarshal(doc, &v); err != nil {
		return err
	}
	if v["openapi"] != "3.1.0" {
		return fmt.Errorf("openapi version")
	}
	info, _ := v["info"].(map[string]any)
	if info["title"] == "" || info["version"] == "" {
		return fmt.Errorf("info")
	}
	paths, _ := v["paths"].(map[string]any)
	if len(paths) < 10 {
		return fmt.Errorf("paths")
	}
	for p, raw := range paths {
		item, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("%s not an item", p)
		}
		for method, opRaw := range item {
			op, ok := opRaw.(map[string]any)
			if !ok {
				return fmt.Errorf("%s %s", method, p)
			}
			responses, _ := op["responses"].(map[string]any)
			if len(responses) == 0 {
				return fmt.Errorf("%s %s missing responses", method, p)
			}
		}
	}
	if strings.Contains(string(doc), "candidate_ip") {
		return fmt.Errorf("webrtc candidate ip leaked into the spec")
	}
	return nil
}

// LLMS is the agent usage card. domain comes from IPD_DOMAIN.
func LLMS(domain string) string {
	if domain == "" {
		domain = "localhost"
	}
	return strings.TrimSpace(fmt.Sprintf(`
# ipd — IP intelligence & network-quality for agents
> Ask: is this egress safe for Claude/ChatGPT/TikTok? Is this IP truly residential/native? Is this VPS blocked in China / what route?
- Quick: curl https://%s/   |  JSON: curl -H 'Accept: application/json' https://%s/v1/me
- Egress-side checks (AI/unlock/leak/return-route) MUST run on the egress: `+"`npx ipd-cli check`"+` or MCP stdio `+"`ipd mcp`"+`.
- MCP: https://%s/mcp (HTTP) | `+"`ipd mcp`"+` (stdio). Tools: whoami, ip_lookup, ip_risk_explain, ip_batch, asn_lookup, prefix_neighbors, ip_history, gfw_check, google_region_check, route_forward, route_return, latency_map, port_check, unlock_check, ai_env_check, dns_leak_test, node_batch_check, job_get, sources_status, watch_create, watch_list, watch_delete.
- Every answer starts with a verdict line; factors[] explains the score; sources[] shows raw provider fields.
- Low confidence is reported as abstain (无法判定). Sharing is off unless IPD_SHARE_ENABLED=true. The server does not store WebRTC candidate addresses.
`, domain, domain, domain)) + "\n"
}
