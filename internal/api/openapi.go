package api

import (
	"encoding/json"
	"fmt"
	"strings"
)

// OpenAPI describes the implemented HTTP surface, including its negotiation rules.
func OpenAPI() []byte {
	doc := map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title": "ipd", "version": "0.9.0", "summary": "Agent-first IP intelligence and network-quality checks.",
			"description": "Passive lookups accept IP addresses. Egress-side AI, unlock, leak and return-route checks must run on the egress via CLI or MCP stdio; HTTP does not execute those tools on a remote caller's machine. Report responses are negotiated, NOT always JSON under /v1. REST handler errors are plain text; delegated MCP protocol errors may be JSON-RPC JSON. Optional share and label submission require explicit configuration; watch creation is an opt-in write, not a feature-flagged endpoint. MCP and optional agent subtrees are delegated transports, not Report APIs. See docs/http-contract.md for limits of structural validation.",
		},
		"paths":      paths(),
		"components": map[string]any{"schemas": reportSchemas()},
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return []byte(`{"openapi":"3.1.0","info":{"title":"ipd","version":"0.9.0"},"paths":{}}`)
	}
	return append(b, '\n')
}

type oa = map[string]any

func schemaRef(name string) oa           { return oa{"$ref": "#/components/schemas/" + name} }
func stringSchema(description string) oa { return oa{"type": "string", "description": description} }
func objectSchema(properties oa, required ...string) oa {
	s := oa{"type": "object", "properties": properties}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}
func arraySchema(items oa) oa { return oa{"type": "array", "items": items} }
func reportWithData(data oa) oa {
	return oa{"allOf": []any{schemaRef("Report"), objectSchema(oa{"data": data})}}
}
func reportSchemas() oa {
	timestamp := oa{"type": "string", "format": "date-time", "description": "RFC3339 timestamp, including fractional seconds. A Go zero time serializes as 0001-01-01T00:00:00Z; not necessarily a measurement time."}
	nullableStrings := oa{"type": []string{"array", "null"}, "items": oa{"type": "string"}}
	source := objectSchema(oa{"id": stringSchema("Provider or dataset identifier."), "attribution": oa{"type": "string"}, "license": oa{"type": "string"}, "raw": oa{}}, "id")
	report := objectSchema(oa{
		"verdict":    stringSchema("Open-ended verdict; abstain / cannot determine mean unknown, not false or safe."),
		"summary_md": oa{"type": "string"}, "data": oa{"description": "Operation-specific JSON value; additional fields may be added."},
		"sources":   oa{"type": []string{"array", "null"}, "items": schemaRef("Source")},
		"cached_at": timestamp, "snapshot_at": oa{"type": "string", "format": "date-time", "description": "Prefix snapshot clock: older of DB-IP and BGP, not the response creation time. Zero time means unavailable."},
		"snapshot_age_seconds": oa{"type": "integer", "minimum": 0, "description": "Age in seconds of the older prefix snapshot clock (DB-IP / BGP), clamped at zero. Zero also represents an unavailable clock; this is not request duration or a live-probe timestamp."},
		"attribution":          nullableStrings,
	}, "verdict", "summary_md", "data", "sources", "cached_at", "snapshot_at", "snapshot_age_seconds", "attribution")
	report["description"] = "Common JSON envelope. Nullable arrays reflect nil Go slices. Unknown additional properties are allowed, including future report fields. No universal verdict enum."
	report["examples"] = []any{oa{"verdict": "abstain", "summary_md": "documentationfixture: no observations", "data": oa{}, "sources": []any{}, "cached_at": "0001-01-01T00:00:00Z", "snapshot_at": "2026-01-01T00:00:00Z", "snapshot_age_seconds": 0, "attribution": nil}}
	batchRow := oa{"oneOf": []any{
		objectSchema(oa{"ip": oa{"type": "string"}, "cc": oa{"type": "string"}, "asn": oa{"type": "integer"}, "type": oa{"type": "string"}, "score": oa{"type": "integer"}, "grade": oa{"type": "string"}}, "ip", "cc", "asn", "type", "score", "grade"),
		objectSchema(oa{"ip": oa{"type": "string"}, "error": oa{"type": "string"}}, "ip", "error"),
	}}
	schemas := oa{
		"Source": source, "Report": report, "BatchRow": batchRow,
		"BatchReport":         reportWithData(objectSchema(oa{"results": arraySchema(schemaRef("BatchRow"))}, "results")),
		"JobSubmissionReport": reportWithData(objectSchema(oa{"job_id": oa{"type": "string"}, "status": oa{"const": "done"}, "result": oa{"description": "The completed operation's data only, NOT a nested Report."}}, "job_id", "status", "result")),
		"JobReport":           reportWithData(objectSchema(oa{"status": oa{"type": "string"}, "result": oa{"anyOf": []any{schemaRef("Report"), oa{"type": "object", "maxProperties": 0}}, "description": "Stored full Report for jobs created by these HTTP routes, or {} when no result is stored. Stored reports are not retroactively snapshot-enriched."}}, "status", "result")),
		"WatchCreatedReport":  reportWithData(objectSchema(oa{"watch_id": oa{"type": "string"}, "next_run": timestamp, "secret": stringSchema("Generated per-watch signing secret, returned only on creation; do not publish it.")}, "watch_id", "next_run", "secret")),
		"WatchListReport":     reportWithData(objectSchema(oa{"watches": arraySchema(objectSchema(oa{"watch_id": oa{"type": "string"}, "target": oa{"type": "string"}, "checks": stringSchema("Comma-joined checks, not an array."), "next_run": timestamp}, "watch_id", "target", "checks", "next_run"))}, "watches")),
		"WatchDeletedReport":  reportWithData(objectSchema(oa{"watch_id": oa{"type": "string"}}, "watch_id")),
		"ShareCreatedReport":  reportWithData(objectSchema(oa{"id": oa{"type": "string"}, "body": oa{"type": "string"}}, "id", "body")),
		"SharedReport":        reportWithData(objectSchema(oa{"body": oa{"type": "string"}}, "body")),
		"LabelReport":         reportWithData(objectSchema(oa{"ok": oa{"const": true}}, "ok")),
		"WebRTCReport":        reportWithData(objectSchema(oa{"leak": oa{"type": "boolean"}, "candidate_count": oa{"type": "integer"}}, "leak", "candidate_count")),
		"RiskReport":          reportWithData(objectSchema(oa{"native": objectSchema(oa{"verdict": oa{"type": "string", "enum": []string{"native", "broadcast", "abstain"}, "description": "Three-state classification, not a boolean. Missing evidence is abstain."}})})),
		"PowChallenge":        objectSchema(oa{"challenge": oa{"type": "string"}, "bits": oa{"type": "integer"}}, "challenge", "bits"),
		"Error":               stringSchema("Plain-text http.Error body, generally ending in a newline; not a JSON error envelope."),
		"JSONRPCError":        objectSchema(oa{"jsonrpc": oa{"const": "2.0"}, "id": oa{}, "error": objectSchema(oa{"code": oa{"type": "integer"}, "message": oa{"type": "string"}, "data": oa{}}, "code", "message")}, "jsonrpc", "id", "error"),
		"JSONRPC":             objectSchema(oa{"jsonrpc": oa{"const": "2.0"}, "id": oa{}, "method": oa{"type": "string"}, "params": oa{}, "result": oa{}, "error": oa{}}, "jsonrpc"),
	}

	for name, schema := range payloadSchemas() {
		schemas[name] = schema
	}

	fixture := func(data any) oa {
		return oa{"verdict": "ok", "summary_md": "documentationfixture", "data": data, "sources": []any{}, "cached_at": "0001-01-01T00:00:00Z", "snapshot_at": "0001-01-01T00:00:00Z", "snapshot_age_seconds": 0, "attribution": nil}
	}
	schemas["BatchReport"].(map[string]any)["examples"] = []any{fixture(oa{"results": []any{oa{"ip": "not-an-ip", "error": "invalid ip"}}})}
	schemas["JobSubmissionReport"].(map[string]any)["examples"] = []any{fixture(oa{"job_id": "documentationfixture", "status": "done", "result": oa{"rows": []any{}, "svg": "<svg></svg>"}})}
	schemas["JobReport"].(map[string]any)["examples"] = []any{fixture(oa{"status": "done", "result": fixture(oa{"rows": []any{}, "svg": "<svg></svg>"})})}
	return schemas
}

// Payload schemas name stable wire fields while permitting additive report data.
func payloadSchemas() oa {
	str, integer, number := oa{"type": "string"}, oa{"type": "integer"}, oa{"type": "number"}
	stringsArray := arraySchema(str)
	nullableArray := func(items oa) oa { return oa{"type": []string{"array", "null"}, "items": items} }
	timestamp := oa{"type": "string", "format": "date-time"}
	asn := objectSchema(oa{"asn": integer, "org": str, "type": str}, "asn", "org", "type")
	geo := objectSchema(oa{"cc": str, "city": str, "region": str, "lat": number, "lon": number, "sources": arraySchema(oa{"type": "object"})}, "cc", "sources")
	lookup := objectSchema(oa{"ip": str, "geo": geo, "asn": asn, "rdns": str, "registered_cc": str, "announced_by": arraySchema(integer), "disagreements": nullableArray(oa{"type": "object"}), "conflicts": arraySchema(oa{"type": "object"}), "anycast": oa{"type": "boolean"}}, "ip", "geo", "asn", "rdns", "registered_cc", "announced_by", "disagreements")
	source := objectSchema(oa{"id": str, "version": str, "updated_at": stringSchema("RFC3339 or empty when unknown; not unconditionally date-time."), "license": str, "attribution": str, "enabled": oa{"type": "boolean"}, "kind": str, "rows": integer, "stale": oa{"type": "boolean"}}, "id", "version", "updated_at", "license", "attribution", "enabled", "kind", "rows", "stale")
	target := objectSchema(oa{"province": str, "carrier": str, "ip": str, "name": str, "core": oa{"type": "boolean"}}, "province", "carrier", "ip", "name", "core")
	hop := objectSchema(oa{"ip": str, "asn": integer, "rtt_ms": number, "rdns": str, "geo_cc": str}, "ip", "asn", "rtt_ms")
	path := objectSchema(oa{"carrier": str, "province": str, "probe": str, "hops": nullableArray(hop), "route_class": str, "error": str}, "carrier", "hops", "route_class")
	probe := objectSchema(oa{"asn": integer, "city": str, "icmp": str, "tcp": oa{"type": []string{"object", "null"}, "additionalProperties": str}}, "asn", "city", "icmp", "tcp")
	submission := func(data oa) oa {
		return oa{"allOf": []any{schemaRef("JobSubmissionReport"), objectSchema(oa{"data": objectSchema(oa{"result": data})})}}
	}
	return oa{
		"MeReport":                reportWithData(objectSchema(oa{"asn": integer, "cc": str, "type": str, "purity": objectSchema(oa{"score": integer, "grade": str}, "score", "grade"), "ipv4": str, "ipv6": str}, "asn", "cc", "type", "purity")),
		"LookupReport":            reportWithData(lookup),
		"ASNReport":               reportWithData(objectSchema(oa{"asn": integer, "org": str, "type": str, "cc": str, "prefixes_v4": stringsArray, "prefixes_v6": stringsArray, "upstreams": arraySchema(integer), "peeringdb_type": str, "eyeball_users": integer}, "asn", "org", "type", "cc", "prefixes_v4", "prefixes_v6", "upstreams", "peeringdb_type", "eyeball_users")),
		"PrefixReport":            reportWithData(objectSchema(oa{"cidr": str, "hosts_seen": integer, "composition": oa{"type": "object", "additionalProperties": number}, "contamination": number, "notable": stringsArray}, "cidr", "hosts_seen", "composition", "contamination", "notable")),
		"HistoryReport":           reportWithData(objectSchema(oa{"events": nullableArray(objectSchema(oa{"ts": timestamp, "field": str, "from": str, "to": str}, "ts", "field", "from", "to"))}, "events")),
		"SourcesReport":           reportWithData(objectSchema(oa{"sources": nullableArray(source)}, "sources")),
		"TargetsReport":           reportWithData(objectSchema(oa{"scope": str, "targets": nullableArray(target)}, "scope", "targets")),
		"DNSLeakReport":           reportWithData(objectSchema(oa{"resolvers": arraySchema(objectSchema(oa{"ip": str, "asn": integer, "cc": str, "ecs": str}, "ip", "asn", "cc", "ecs")), "leak": oa{"type": "boolean"}, "token": str}, "resolvers", "leak", "token")),
		"FingerprintReport":       reportWithData(objectSchema(oa{"ip": str, "ja3": str, "ja3_raw": str, "ja4": str, "mss": integer, "ttl": integer, "h2": str, "at": timestamp}, "ip")),
		"GFWSubmissionReport":     submission(objectSchema(oa{"verdict": str, "per_carrier": oa{"type": "object", "additionalProperties": str}, "probes": nullableArray(probe), "control": nullableArray(probe), "confidence": number, "notes": nullableArray(str)}, "verdict", "per_carrier", "probes", "control", "confidence", "notes")),
		"RouteSubmissionReport":   submission(objectSchema(oa{"paths": arraySchema(path), "summary": str}, "paths", "summary")),
		"LatencySubmissionReport": submission(objectSchema(oa{"rows": arraySchema(objectSchema(oa{"probe": str, "cc": str, "city": str, "asn": integer, "rtt_ms": oa{"type": []string{"number", "null"}, "description": "RTT milliseconds, or null when no valid RTT evidence is available; null is not zero latency."}, "loss": oa{"type": []string{"number", "null"}, "description": "Observed packet-loss fraction, or null when unavailable. Failed/unknown samples may still have observed nonzero loss; null is not zero loss."}}, "probe", "cc", "city", "asn", "rtt_ms", "loss")), "svg": str}, "rows", "svg")),
	}
}

func parameter(name, in, description string, schema oa, required bool) oa {
	return oa{"name": name, "in": in, "description": description, "required": required, "schema": schema}
}
func response(description string, content oa) oa {
	return oa{"description": description, "content": content}
}
func media(schema oa) oa { return oa{"schema": schema} }
func textResponse(description, contentType string) oa {
	return response(description, oa{contentType: media(oa{"type": "string"})})
}
func errorResponse(description string) oa {
	return response(description, oa{"text/plain": media(schemaRef("Error"))})
}

func paths() map[string]any {
	paths := oa{}
	// Keep parameters on each operation so even wildcard path templates have an
	// explicit required declaration, as required by OpenAPI 3.1.
	add := func(path, method, summary, description string, success oa, errors oa, params ...oa) oa {
		responses := oa{"200": success, "429": errorResponse("Rate limit exceeded before dispatch (except health, favicon and static assets).")}
		for k, v := range errors {
			responses[k] = v
		}
		params = append(params, parameter("X-API-Key", "header", "Optional configured key selecting keyed rate limits; not mandatory REST authentication.", oa{"type": "string"}, false))
		for _, part := range strings.Split(path, "{")[1:] {
			name := strings.SplitN(part, "}", 2)[0]
			desc := "Path value."
			switch name {
			case "ip":
				desc = "IP address; .json/.txt/.md suffixes are stripped for lookup/risk/history."
			case "asn":
				desc = "ASN string, optionally prefixed AS; suffixes stripped, decimal parsed. Unparseable input is treated as ASN 0, not rejected."
			case "cidr":
				desc = "CIDR including its slash, e.g. 192.0.2.0/24. Go ServeMux consumes the remaining path; suffixes stripped. Clients must preserve the slash."
			case "id":
				desc = "Identifier; on GET watch the value is required by routing but ignored by the implementation."
			case "token":
				desc = "Token echoed into the DNS report; not an asynchronous token lookup."
			case "asset", "path":
				desc = "Remaining subtree path, potentially containing slashes; delegated handler semantics apply."
			}
			params = append(params, parameter(name, "path", desc, oa{"type": "string"}, true))
		}
		for _, raw := range responses {
			resp := raw.(map[string]any)
			headers, _ := resp["headers"].(map[string]any)
			if headers == nil {
				headers = oa{}
				resp["headers"] = headers
			}
			headers["X-IPD-Snapshot-Age"] = oa{"description": "Prefix snapshot age in seconds when a lookup engine is configured; same clock as Report.snapshot_age_seconds, not probe duration.", "schema": oa{"type": "integer", "minimum": 0}}
		}
		op := oa{"summary": summary, "description": description, "responses": responses}
		if len(params) > 0 {
			op["parameters"] = params
		}
		item, ok := paths[path].(map[string]any)
		if !ok {
			item = oa{}
			paths[path] = item
		}
		item[method] = op
		return op
	}
	reportOp := func(path, method, summary, description, schema string, errors oa, params ...oa) oa {
		params = append(params,
			parameter("format", "query", "Recognized values override suffix and Accept; unknown values are ignored. /v1 coerces html to plain text; Render also falls back to plain text outside the root/share HTML branches.", oa{"type": "string", "examples": []string{"json", "md", "markdown", "txt", "text", "plain", "html"}}, false),
			parameter("stream", "query", "Exactly 1 returns a finite SSE local event containing a Report, then done with {}. Not ongoing monitoring; batch NDJSON takes precedence.", oa{"type": "string"}, false))
		description += " Negotiation: recognized ?format overrides suffix, then quality-weighted Accept (JSON/+json, Markdown, plain text, HTML). Missing/wildcard Accept defaults to plain text for /v1 and curl/wget/httpie, HTML for root/share browsers. /v1 HTML becomes plain text. Fixed routes such as /v1/me.json do not exist: suffix selection applies only when the mux route still matches."
		content := oa{"application/json": media(schemaRef(schema)), "text/plain": media(oa{"type": "string"}), "text/markdown": media(oa{"type": "string"}), "text/event-stream": oa{"schema": oa{"type": "string"}, "example": "event: local\ndata: {\"verdict\":\"abstain\",\"summary_md\":\"documentationfixture\",\"data\":{},\"sources\":[],\"cached_at\":\"0001-01-01T00:00:00Z\",\"snapshot_at\":\"0001-01-01T00:00:00Z\",\"snapshot_age_seconds\":0,\"attribution\":null}\n\nevent: done\ndata: {}\n\n"}}
		rep := response("Negotiated Report; success is HTTP 200, including synchronous job submissions.", content)
		rep["headers"] = oa{"X-IPD-Verdict": oa{"description": "Report verdict on non-SSE responses.", "schema": oa{"type": "string"}}}
		return add(path, method, summary, description, rep, errors, params...)
	}
	body := func(op oa, description string, required bool, content oa) {
		op["requestBody"] = oa{"description": description, "required": required, "content": content}
	}
	jsonBody := func(op oa, description string, required bool, schema oa, example any) {
		m := media(schema)
		if example != nil {
			m["example"] = example
		}
		body(op, description, required, oa{"application/json": m})
	}
	bad := oa{"400": errorResponse("Invalid input, unavailable provider/store, or service error; plain text even with Accept: application/json.")}
	add("/healthz", "get", "Liveness", "Fixed response, no negotiation or rate limiting.", oa{"description": "Alive", "content": oa{"text/plain": oa{"schema": oa{"type": "string"}, "example": "ok\n"}}}, nil)
	delete(objectResponses(paths, "/healthz", "get"), "429")
	add("/metrics", "get", "Prometheus metrics", "Non-public clients receive 404 unless metrics are configured public.", textResponse("Prometheus exposition", "text/plain"), oa{"404": errorResponse("Metrics hidden from public clients.")})
	add("/openapi.json", "get", "OpenAPI document", "Fixed JSON, not a Report.", response("OpenAPI 3.1 document", oa{"application/json": media(objectSchema(oa{"openapi": oa{"const": "3.1.0"}, "info": oa{"type": "object"}, "paths": oa{"type": "object"}}, "openapi", "info", "paths"))}), nil)
	for _, p := range []string{"/llms.txt", "/llms-full.txt"} {
		add(p, "get", "Agent usage card", "Fixed text, not a Report.", textResponse("Usage card (full includes methodology)", "text/plain"), nil)
	}
	for _, p := range []string{"/methodology", "/v1/methodology"} {
		add(p, "get", "Scoring methodology", "Fixed Markdown, ignores report negotiation.", textResponse("Methodology", "text/markdown"), nil)
	}
	add("/v1/pow", "get", "Proof-of-work challenge", "Fixed JSON. Solve only when PoW is configured for gfw/route/latency.", response("Challenge and configured bit count", oa{"application/json": media(schemaRef("PowChallenge"))}), nil)
	for _, p := range []string{"/favicon.ico", "/favicon.svg"} {
		add(p, "get", "SVG favicon", "Both paths serve SVG.", textResponse("SVG icon", "image/svg+xml"), oa{"404": errorResponse("Embedded icon unavailable.")})
		delete(objectResponses(paths, p, "get"), "429")
	}
	add("/leak", "get", "Browser UI", "Serves the embedded UI; not an egress probe API.", textResponse("HTML UI", "text/html"), oa{"500": errorResponse("Embedded UI unavailable.")})
	add("/static/{asset}", "get", "Embedded static asset", "Delegated to http.FileServer. Contents and MIME types depend on asset; directory redirects/listing and conditional/range responses follow net/http.", response("Asset", oa{"*/*": media(oa{})}), oa{"default": oa{"description": "FileServer response, including redirects, 206/304, missing assets (404), invalid ranges (416). Not a Report."}})
	delete(objectResponses(paths, "/static/{asset}", "get"), "429")
	root := reportOp("/", "get", "Caller report or browser UI", "HTML selected before stream processing; WhoAmI failures are wrapped as an abstain Report with HTTP 200.", "Report", oa{"500": errorResponse("Embedded UI unavailable.")})
	objectResponsesContent(root)["text/html"] = media(oa{"type": "string"})
	reportOp("/v1/me", "get", "Caller egress profile", "Uses configured egress addresses or caller address, not remote execution of all egress tools.", "MeReport", bad, parameter("ip_version", "query", "4 or 6 selects the preferred configured/caller family; 6 falls back when unavailable, other values use default selection.", oa{"type": "string"}, false))
	reportOp("/v1/sources", "get", "Dataset status and attribution", "Dataset metadata, not active egress tests.", "SourcesReport", nil)
	reportOp("/v1/ip/{ip}", "get", "Passive IP lookup", "Geo, ASN and source disagreements; private/documentation IPs return a reserved verdict.", "LookupReport", bad)
	reportOp("/v1/ip/{ip}/risk", "get", "Risk evidence", "Purity, residential class and native/broadcast/abstain evidence; an unknown verdict is not a boolean false.", "RiskReport", bad, parameter("live", "query", "Exactly 0 disables live enrichment; other values allow it unless offline configuration disables it.", oa{"type": "string", "default": "1"}, false))
	reportOp("/v1/ip/{ip}/history", "get", "Stored change history", "Does not probe the target.", "HistoryReport", bad, parameter("days", "query", "Lookback days; absent, non-integer, <=0 or >365 falls back to 90.", oa{"type": "integer", "default": 90}, false))
	reportOp("/v1/asn/{asn}", "get", "Autonomous system", "No validation error for an unparseable ASN (treated as 0).", "ASNReport", nil)
	reportOp("/v1/prefix/{cidr}", "get", "Prefix neighbour composition", "Remaining path is a CIDR including slash.", "PrefixReport", bad)
	batch := reportOp("/v1/batch", "post", "Batch IP risk lookup", "Reads at most 1 MiB. Tries JSON {ips:[...]}; decode failure or empty ips falls back to nonempty trimmed input lines. Empty input produces zero rows. More than 1000 entries is HTTP 400; invalid individual IPs become error rows with HTTP 200. If Accept contains ndjson, flat newline-delimited rows are returned, overriding format and stream; not a stream of Report envelopes.", "BatchReport", bad)
	jsonBody(batch, "JSON object or newline-separated plain IPs (not NDJSON request objects). Content-Type is not enforced; empty input is accepted.", false, objectSchema(oa{"ips": oa{"type": "array", "items": oa{"type": "string"}, "maxItems": 1000}}), oa{"ips": []string{"192.0.2.1", "2001:db8::1"}})
	objectBodyContent(batch)["text/plain"] = oa{"schema": oa{"type": "string"}, "example": "192.0.2.1\n2001:db8::1\n"}
	objectResponsesContent(batch)["application/x-ndjson"] = oa{"schema": oa{"type": "string", "description": "Each nonempty line validates against BatchRow. Zero results produces an empty body."}, "example": "{\"ip\":\"not-an-ip\",\"error\":\"invalid ip\"}\n"}
	for _, p := range []string{"/v1/gfw", "/v1/route", "/v1/latency"} {
		resultSchema := map[string]string{"/v1/gfw": "GFWSubmissionReport", "/v1/route": "RouteSubmissionReport", "/v1/latency": "LatencySubmissionReport"}[p]
		op := reportOp(p, "post", "Synchronous measurement with job wrapper", "Runs the measurement BEFORE returning HTTP 200 data:{job_id,status:done,result:<operation data>}. No HTTP 202, pending job or async wait contract. Without a DB job_id is job and cannot be retrieved. PoW required only when configured; GFW checks missing target before PoW. Provider errors are HTTP 400.", resultSchema, oa{"400": bad["400"], "401": errorResponse("X-Ipd-Pow missing/invalid when IPD_POW_REQUIRED is enabled.")}, parameter("X-Ipd-Pow", "header", "Optional unless configured; solution to /v1/pow challenge.", oa{"type": "string"}, false))
		props := oa{"target": stringSchema("Measurement target. Always supply a nonempty target. Baseline HTTP decoding validates presence only for GFW; the integrated latency service also rejects empty targets with 400. Permissive decoding does not promise successful execution.")}
		required := []string{}
		if p == "/v1/gfw" {
			props["target"] = oa{"type": "string", "minLength": 1}
			props["ports"] = oa{"type": "array", "items": oa{"type": "integer"}, "description": "Empty defaults to [22,80,443]; at most first five used."}
			required = []string{"target"}
		}
		if p == "/v1/route" {
			props["carriers"] = arraySchema(oa{"type": "string"})
			props["carriers"].(map[string]any)["description"] = "Provider carrier selectors, normally ct/cu/cm; not HTTP-enforced enums."
		}
		jsonBody(op, "JSON decoded without enforcing Content-Type. Baseline decoders can leave zero/default fields on malformed or empty input, but this is not a success guarantee. GFW rejects empty target in HTTP; integrated latency service validation also rejects it. Supply a nonempty target.", p == "/v1/gfw", objectSchema(props, required...), oa{"target": "example.invalid"})
	}
	reportOp("/v1/jobs/{id}", "get", "Read stored job", "For HTTP-created completed jobs, data.result is the FULL stored Report, unlike the submission response which contains only operation data. Missing job/store is 404.", "JobReport", oa{"404": errorResponse("Job not found or no store.")})
	reportOp("/v1/route/targets", "get", "Return-path targets", "Lists configured targets only; actual return-route tracing must run at the egress.", "TargetsReport", nil, parameter("scope", "query", "full selects all; absent defaults to core and any other value selects core (the supplied scope is still echoed).", oa{"type": "string", "default": "core"}, false))
	reportOp("/v1/dnsleak/{token}", "get", "DNS leak report with echoed token", "Calls DNSLeak with one round on this server; token is only echoed, not used to retrieve an async client test. Does not prove a remote caller's DNS path.", "DNSLeakReport", nil)
	upload := reportOp("/v1/report", "post", "Opt-in redacted share upload", "Requires IPD_SHARE_ENABLED and a store. Reads up to 1 MiB of raw text, redacts and stores it. All service errors map to 403.", "ShareCreatedReport", oa{"403": errorResponse("Sharing disabled, no store, or save failure.")})
	body(upload, "Raw report text; not a JSON Report decoder. Empty text is accepted when sharing is enabled.", false, oa{"text/plain": oa{"schema": oa{"type": "string"}, "example": "documentationfixture 192.0.2.1"}})
	shared := reportOp("/r/{id}", "get", "Read an opt-in shared report", "404 when sharing is disabled, missing, or no store. Browser negotiation can return escaped HTML, otherwise a Report whose data.body is redacted text.", "SharedReport", oa{"404": errorResponse("Share unavailable or sharing disabled.")})
	objectResponsesContent(shared)["text/html"] = media(oa{"type": "string"})
	watch := reportOp("/v1/watch", "post", "Opt-in watch creation", "Explicit write, requires a store but no watch feature flag. Generates watch_id, next_run and a secret returned on creation. HTTP does not require target/checks/webhook fields or validate their values. Delivery is outside this request's contract.", "WatchCreatedReport", bad)
	jsonBody(watch, "JSON fields decoded without required-field validation; empty body/fields are accepted with a store.", false, objectSchema(oa{"target": oa{"type": "string"}, "checks": arraySchema(oa{"type": "string"}), "webhook": oa{"type": "string"}}), oa{"target": "192.0.2.1", "checks": []string{"risk"}, "webhook": "https://example.invalid/documentationfixture"})
	reportOp("/v1/watch/{id}", "get", "List ALL watches (id ignored)", "Despite the path, this is ListWatches, not lookup by id; no per-id 404. Lists checks as comma-joined strings, without secrets. No store returns an empty list.", "WatchListReport", bad)
	reportOp("/v1/watch/{id}", "delete", "Delete a watch", "Requires a store; nonexistent ids are not converted to 404.", "WatchDeletedReport", bad)
	label := reportOp("/v1/label", "post", "Opt-in training label", "Requires IPD_LABELS_ENABLED and a store. All service errors map to 403; HTTP does not require fields. Go decoder accepts IP/Label/Note case-insensitively.", "LabelReport", oa{"403": errorResponse("Labels disabled, no store or save failure.")})
	jsonBody(label, "Optional label fields; no required-field validation.", false, objectSchema(oa{"ip": oa{"type": "string"}, "label": oa{"type": "string"}, "note": oa{"type": "string"}}), oa{"ip": "192.0.2.1", "label": "documentationfixture", "note": "documentationfixture"})
	rtc := reportOp("/v1/leak/webrtc", "post", "Store a local WebRTC verdict", "Only leak (boolean) and candidate_count (JSON number converted to integer) are read; all other fields are ignored. Missing/wrong-type fields default to false/0; no DB succeeds without storing. Does not perform remote WebRTC detection.", "WebRTCReport", oa{"500": errorResponse("Store write failed.")})
	jsonBody(rtc, "Only these two fields are retained. No address fields are defined or stored.", false, objectSchema(oa{"leak": oa{"type": "boolean"}, "candidate_count": oa{"type": "number", "description": "Converted to Go int (fractional part truncated); response is integer."}}), oa{"leak": false, "candidate_count": 0})
	reportOp("/v1/fingerprint", "get", "Last observed fingerprint", "No active fingerprint collection request; absent observation returns abstain with HTTP 200.", "FingerprintReport", nil, parameter("ip", "query", "Address to look up; absent uses caller IP. Not validated by HTTP.", oa{"type": "string"}, false))
	// Delegated transports are intentionally not advertised as Report endpoints.
	for _, p := range []string{"/mcp", "/mcp/", "/mcp/{path}"} {
		op := add(p, "post", "MCP Streamable HTTP transport", "Delegated to the MCP SDK (stateless, JSONResponse). Accept must contain both application/json and text/event-stream. Egress-only tools return requires_egress_run over HTTP; use stdio on the egress. Subtree is mounted too; not a new REST endpoint.", response("JSON-RPC response", oa{"application/json": media(schemaRef("JSONRPC")), "text/event-stream": media(oa{"type": "string"})}), oa{"202": oa{"description": "Notification accepted; no response body."}, "400": response("Invalid protocol/header/message: HTTP validation errors may be plain text; SDK protocol errors may be JSON-RPC JSON.", oa{"text/plain": media(schemaRef("Error")), "application/json": media(schemaRef("JSONRPCError"))}), "405": errorResponse("Non-POST method in stateless mode."), "413": errorResponse("SDK request size limit exceeded."), "415": errorResponse("Content-Type must be application/json."), "500": errorResponse("Transport connection failure."), "default": oa{"description": "SDK-managed protocol response; not an ipd Report."}}, parameter("MCP-Protocol-Version", "header", "SDK-supported negotiated protocol version.", oa{"type": "string"}, false))
		jsonBody(op, "JSON-RPC request or notification; full MCP method schemas are owned by the SDK/tools, not REST Report schemas.", true, schemaRef("JSONRPC"), oa{"jsonrpc": "2.0", "id": 1, "method": "ping"})
	}
	for _, p := range []string{"/agent", "/agent/", "/agent/{path}"} {
		op := add(p, "post", "Optional injected agent transport", "Mounted only when Server.Hub is non-nil. Handler is injected and owns its methods, body, status and authentication; not a public Report API. Default probe Hub uses /agent/enroll for enrollment and WebSocket upgrade elsewhere.", response("Injected handler response", oa{"application/json": media(oa{})}), oa{"default": oa{"description": "Injected handler response, or mux 404 when absent; no universal envelope."}})
		body(op, "Opaque body owned by the configured handler; no ipd REST schema.", false, oa{"application/json": media(oa{})})
		add(p, "get", "Optional agent WebSocket transport", "Injected Server.Hub only; normally WebSocket upgrade, not an HTTP Report. This documents an existing mount, not a new endpoint.", response("Injected handler response", oa{"application/octet-stream": media(oa{})}), oa{"101": oa{"description": "WebSocket upgrade when provided by the injected handler."}, "default": oa{"description": "Injected handler owns response, or 404 if absent."}})
	}
	return paths
}
func objectResponses(paths oa, path, method string) oa {
	return paths[path].(map[string]any)[method].(map[string]any)["responses"].(map[string]any)
}
func objectResponsesContent(op oa) oa {
	return op["responses"].(map[string]any)["200"].(map[string]any)["content"].(map[string]any)
}
func objectBodyContent(op oa) oa {
	return op["requestBody"].(map[string]any)["content"].(map[string]any)
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
