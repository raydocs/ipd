package api

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"ipd/internal/app"
	"ipd/internal/config"
	"ipd/internal/lookup"
	"ipd/internal/probe"
	"ipd/internal/store"
)

func contractDoc(t *testing.T) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(OpenAPI(), &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}
func object(t *testing.T, v any) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("expected object, got %T", v)
	}
	return m
}
func operation(t *testing.T, doc map[string]any, path, method string) map[string]any {
	t.Helper()
	paths := object(t, doc["paths"])
	item, ok := paths[path].(map[string]any)
	if !ok {
		t.Fatalf("missing path %s", path)
	}
	op, ok := item[method].(map[string]any)
	if !ok {
		t.Fatalf("missing operation %s %s", method, path)
	}
	return op
}

// Extract registrations from Handler, not a second hand-maintained path list.
// Delegated subtrees have explicit wildcard entries; Go's ... is not OAS syntax.
func TestOpenAPIHandlerCoverageAndParameters(t *testing.T) {
	doc := contractDoc(t)
	src, err := os.ReadFile("http.go")
	if err != nil {
		t.Fatal(err)
	}
	f, err := parser.ParseFile(token.NewFileSet(), "http.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "HandleFunc" && sel.Sel.Name != "Handle") {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok {
			return true
		}
		route, _ := strconv.Unquote(lit.Value)
		parts := strings.SplitN(route, " ", 2)
		method, path := "post", route
		if len(parts) == 2 {
			method, path = strings.ToLower(parts[0]), parts[1]
		}
		path = strings.ReplaceAll(path, "{cidr...}", "{cidr}")
		path = strings.ReplaceAll(path, "{$}", "")
		if path == "/static/" {
			path += "{asset}"
		}
		if path == "/mcp/" || path == "/agent/" {
			path += "{path}"
		}
		item, ok := object(t, doc["paths"])[path].(map[string]any)
		if !ok || item[method] == nil {
			t.Errorf("Handler route %s missing documented operation %s %s", route, method, path)
		}
		return true
	})
	template := regexp.MustCompile(`\{([^}]+)\}`)
	for path, raw := range object(t, doc["paths"]) {
		item := object(t, raw)
		for method, rawOp := range item {
			if method == "parameters" || strings.HasPrefix(method, "x-") {
				continue
			}
			op := object(t, rawOp)
			params, _ := op["parameters"].([]any)
			seen := map[string]bool{}
			for _, p := range params {
				p := object(t, p)
				if p["in"] == "path" {
					name := p["name"].(string)
					seen[name] = true
					if !strings.Contains(path, "{"+name+"}") || p["required"] != true || object(t, p["schema"])["type"] != "string" {
						t.Errorf("%s %s invalid path parameter %s", method, path, name)
					}
				}
			}
			for _, match := range template.FindAllStringSubmatch(path, -1) {
				if !seen[match[1]] {
					t.Errorf("%s %s missing required path parameter %s", method, path, match[1])
				}
			}
			// Session issuance is intentionally bodyless; all older POSTs consume a body.
			if method == "post" && path != "/v1/dnsleak" && op["requestBody"] == nil {
				t.Errorf("POST %s missing request body", path)
			}
		}
	}
}

func TestOpenAPISpecificContracts(t *testing.T) {
	doc := contractDoc(t)
	for _, tc := range []struct{ path, name, typ string }{
		{"/v1/me", "ip_version", "string"}, {"/v1/ip/{ip}/risk", "live", "string"},
		{"/v1/ip/{ip}/history", "days", "integer"}, {"/v1/route/targets", "scope", "string"},
		{"/v1/fingerprint", "ip", "string"}, {"/v1/jobs/{id}", "stream", "string"}, {"/v1/me", "format", "string"},
	} {
		t.Run(tc.path+tc.name, func(t *testing.T) {
			params, _ := operation(t, doc, tc.path, "get")["parameters"].([]any)
			for _, raw := range params {
				p := object(t, raw)
				if p["name"] == tc.name && p["in"] == "query" {
					if p["required"] != false || object(t, p["schema"])["type"] != tc.typ {
						t.Fatal(p)
					}
					return
				}
			}
			t.Fatalf("missing query parameter %s", tc.name)
		})
	}
	for _, tc := range []struct{ path, method, status, media string }{
		{"/healthz", "get", "200", "text/plain"}, {"/v1/methodology", "get", "200", "text/markdown"},
		{"/v1/pow", "get", "200", "application/json"}, {"/v1/batch", "post", "200", "application/x-ndjson"},
		{"/v1/gfw", "post", "401", "text/plain"}, {"/v1/jobs/{id}", "get", "404", "text/plain"},
		{"/v1/report", "post", "403", "text/plain"}, {"/v1/label", "post", "403", "text/plain"},
		{"/v1/leak/webrtc", "post", "500", "text/plain"}, {"/v1/me", "get", "429", "text/plain"},
		{"/", "get", "200", "text/html"}, {"/v1/me", "get", "200", "text/event-stream"},
	} {
		t.Run(tc.path+tc.status+tc.media, func(t *testing.T) {
			response := object(t, object(t, operation(t, doc, tc.path, tc.method)["responses"])[tc.status])
			object(t, object(t, response["content"])[tc.media])
		})
	}
	batch := object(t, object(t, operation(t, doc, "/v1/batch", "post")["requestBody"])["content"])
	object(t, batch["application/json"])
	object(t, batch["text/plain"])
	// The baseline HTTP decoders do not require these bodies. This does not
	// promise service/provider success for missing measurement targets.
	for _, path := range []string{"/v1/route", "/v1/latency", "/v1/watch", "/v1/label", "/v1/leak/webrtc", "/v1/batch"} {
		if object(t, operation(t, doc, path, "post")["requestBody"])["required"] != false {
			t.Errorf("%s invents mandatory body", path)
		}
	}
}

// Resolve only local schemas using the existing SDK's transitive dependency.
// This validates JSON Schema shapes, not all of OpenAPI or the wire protocol.
func contractSchema(t *testing.T, doc map[string]any, schema any) *jsonschema.Resolved {
	t.Helper()
	b, err := json.Marshal(map[string]any{"allOf": []any{schema}, "$defs": object(t, doc["components"])["schemas"]})
	if err != nil {
		t.Fatal(err)
	}
	b = []byte(strings.ReplaceAll(string(b), "#/components/schemas/", "#/$defs/"))
	var s jsonschema.Schema
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	resolved, err := s.Resolve(&jsonschema.ResolveOptions{ValidateDefaults: true})
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

// No environment settings or public network dependencies in these fixtures.
func contractHandler(t *testing.T, dbEnabled bool) (*app.Service, http.Handler) {
	t.Helper()
	cfg := &config.Config{Offline: true, AnonymousRPM: 10000, DataDir: t.TempDir()}
	var db *store.Store
	if dbEnabled {
		var err error
		db, err = store.Open(":memory:")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
	}
	svc := app.New(cfg, db)
	svc.Vantage = contractVantage{}
	return svc, New(svc).Handler()
}

type contractVantage struct{}

func (contractVantage) Name() string  { return "documentationfixture" }
func (contractVantage) Enabled() bool { return true }
func (contractVantage) Measure(context.Context, probe.Query) ([]probe.Sample, error) {
	return []probe.Sample{{Provider: "documentationfixture", Network: "ct", City: "documentationfixture", ICMP: "timeout"}}, nil
}

func contractRequest(h http.Handler, method, path, body, accept string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("Accept", accept)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func validateContractResponse(t *testing.T, doc map[string]any, path, method string, w *httptest.ResponseRecorder) {
	t.Helper()
	resp := object(t, object(t, operation(t, doc, path, method)["responses"])[strconv.Itoa(w.Code)])
	media := strings.Split(w.Header().Get("Content-Type"), ";")[0]
	schema := object(t, object(t, resp["content"])[media])["schema"]
	var value any = w.Body.String()
	if media == "application/json" {
		if err := json.Unmarshal(w.Body.Bytes(), &value); err != nil {
			t.Fatal(err)
		}
	}
	if err := contractSchema(t, doc, schema).Validate(value); err != nil {
		t.Fatal(err)
	}
}
func TestOpenAPIWireContracts(t *testing.T) {
	doc := contractDoc(t)
	svc, h := contractHandler(t, true)
	for _, tc := range []struct {
		path, template, method, body, accept string
		status                               int
	}{
		{"/healthz", "/healthz", "get", "", "", 200}, {"/v1/pow", "/v1/pow", "get", "", "", 200},
		{"/v1/ip/192.0.2.1", "/v1/ip/{ip}", "get", "", "", 200},
		{"/v1/ip/192.0.2.1?format=json", "/v1/ip/{ip}", "get", "", "text/plain", 200},
		{"/v1/ip/192.0.2.1.txt", "/v1/ip/{ip}", "get", "", "application/json", 200},
		{"/v1/ip/192.0.2.1?format=html", "/v1/ip/{ip}", "get", "", "text/html", 200},
		{"/v1/ip/192.0.2.1?stream=1", "/v1/ip/{ip}", "get", "", "application/json", 200},
		{"/v1/ip/not-an-ip", "/v1/ip/{ip}", "get", "", "application/json", 400},
		{"/v1/prefix/not-a-prefix", "/v1/prefix/{cidr}", "get", "", "", 400},
		{"/v1/gfw", "/v1/gfw", "post", `{}`, "application/json", 400},
		{"/v1/jobs/documentationfixture-missing", "/v1/jobs/{id}", "get", "", "application/json", 404},
		{"/v1/report", "/v1/report", "post", "documentationfixture", "application/json", 403},
		{"/r/documentationfixture", "/r/{id}", "get", "", "application/json", 404},
		{"/v1/label", "/v1/label", "post", `{}`, "application/json", 403},
		{"/v1/leak/webrtc", "/v1/leak/webrtc", "post", `{}`, "application/json", 200},
		{"/v1/batch", "/v1/batch", "post", `{"ips":["192.0.2.1","not-an-ip"]}`, "application/json", 200},
		{"/v1/batch", "/v1/batch", "post", "", "application/json", 200},
	} {
		t.Run(tc.path+tc.accept, func(t *testing.T) {
			w := contractRequest(h, strings.ToUpper(tc.method), tc.path, tc.body, tc.accept)
			if w.Code != tc.status {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			validateContractResponse(t, doc, tc.template, tc.method, w)
		})
	}
	// PoW is opt-in and errors remain plain text even when JSON is requested.
	svc.Cfg.PowRequired = true
	for _, path := range []string{"/v1/gfw", "/v1/route", "/v1/latency"} {
		w := contractRequest(h, "POST", path, `{"target":"192.0.2.1"}`, "application/json")
		if w.Code != 401 {
			t.Fatal(w.Code)
		}
		validateContractResponse(t, doc, path, "post", w)
	}
}

func decodeContractJSON(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestOpenAPIBatchLinesAndNDJSON(t *testing.T) {
	doc := contractDoc(t)
	_, h := contractHandler(t, false)
	rowSchema := contractSchema(t, doc, map[string]any{"$ref": "#/components/schemas/BatchRow"})
	for _, body := range []string{`{"ips":["192.0.2.1","not-an-ip"]}`, "192.0.2.1\nnot-an-ip\n"} {
		w := contractRequest(h, "POST", "/v1/batch?format=json&stream=1", body, "application/x-ndjson")
		if w.Code != 200 || w.Header().Get("Content-Type") != "application/x-ndjson" {
			t.Fatalf("status/media: %d %s", w.Code, w.Header().Get("Content-Type"))
		}
		lines := strings.Split(strings.TrimSpace(w.Body.String()), "\n")
		if len(lines) != 2 {
			t.Fatalf("expected two flat rows, got %d", len(lines))
		}
		for _, line := range lines {
			var row map[string]any
			if err := json.Unmarshal([]byte(line), &row); err != nil {
				t.Fatal(err)
			}
			if err := rowSchema.Validate(row); err != nil {
				t.Fatal(err)
			}
			if row["verdict"] != nil || row["data"] != nil {
				t.Fatal("NDJSON must contain rows, not Reports")
			}
		}
		w = contractRequest(h, "POST", "/v1/batch", body, "application/json")
		validateContractResponse(t, doc, "/v1/batch", "post", w)
		rows := object(t, decodeContractJSON(t, w)["data"])["results"].([]any)
		if len(rows) != 2 || object(t, rows[1])["error"] != "invalid ip" {
			t.Fatal("individual failures must be error rows")
		}
	}
	w := contractRequest(h, "POST", "/v1/batch", "", "application/x-ndjson")
	if w.Code != 200 || w.Body.Len() != 0 {
		t.Fatal("empty batch is empty NDJSON")
	}
	w = contractRequest(h, "POST", "/v1/batch", strings.Repeat("192.0.2.1\n", 1001), "application/json")
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
	validateContractResponse(t, doc, "/v1/batch", "post", w)
}

func TestOpenAPIJobAndOptInWireShapes(t *testing.T) {
	doc := contractDoc(t)
	svc, h := contractHandler(t, true)
	// Enable the injected provider, never a live provider, so latency rows are exercised.
	svc.Cfg.Offline = false
	for _, path := range []string{"/v1/gfw", "/v1/route", "/v1/latency"} {
		w := contractRequest(h, "POST", path, `{"target":"example.invalid"}`, "application/json")
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
		validateContractResponse(t, doc, path, "post", w)
		data := object(t, decodeContractJSON(t, w)["data"])
		if data["status"] != "done" || data["job_id"] == "" {
			t.Fatal("submission must already be done")
		}
		if object(t, data["result"])["summary_md"] != nil {
			t.Fatal("submission result must not be a nested Report")
		}
		w = contractRequest(h, "GET", "/v1/jobs/"+data["job_id"].(string), "", "application/json")
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
		validateContractResponse(t, doc, "/v1/jobs/{id}", "get", w)
		stored := object(t, object(t, decodeContractJSON(t, w)["data"])["result"])
		if stored["summary_md"] == nil || stored["data"] == nil {
			t.Fatal("retrieval result must be the stored full Report")
		}
		// The stored result is marshaled before write adds HTTP snapshot metadata.
		if stored["snapshot_at"] != "0001-01-01T00:00:00Z" {
			t.Fatal("stored snapshot unexpectedly enriched")
		}
	}
	// Watch's decoder is independently permissive; measurement requests above
	// always name a target and do not assume provider/service validation stays permissive.
	emptyWatch := contractRequest(h, "POST", "/v1/watch", "", "application/json")
	if emptyWatch.Code != 200 {
		t.Fatalf("watch status %d", emptyWatch.Code)
	}
	validateContractResponse(t, doc, "/v1/watch", "post", emptyWatch)

	w := contractRequest(h, "POST", "/v1/watch", `{"target":"192.0.2.1","checks":["risk","history"],"webhook":"https://example.invalid/documentationfixture"}`, "application/json")
	validateContractResponse(t, doc, "/v1/watch", "post", w)
	created := object(t, decodeContractJSON(t, w)["data"])
	if created["secret"] == "" || created["watch_id"] == "" {
		t.Fatal("missing generated watch fields")
	}
	w = contractRequest(h, "GET", "/v1/watch/documentationfixture-ignored", "", "application/json")
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	validateContractResponse(t, doc, "/v1/watch/{id}", "get", w)
	rows := object(t, decodeContractJSON(t, w)["data"])["watches"].([]any)
	if len(rows) != 2 {
		t.Fatal("GET watch/id must list all watches, even for unknown id")
	}
	found := false
	for _, raw := range rows {
		row := object(t, raw)
		if row["secret"] != nil {
			t.Fatal("list leaked watch secret")
		}
		if row["watch_id"] == created["watch_id"] {
			found = row["checks"] == "risk,history"
		}
	}
	if !found {
		t.Fatal("list must include created watch with comma-joined checks")
	}
	w = contractRequest(h, "DELETE", "/v1/watch/"+created["watch_id"].(string), "", "application/json")
	validateContractResponse(t, doc, "/v1/watch/{id}", "delete", w)
	svc.Cfg.ShareEnabled = true
	w = contractRequest(h, "POST", "/v1/report", "documentationfixture 192.0.2.1", "application/json")
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	validateContractResponse(t, doc, "/v1/report", "post", w)
	shareID := object(t, decodeContractJSON(t, w)["data"])["id"].(string)
	w = contractRequest(h, "GET", "/r/"+shareID, "", "application/json")
	validateContractResponse(t, doc, "/r/{id}", "get", w)
	w = contractRequest(h, "GET", "/r/"+shareID, "", "text/html")
	if !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Fatal("share browser response is HTML")
	}
	validateContractResponse(t, doc, "/r/{id}", "get", w)
	svc.Cfg.LabelsEnabled = true
	w = contractRequest(h, "POST", "/v1/label", "", "application/json")
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	validateContractResponse(t, doc, "/v1/label", "post", w)
}

func TestOpenAPINegotiationAndFailureEdges(t *testing.T) {
	doc := contractDoc(t)
	svc, h := contractHandler(t, false)
	for _, tc := range []struct{ path, accept, media, prefix string }{
		{"/v1/ip/192.0.2.1", "", "text/plain", "VERDICT:"},
		{"/v1/ip/192.0.2.1", "*/*", "text/plain", "VERDICT:"},
		{"/v1/ip/192.0.2.1", "text/html", "text/plain", "VERDICT:"},
		{"/v1/ip/192.0.2.1?format=json", "text/plain", "application/json", "{"},
		{"/v1/ip/192.0.2.1.txt", "application/json", "text/plain", "VERDICT:"},
		{"/v1/ip/192.0.2.1.md", "application/json", "text/markdown", "# VERDICT:"},
		{"/v1/ip/192.0.2.1", "text/plain;q=0.1, application/json;q=0.9", "application/json", "{"},
		{"/v1/ip/192.0.2.1?stream=1", "application/json", "text/event-stream", "event: local\ndata: "},
	} {
		t.Run(tc.path+tc.accept, func(t *testing.T) {
			w := contractRequest(h, "GET", tc.path, "", tc.accept)
			if w.Code != 200 || strings.Split(w.Header().Get("Content-Type"), ";")[0] != tc.media || !strings.HasPrefix(w.Body.String(), tc.prefix) {
				t.Fatalf("unexpected status/media/body: %d %s", w.Code, w.Header().Get("Content-Type"))
			}
			validateContractResponse(t, doc, "/v1/ip/{ip}", "get", w)
			if tc.media == "text/event-stream" {
				parts := strings.Split(w.Body.String(), "\n")
				var report any
				if err := json.Unmarshal([]byte(strings.TrimPrefix(parts[1], "data: ")), &report); err != nil {
					t.Fatal(err)
				}
				if err := contractSchema(t, doc, map[string]any{"$ref": "#/components/schemas/Report"}).Validate(report); err != nil {
					t.Fatal(err)
				}
				if !strings.HasSuffix(w.Body.String(), "event: done\ndata: {}\n\n") {
					t.Fatal("finite SSE must end in done")
				}
			}
		})
	}
	// No DB: generated job id is a placeholder, not an async handle.
	w := contractRequest(h, "POST", "/v1/latency", `{"target":"example.invalid"}`, "application/json")
	if w.Code != 200 {
		t.Fatalf("latency status %d: %s", w.Code, w.Body.String())
	}
	validateContractResponse(t, doc, "/v1/latency", "post", w)
	if object(t, decodeContractJSON(t, w)["data"])["job_id"] != "job" {
		t.Fatal("no-store job placeholder")
	}
	for _, tc := range []struct {
		path, method, body string
		status             int
	}{
		{"/v1/jobs/job", "GET", "", 404}, {"/v1/watch", "POST", "", 400}, {"/v1/watch/documentationfixture", "DELETE", "", 400},
	} {
		w := contractRequest(h, tc.method, tc.path, tc.body, "application/json")
		if w.Code != tc.status {
			t.Fatal(w.Code)
		}
		template := tc.path
		if strings.HasPrefix(tc.path, "/v1/jobs/") {
			template = "/v1/jobs/{id}"
		}
		if strings.HasPrefix(tc.path, "/v1/watch/") {
			template = "/v1/watch/{id}"
		}
		validateContractResponse(t, doc, template, strings.ToLower(tc.method), w)
	}
	svc.Cfg.ShareEnabled = true
	svc.Cfg.LabelsEnabled = true
	for _, p := range []string{"/v1/report", "/v1/label"} {
		w := contractRequest(h, "POST", p, "", "application/json")
		if w.Code != 403 {
			t.Fatal(w.Code)
		}
		validateContractResponse(t, doc, p, "post", w)
	}
	// Global rate limiting also returns text, never a JSON error envelope.
	svc.Cfg.AnonymousRPM = 1
	limited := New(svc).Handler()
	contractRequest(limited, "GET", "/v1/sources", "", "application/json")
	w = contractRequest(limited, "GET", "/v1/sources", "", "application/json")
	if w.Code != 429 {
		t.Fatal(w.Code)
	}
	validateContractResponse(t, doc, "/v1/sources", "get", w)
}

func TestOpenAPISchemasAndExamples(t *testing.T) {
	doc := contractDoc(t)
	schemas := object(t, object(t, doc["components"])["schemas"])
	for name, raw := range schemas {
		t.Run(name, func(t *testing.T) {
			resolved := contractSchema(t, doc, raw)
			examples, _ := object(t, raw)["examples"].([]any)
			for _, example := range examples {
				if err := resolved.Validate(example); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestOpenAPIRequestShapesAndExamples(t *testing.T) {
	doc := contractDoc(t)
	for _, tc := range []struct {
		path, field, typ string
		required         bool
	}{
		{"/v1/gfw", "target", "string", true}, {"/v1/gfw", "ports", "array", false},
		{"/v1/route", "target", "string", false}, {"/v1/route", "carriers", "array", false},
		{"/v1/latency", "target", "string", false}, {"/v1/watch", "checks", "array", false},
		{"/v1/watch", "webhook", "string", false}, {"/v1/label", "ip", "string", false},
		{"/v1/leak/webrtc", "leak", "boolean", false}, {"/v1/leak/webrtc", "candidate_count", "number", false},
	} {
		body := object(t, operation(t, doc, tc.path, "post")["requestBody"])
		schema := object(t, object(t, object(t, body["content"])["application/json"])["schema"])
		if object(t, object(t, schema["properties"])[tc.field])["type"] != tc.typ {
			t.Errorf("%s %s type mismatch", tc.path, tc.field)
		}
		required, _ := schema["required"].([]any)
		found := false
		for _, r := range required {
			found = found || r == tc.field
		}
		if found != tc.required {
			t.Errorf("%s %s required mismatch", tc.path, tc.field)
		}
	}
	// Validate every embedded content example against its local schema, rather
	// than just testing our own structural lint function.
	var walk func(any)
	walk = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			if schema, ok := v["schema"]; ok {
				if example, ok := v["example"]; ok {
					if err := contractSchema(t, doc, schema).Validate(example); err != nil {
						t.Fatal(err)
					}
				}
			}
			for _, child := range v {
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(doc)
}

func TestOpenAPIEnvelopeTimestampAndTriState(t *testing.T) {
	doc := contractDoc(t)
	rep := app.Report{Verdict: "abstain", Summary: "documentationfixture", Data: map[string]any{"native": map[string]any{"verdict": "abstain"}}, Sources: []app.Source{}}
	raw, _ := json.Marshal(rep)
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	schema := contractSchema(t, doc, map[string]any{"$ref": "#/components/schemas/RiskReport"})
	if err := schema.Validate(value); err != nil {
		t.Fatal(err)
	}
	// Evolving reports may add fields without invalidating this contract.
	value["documentationfixture_future_field"] = true
	if err := schema.Validate(value); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"cached_at", "snapshot_at"} {
		if value[field] != "0001-01-01T00:00:00Z" {
			t.Fatal("zero timestamps must be serialized, not omitted or replaced with now")
		}
		if _, err := time.Parse(time.RFC3339Nano, value[field].(string)); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		field string
		bad   any
	}{{"cached_at", nil}, {"snapshot_at", 123}, {"snapshot_age_seconds", -1}, {"snapshot_age_seconds", 0.5}, {"sources", []any{"documentationfixture"}}, {"attribution", false}} {
		old := value[tc.field]
		value[tc.field] = tc.bad
		if err := schema.Validate(value); err == nil {
			t.Errorf("schema accepted invalid %s", tc.field)
		}
		value[tc.field] = old
	}
	native := object(t, object(t, value["data"])["native"])
	for _, state := range []string{"native", "broadcast", "abstain"} {
		native["verdict"] = state
		if err := schema.Validate(value); err != nil {
			t.Fatal(err)
		}
	}
	native["verdict"] = false
	if err := schema.Validate(value); err == nil {
		t.Fatal("native verdict must not be collapsed into boolean false")
	}
	// Use an unavailable snapshot clock to avoid a wall-second boundary race.
	svc, h := contractHandler(t, false)
	svc.Look = &lookup.Engine{}
	w := contractRequest(h, "GET", "/v1/ip/192.0.2.1?format=json", "", "")
	jsonReport := decodeContractJSON(t, w)
	age, err := strconv.ParseInt(w.Header().Get("X-IPD-Snapshot-Age"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	if int64(jsonReport["snapshot_age_seconds"].(float64)) != age {
		t.Fatal("unavailable snapshot header and envelope clocks differ")
	}
	if _, err := time.Parse(time.RFC3339Nano, jsonReport["snapshot_at"].(string)); err != nil {
		t.Fatal(err)
	}
}

func TestOpenAPIReadPayloads(t *testing.T) {
	doc := contractDoc(t)
	svc, h := contractHandler(t, true)
	for _, tc := range []struct{ path, template string }{
		{"/v1/me", "/v1/me"}, {"/v1/sources", "/v1/sources"},
		{"/v1/ip/192.0.2.1/risk?live=0", "/v1/ip/{ip}/risk"},
		{"/v1/ip/192.0.2.1/history?days=invalid", "/v1/ip/{ip}/history"},
		{"/v1/asn/AS64496", "/v1/asn/{asn}"}, {"/v1/asn/not-an-asn", "/v1/asn/{asn}"},
		{"/v1/prefix/192.0.2.0/24", "/v1/prefix/{cidr}"},
		{"/v1/route/targets?scope=documentationfixture", "/v1/route/targets"},
		{"/v1/fingerprint?ip=192.0.2.1", "/v1/fingerprint"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			w := contractRequest(h, "GET", tc.path, "", "application/json")
			if w.Code != 200 {
				t.Fatalf("status %d", w.Code)
			}
			validateContractResponse(t, doc, tc.template, "get", w)
		})
	}
	svc.SaveFingerprint(app.Fingerprint{IP: "192.0.2.1", JA3: "documentationfixture", JA4: "documentationfixture"})
	w := contractRequest(h, "GET", "/v1/fingerprint?ip=192.0.2.1", "", "application/json")
	validateContractResponse(t, doc, "/v1/fingerprint", "get", w)
	// Empty history with no store still has a different valid verdict and clock.
	_, h = contractHandler(t, false)
	w = contractRequest(h, "GET", "/v1/ip/192.0.2.1/history", "", "application/json")
	validateContractResponse(t, doc, "/v1/ip/{ip}/history", "get", w)
}

func TestOpenAPIStoreFailureStatuses(t *testing.T) {
	doc := contractDoc(t)
	svc, h := contractHandler(t, true)
	if err := svc.DB.Close(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path, template, method string
		status                 int
	}{
		{"/v1/leak/webrtc", "/v1/leak/webrtc", "POST", 500},
		{"/v1/watch", "/v1/watch", "POST", 400},
		{"/v1/watch/documentationfixture", "/v1/watch/{id}", "GET", 400},
		{"/v1/watch/documentationfixture", "/v1/watch/{id}", "DELETE", 400},
	} {
		w := contractRequest(h, tc.method, tc.path, `{}`, "application/json")
		if w.Code != tc.status {
			t.Fatalf("%s status %d", tc.path, w.Code)
		}
		validateContractResponse(t, doc, tc.template, strings.ToLower(tc.method), w)
	}
}

func TestOpenAPIOperationStructure(t *testing.T) {
	doc := contractDoc(t)
	for path, raw := range object(t, doc["paths"]) {
		for method, rawOp := range object(t, raw) {
			op := object(t, rawOp)
			if op["summary"] == nil || op["description"] == nil {
				t.Errorf("%s %s lacks explanatory metadata", method, path)
			}
			responses := object(t, op["responses"])
			if len(responses) == 0 {
				t.Errorf("%s %s lacks responses", method, path)
			}
			for status, rawResponse := range responses {
				resp := object(t, rawResponse)
				if resp["description"] == nil {
					t.Errorf("%s %s %s lacks description", method, path, status)
				}
				if content, ok := resp["content"]; ok {
					for _, rawMedia := range object(t, content) {
						entry := object(t, rawMedia)
						if entry["schema"] == nil {
							t.Errorf("%s %s %s lacks media schema", method, path, status)
						} else {
							contractSchema(t, doc, entry["schema"])
						}
					}
				}
			}
			seen := map[string]bool{}
			params, _ := op["parameters"].([]any)
			for _, rawParam := range params {
				p := object(t, rawParam)
				key := p["in"].(string) + ":" + p["name"].(string)
				if seen[key] {
					t.Errorf("%s %s duplicate parameter %s", method, path, key)
				}
				seen[key] = true
				if p["in"] == "header" && (p["name"] == "Accept" || p["name"] == "Content-Type" || p["name"] == "Authorization") {
					t.Errorf("%s %s declares an OAS-ignored header parameter", method, path)
				}
			}
			if rawBody, ok := op["requestBody"]; ok {
				for _, rawMedia := range object(t, object(t, rawBody)["content"]) {
					entry := object(t, rawMedia)
					if entry["schema"] == nil {
						t.Errorf("%s %s request media missing schema", method, path)
					} else {
						contractSchema(t, doc, entry["schema"])
					}
				}
			}
		}
	}
}

func TestOpenAPILatencyNullableEvidence(t *testing.T) {
	doc := contractDoc(t)
	response := object(t, object(t, operation(t, doc, "/v1/latency", "post")["responses"])["200"])
	schema := contractSchema(t, doc, object(t, object(t, response["content"])["application/json"])["schema"])
	for _, tc := range []struct {
		name      string
		rtt, loss any
		valid     bool
	}{
		{"unknown", nil, nil, true}, {"failed", nil, 1.0, true},
		{"missing loss", 12.5, nil, true}, {"valid zero loss", 12.5, 0.0, true},
		{"text RTT", "unknown", nil, false}, {"boolean loss", nil, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := map[string]any{"probe": "documentationfixture", "cc": "", "city": "documentationfixture", "asn": 64496, "rtt_ms": tc.rtt, "loss": tc.loss}
			rep := app.Report{Verdict: "abstain", Summary: "documentationfixture", Sources: []app.Source{}, Data: map[string]any{"job_id": "documentationfixture", "status": "done", "result": map[string]any{"rows": []any{row}, "svg": "<svg></svg>"}}}
			raw, err := json.Marshal(rep)
			if err != nil {
				t.Fatal(err)
			}
			var value any
			if err := json.Unmarshal(raw, &value); err != nil {
				t.Fatal(err)
			}
			if err := schema.Validate(value); (err == nil) != tc.valid {
				t.Fatalf("latency evidence validity: want %v, got %v", tc.valid, err)
			}
		})
	}
}

func TestOpenAPINonReservedUnobservedLookup(t *testing.T) {
	doc := contractDoc(t)
	svc, h := contractHandler(t, false)
	svc.Look = &lookup.Engine{}
	// RFC 9637 documentation space (https://www.rfc-editor.org/rfc/rfc9637.html).
	// Unlike 2001:db8::/32, the current classifier does not mark this fixture
	// reserved. An empty engine exercises the non-reserved, no-observation path;
	// LookupIP is passive and never sends traffic to this documentation address.
	w := contractRequest(h, "GET", "/v1/ip/3fff::1", "", "application/json")
	if w.Code != 200 {
		t.Fatalf("lookup status %d", w.Code)
	}
	rep := decodeContractJSON(t, w)
	if rep["verdict"] != "abstain" {
		t.Fatalf("fixture must exercise non-reserved missing observations, got %v", rep["verdict"])
	}
	data := object(t, rep["data"])
	if object(t, data["asn"])["asn"] != float64(0) {
		t.Fatal("fixture unexpectedly has an ASN observation")
	}
	disagreements, present := data["disagreements"]
	if !present || disagreements != nil {
		t.Fatal("unobserved lookup must include the actual null disagreements value")
	}
	validateContractResponse(t, doc, "/v1/ip/{ip}", "get", w)
}

func TestOpenAPIMCPBadRequestMedia(t *testing.T) {
	doc := contractDoc(t)
	_, h := contractHandler(t, false)
	for _, tc := range []struct{ path, template, accept, media string }{
		{"/mcp", "/mcp", "application/json, text/event-stream", "application/json"},
		{"/mcp/", "/mcp/", "application/json, text/event-stream", "application/json"},
		{"/mcp/documentationfixture", "/mcp/{path}", "application/json, text/event-stream", "application/json"},
		{"/mcp", "/mcp", "application/json", "text/plain"},
	} {
		t.Run(tc.path+tc.media, func(t *testing.T) {
			r := httptest.NewRequest("POST", tc.path, strings.NewReader(`{"jsonrpc":"2.0","id":"documentationfixture","method":"ping"}`))
			r.RemoteAddr = "127.0.0.1:12345"
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Accept", tc.accept)
			// Missing request-level protocol metadata is an SDK protocol error, not
			// the plain-text HTTP header error produced by the final Accept fixture.
			r.Header.Set("MCP-Protocol-Version", "2026-07-28")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 400 || strings.Split(w.Header().Get("Content-Type"), ";")[0] != tc.media {
				t.Fatalf("MCP status/media: %d %s", w.Code, w.Header().Get("Content-Type"))
			}
			if tc.media == "application/json" {
				rep := decodeContractJSON(t, w)
				if rep["jsonrpc"] != "2.0" || rep["id"] != "documentationfixture" || rep["verdict"] != nil {
					t.Fatal("expected JSON-RPC error, not an ipd Report")
				}
				rpcError := object(t, rep["error"])
				if _, ok := rpcError["code"].(float64); !ok || rpcError["message"] == "" || rpcError["message"] == nil {
					t.Fatal("missing structured protocol error")
				}
			}
			// Select the explicit 400 response: a default response cannot supply its media.
			validateContractResponse(t, doc, tc.template, "post", w)
		})
	}
}
