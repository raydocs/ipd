# Implemented HTTP contract

`GET /openapi.json` describes the existing `Server.Handler` surface. It does not
add routes, validate incoming requests, or change execution. The contract tests
extract route registrations from `http.go`, check path parameters and concrete
request/response declarations, and exercise an offline Handler with in-memory
storage and a fake measurement provider. Fixtures use documentation addresses,
`example.invalid`, or loopback; they do not contact measurement providers.

## Negotiation and errors

Report routes do **not** default to JSON merely because their path starts with
`/v1`. Recognized `?format=` takes precedence over `.json`, `.txt`, or `.md`, then
quality-weighted `Accept` chooses JSON (`+json` also works), Markdown, plain text,
or HTML. A suffix only works if the existing mux route still matches: e.g.
`/v1/ip/192.0.2.1.json` works, `/v1/me.json` is not a registered alias. Unknown
format values are ignored. `/v1` coerces HTML to plain text; absent/wildcard Accept
also defaults to plain text. Root and shared reports have actual HTML branches
for browser negotiation; curl/wget/httpie default to text there. Other Report
handlers fall back to plain text if HTML is selected.

`?stream=1` on a Report route emits a finite `text/event-stream` body: one `local`
event containing the Report and then `done` with `{}`. This is neither a progress
subscription nor watch delivery. Root/share HTML branches take precedence over
streaming. Batch's NDJSON branch takes precedence over both format and stream.

Handler errors use `http.Error`: plain text, generally newline-terminated, even
when the client requested JSON. They are not Report envelopes. Important statuses
are 400 for invalid IP/prefix, oversized batch count, measurement/provider errors
or watch store failures; 401 for configured PoW failures; 403 for share/label
submission failures; 404 for unavailable shares/jobs or hidden metrics; and 500
for WebRTC store failure. These are not normalized into a single JSON error API.
The outer anonymous/keyed limiter can return plain-text 429 before dispatch;
health, favicon and static assets bypass it. `X-API-Key` optionally selects the
configured keyed quota; it is not mandatory authentication for the REST surface.

Health, metrics, OpenAPI, usage cards, methodology and favicons have their own
fixed media types. `/methodology` aliases `/v1/methodology`; `/leak` serves the UI.
Static assets are delegated to `net/http` (including redirects, ranges and
conditional requests). GET registrations also inherit Go ServeMux's HEAD
handling. Unmatched routes/methods and mux canonicalization retain net/http
404/405/redirect semantics, not a Report schema.

## JSON envelope and clocks

JSON Reports contain `verdict`, `summary_md`, operation-specific `data`, `sources`,
`cached_at`, `attribution`, `snapshot_at`, and `snapshot_age_seconds`. Additional
properties are intentionally permitted for compatibility with report additions.
`Source` describes source IDs and optional attribution/license/raw JSON.
`data` is not globally restricted to one fixed object shape. Nil source or
attribution slices can serialize as JSON null, not just empty arrays.

`cached_at` is the Report's cache/result timestamp; it is not universally the
current request time. `snapshot_at` is the prefix-data clock (older of the DB-IP
and BGP snapshot clocks), **not** a live measurement timestamp.
`snapshot_age_seconds` is its nonnegative age, clamped at zero for future clocks;
zero also represents an unavailable clock. Go zero timestamps serialize as
`0001-01-01T00:00:00Z`, not null or an omitted field. HTTP adds the current prefix
snapshot clock to the outer Report; `X-IPD-Snapshot-Age` exposes that age when a
lookup engine is configured, including on error/fixed-format responses.

Verdicts are not a universal boolean or a closed success enum. In particular,
`data.native.verdict` on risk reports is `native`, `broadcast`, or `abstain`;
unknown evidence must not become false/safe. Residential `cannot determine` and
other uncertainty verdicts remain strings. The document does not invent a
universal boolean field for either classification.

Embedded examples are synthetic **documentationfixture** values, not evidence of
any actual address's measured quality or a promised verdict.

## Batch and synchronous jobs

`POST /v1/batch` reads at most 1 MiB. It first attempts `{ "ips": [...] }` JSON;
if decoding fails or the array is empty it treats nonempty trimmed input lines as
IP strings. Thus a truly empty body yields zero rows, but `{"ips":[]}` falls back
to a single invalid-address line. Plain lines are not NDJSON request objects.
More than 1000 entries returns 400. Individual invalid IPs yield `{ip,error}` rows
with HTTP 200; valid rows have flat IP/country/ASN/type/score/grade fields.

Ordinary JSON responses use `BatchReport.data.results`. If Accept contains
`ndjson`, the response instead uses `application/x-ndjson`: one flat `BatchRow`
JSON object per line, **not** one Report per line. An empty result has an empty
NDJSON body. The OpenAPI wire schema is a string with a row-schema description,
since the entire multi-line body is not one JSON value.

`POST /v1/gfw`, `/v1/route`, and `/v1/latency` perform their work **synchronously**,
then return HTTP 200 with `data:{job_id,status:"done",result:<operation data>}`.
There is no 202/pending/async-wait promise. With a store, the saved job is already
finished before the response. `GET /v1/jobs/{id}` wraps its status and the stored
**full Report** in `data.result`, unlike the submission's data-only result. Stored
Reports are marshaled before HTTP snapshot enrichment; the outer retrieval clock
does not retroactively change them. Without a store the submission uses the
placeholder `job` and subsequent retrieval returns 404.

Only GFW explicitly requires a nonempty `target` at the HTTP layer; empty bodies
on route/latency reach the provider with default values. Provider errors can
still produce 400. PoW applies only when configured; GFW checks missing target
before checking PoW. The JSON body schemas describe the intended typed fields,
not strict rejection of every malformed body: several decoders ignore errors,
unknown fields or wrong types, and do not enforce Content-Type.

## Opt-in writes and egress boundaries

Sharing requires `IPD_SHARE_ENABLED` plus storage; upload is **raw text**, limited
to 1 MiB and redacted before storage. Submission errors are 403. Reading is 404
when disabled/missing and returns either escaped HTML or `data.body` in a Report.
Labels similarly require `IPD_LABELS_ENABLED` plus storage and return 403 on any
service error; the HTTP decoder does not impose nonempty label fields.

Watch creation is an explicit opt-in write requiring storage, **not** a separate
watch feature flag. No target/checks/webhook required-field validation is added by
HTTP. Creation returns a generated signing secret; the list does not.
**`GET /v1/watch/{id}` calls ListWatches and ignores id**, returning all watches,
not a per-id lookup or per-id 404. Its checks are comma-joined strings. Delete
uses id and does not turn missing rows into 404. The specification documents
these existing behaviors; it does not fix them or guarantee webhook delivery.

WebRTC ingestion retains only a local boolean and numeric candidate count
(truncated to integer); missing/wrong-type fields default to false/zero. It does
not store address fields or perform remote browser detection. Fingerprint reads
only the last recorded observation and returns abstain when absent. The DNS token
route runs the server-side DNSLeak routine and echoes the token, rather than
retrieving an asynchronous caller-side measurement. Return-route targets are a
list, not remote return-route execution. Actual egress-only AI/unlock/leak/return
checks must run on the egress via CLI or MCP stdio; HTTP cannot prove a remote
caller's environment.

`/mcp` and its existing subtree delegate to the stateless MCP SDK, not the Report
REST protocol. Its POST requires JSON Content-Type and Accept containing both
JSON and event-stream; notification acknowledgments and SDK errors have their
own statuses. Full tool/protocol semantics remain SDK-owned. The optional
`/agent` subtree is an injected handler (normally probe enrollment/WebSocket),
absent when no Hub is configured; its opaque transport is not a new REST API.

## Validation limits

`LintOpenAPI` is only a small structural sanity check. The contract tests also
resolve local JSON Schemas with the existing dependency (no remote schema
loader), validate embedded examples and actual JSON responses, reject concrete
invalid envelope/tri-state shapes, and assert negotiation, job nesting, NDJSON,
PoW, opt-in and watch behavior through `httptest`.

This is **structural validation plus selected wire regressions, not full OpenAPI
or protocol certification**. It does not certify every JSON Schema format,
client generator, SDK protocol version, optional injected handler, live provider,
rate-limit deployment configuration, browser egress path or webhook delivery.
