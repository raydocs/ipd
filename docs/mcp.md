# MCP parameter contract

The stdio server runs with `ipd mcp`. The HTTP endpoint is `/mcp`.
Tool descriptions and `tools/list` input schemas disclose unsupported options.
Unsupported non-default options return a tool error (`isError: true`) containing
`unsupported_option: <parameter>` **before** invoking the service. An error is not
a report that the requested operation ran. Errors do not repeat option values,
which may contain credentials.

## Audited options

- `ip_lookup.fields`, `ip_batch.fields`: field selection is unavailable. Omit the
  option or use `[]` to receive the existing full report, then select fields in
  the client. The CLI also has no field-selection flag.
- `google_region_check.proxy`, `unlock_check.proxy`, `ai_env_check.proxy`: per-call
  proxy overrides are unavailable. Omit the option or use `""` to retain the
  process configuration. Set `IPD_PROXY` before starting `ipd mcp`, or use the
  existing CLI global `--proxy URL` flag (for example, `ipd --proxy URL ai`).
  The MCP handler does not mutate shared configuration or construct a per-call
  network client. An empty option does not disable the configured process proxy.
- `route_forward.proto`: protocol selection is unavailable. Omit it or use `""`
  for the provider default. Even `"icmp"` is rejected: the service does not accept
  a protocol argument, and the default can depend on the selected provider.
  `ipd route <target>` uses the same default; there is no CLI protocol selector.
- `latency_map.regions`, `port_check.from`: location selection is unavailable.
  Omit these options, or use `[]` / `""` respectively, for the existing fixed
  China-carrier and overseas-control query. `IPD_VANTAGE` selects the provider,
  **not** a region or location filter. No CLI location selector exists. In
  particular, `from: "global"` is not an implemented selection: `PortCheck`
  accepts a string but does not use it.
- `node_batch_check.checks`, `node_batch_check.rename_template`: custom check
  selection and naming are unavailable. Omit them, or use `[]` / `""`, for the
  existing fixed pipeline and stock rename, also used by `ipd nodes <source>`.
  Neither CLI flag exists. This does not add a node runner or make the default
  checker capable of measuring nodes; existing unreachable/abstention behavior
  remains. Unsupported requests are rejected before reading the source.
- `watch_create.checks`: custom watch checks are unavailable. Omit it or use
  `[]` for the existing fixed risk snapshot, as with
  `ipd watch add <ip> [webhook]`. Although the service can store a selector,
  the scheduler does not execute it. Non-empty selections, including `["risk"]`,
  are therefore rejected before creating a watch, rather than stored as if
  supported. Existing stored watches are unchanged.
- `gfw_check.wait`: optional waiting/asynchronous mode is unavailable. Omit it
  or use `false` to retain the existing **synchronous** call. `false` does not
  request an async job; `true` returns `unsupported_option`. The CLI
  `ipd gfw <target>` is also synchronous.
- `job_get.wait_s`: long polling is unavailable. Omit it or use `0` for an
  immediate snapshot; any nonzero value (including a negative value) is rejected.
  Poll `job_get` with `job_id` client-side. There is no CLI wait flag.

Omission and explicit zero values intentionally have the same behavior, so
existing default calls remain valid; presence alone is not an override request.
Nullable array options also accept `null`, as advertised by the generated schema,
with the same meaning as an empty array. Non-empty arrays (even `[""]`) and
non-empty strings (even whitespace) are requests, not defaults. Other invalid
JSON types are rejected by MCP schema validation, not silently coerced.
Supported arguments such as `route_forward.carriers`, `gfw_check.ports`, and
`unlock_check.services` continue to reach the service unchanged.

## HTTP egress guard and output

For schema-valid HTTP requests, egress-only tools return `requires_egress_run`
before checking unsupported options or executing local work. This includes
requests containing `proxy`, node `checks`, or `rename_template`. No per-call
options have been applied; review them before running the suggested command on
the egress machine. Schema validation still precedes the typed tool handler.
The Google hint is `ipd unlock google_region youtube_premium`, **not** `ipd gfw`
(the latter requires a target and checks a different condition).

`summary_md` is at most 600 **UTF-8 bytes**, shortened only at a code-point
boundary. Its one-line text rendering uses the same intact prefix. Structured
`data` is not truncated.

## Regression checks

`go test ./internal/mcp -count=1` uses real MCP in-memory client/server sessions
with deterministic provider/HTTP fixtures, not public network probes. It checks
all options above, omitted/zero/nullable-array defaults, schema disclosure,
rejection before probes or watch writes, HTTP guard precedence and CLI hints,
supported argument forwarding, and intact UTF-8 summaries over MCP. Same-package
`toOut` tests supply `app.Report` fixtures directly to verify exact longest-prefix
boundaries for ASCII/Chinese/emoji, independent of any tool's business wording.
