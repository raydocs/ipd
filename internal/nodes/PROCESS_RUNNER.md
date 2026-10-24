# Isolated external-core runner — round 8

## Scope and integration boundary

This is the first independently testable runner increment, **not** an end-to-end
all-protocol detector. No mihomo/sing-box binary or library is bundled, downloaded,
installed, linked, or executed by these tests. No public proxy, account, real
server address, or public measurement is used.

`ExecRunner` implements the existing `Runner` interface. One lifecycle implementation
owns two `coreBackend` adapters: mihomo and sing-box. Core-specific parsing,
configuration and argv are separate from process management. `Mihomo` remains a
source-compatible alias; an empty `Bin` no longer searches PATH. Configure options
before use; do not copy the runner or change its options during a run.

```go
r := &nodes.ExecRunner{
    Backend: nodes.BackendAuto, // or BackendMihomo / BackendSingBox
    Executables: map[nodes.Backend]string{
        nodes.BackendMihomo: "/absolute/trusted/path/mihomo",
        nodes.BackendSingBox: "/absolute/trusted/path/sing-box",
    },
    StartupTimeout: 10 * time.Second,
    Budget: 3 * time.Minute,
}
socks, err := r.Start(ctx, localConfigPath)
if err != nil { /* sanitized, errors.Is-compatible */ }
defer r.Stop()
endpoints := r.Endpoints() // {SOCKS, HTTP, Backend} per original node name/tag
_ = socks // authenticated socks5:// URLs, NOT bare host:port
_ = endpoints
```

`Bin` is an alternative explicit executable for the selected backend when
`Executables` is nil. With a non-nil map the selected entry is mandatory: a
missing binary never falls back to the other entry. `SelectBackend(data, forced)`
validates the input and runner-supported capabilities without launching a process.
`SelectedBackend()` preserves the identity after teardown; each live `Endpoint`
also carries it. `Run` includes it in `Outcome.Backend` for identity-aware runners;
legacy/custom runners keep an empty identity and the original path-based interface.

No app, CLI, Web, checker, score/purity/exit-IP/unlock path or parent roadmap is
wired here. `Parse`/`Run` still use the Clash document model, not sing-box JSON;
JSON callers use `ExecRunner.Start` directly until a later integration increment.
`Run` uses optional `StartFile` to retain original YAML safety across serialization.
The compatibility URI parser loses protocol credentials/options; its `File` is
explicitly unsupported by this runner rather than dialed with lost semantics.

## Selection is pre-launch, not error recovery

- Clash YAML defaults to mihomo; sing-box JSON defaults to sing-box. Detection is
  content-based, not filename-based. JSON starts with a quoted-key object (or an
  invalid array); plain-key YAML flow maps remain YAML. Quoted-key flow YAML is
  conservatively treated as JSON, never reparsed permissively after a JSON error.
- An explicit `Backend` pins that choice. Unknown choices and an incompatible
  input/core format return `ErrRunnerUnsupported` **before any process**. This
  bounded increment does **not** translate Clash parameters into sing-box or the
  reverse. It therefore does not promise automatic cross-core protocol fallback.
- Known *core* capabilities are not the same as this runner's audited whitelist.
  Current mihomo supports TUIC, AnyTLS and WireGuard, plus ShadowTLS in layered
  forms; they are **not** evidence that mihomo lacks those protocols. sing-box
  also has TUIC/AnyTLS/ShadowTLS, and current WireGuard uses an endpoint model.
  Do not add an automatic fallback table inferred from protocol names alone.
- Runtime startup/listener/upstream failures never change backend, ports or route
  to another node or DIRECT. A future selector/converter must establish semantic
  equivalence and capability/version requirements **before** launching anything.

Runner-supported subsets (not claims of successful core handshakes):

- mihomo: `ss`, `vless`, `vmess`, `trojan`, `hysteria2`. Basic credentials, TLS
  flags/SNI/ALPN/fingerprints, applicable WS/gRPC and VLESS/VMess HTTP/H2/Reality,
  and selected Hysteria2 bandwidth/obfuscation/port-hopping options are forwarded.
  Exact field/type allowlists are in `runnerProxyFields`.
- sing-box: `shadowsocks`, `vless`, `vmess`, `trojan`, `hysteria2`, `tuic`, `anytls`.
  Basic credentials, a bounded inline TLS/Reality/uTLS subset, applicable WS/gRPC,
  and selected Hysteria2/TUIC/AnyTLS options are forwarded. Exact allowlists are
  in `singBoxFields`. This is not every option in the official schema.
- Unknown fields, aliases such as `hy2`, plugins, scripts, file certificate/key
  paths, interface/mark overrides, dialer/detour references, unsupported transports
  and unknown nested options return unsupported. Nothing is silently stripped
  from an accepted node. Node names/tags alone are replaced by `ipd-node` inside
  each private configuration; external result identities keep their original value.
- WireGuard endpoint/system-interface lifecycle and ShadowTLS/other multi-outbound
  graphs remain unsupported here. Any sing-box `endpoints` key fails explicitly;
  detours never become direct connections. Advanced protocol expansion and safe
  cross-format conversion are follow-up work, not a negative core-capability claim.

## Safety and lifecycle contract

Input is a local regular file, bounded to 4 MiB / 64 nodes. Before any map decoding
for the runner, YAML representation-tree validation rejects duplicate *decoded*
keys, non-string/complex/tagged keys, merge keys (including quoted `<<`), aliases
(including scalar/cyclic/ignored-global values), custom tags and extra documents.
JSON token validation rejects duplicate decoded/escaped keys at every depth,
including ignored globals, extra documents and malformed input. Both have a
64-level depth limit. Names/tags must be nonempty and unique; ports are integers
in 1–65535. The compatibility `Parse` API remains permissive for old non-runner
callers but retains an unsafe-input bit checked by `StartFile`.

Only approved node fields reach a fresh generated config. Top-level input uses a
closed allowlist: `proxies` (mihomo) or `outbounds` (sing-box), plus optional
runner-owned `metadata: {name: string, description: string}` for presentation only.
Unknown metadata fields and **all other globals**, even empty/default-looking
values, return `ErrRunnerUnsupported` before any child or network probe. This
includes certificate/trust stores and paths, interfaces/marks, hosts/DNS, rules,
controllers/UIs, inbounds, providers, scripts, experimental APIs, tun and caches.
They are not silently discarded into changed trust/address/route defaults. Whole
routing documents therefore need a separately reviewed extraction/conversion
step; this runner checks only self-contained individual node outbounds.

Each node gets its own process, directory (0700), config (0600), random listener
password and TCP mixed SOCKS/HTTP listener on `127.0.0.1`. mihomo's listener `proxy`
pins `ipd-node` with a `MATCH,REJECT` fallback. sing-box contains one outbound and
an explicit route `final` pointing at `ipd-node`; no DIRECT outbound exists.
Listener UDP is not enabled; this increment does not verify UDP forwarding.

A loopback ephemeral port is reserved until immediately before core launch.
Neither core accepts a portable inherited socket here, so a bind race remains.
**SOCKS credential acceptance is client authentication, not server identity.**
Kernel evidence must establish the listening socket's child ownership before any
protocol/authentication probe, after readiness, and again for the entire batch
immediately before endpoints are published:

- Darwin requires the existing, root-owned non-writable-by-group/others system
  `/usr/sbin/lsof`, fixed argv, no inherited environment and NUL-delimited fields.
  Query all TCP LISTEN records at the port (no PID/address-family filter hiding
  competitors). Require exactly one IPv4 `127.0.0.1:port` fd with the launched PID
  and this runner's parent PID. Missing fields, warnings, query failure, foreign,
  wildcard, IPv6 or multiple listeners fail closed. `-nP` disables name lookups.
- Linux requires readable `/proc/self/net/tcp{,6}`, the child's fd symlinks/stat,
  and matching network namespaces. Require one LISTEN record at the port across
  both tables, the exact IPv4 loopback address, and its inode in the live direct
  child's fd set. Foreign/ambiguous records, unreadable evidence or namespace
  differences fail closed. A dead/reused PID is not accepted as a live child.
- Other platforms, unavailable tools or restricted kernel visibility return
  unsupported without endpoints; there is no protocol-only ownership fallback.

SOCKS5 random-token authentication and an HTTP 407 then check protocol readiness
only. A collision fails closed with no retry/fallback, CONNECT or upstream
measurement. Kernel checks attest ownership at those instants; URLs are not
perpetual capabilities and become invalid after child teardown. Trusted binaries
must not delegate/inherit their listening fd to other processes or deliberately
change listeners; same-user process tampering is outside this trusted-core model.
Credentials in endpoint URLs are secrets: do not log, serialize to public UI,
or expose them in error messages.

Absolute executable paths use `exec.CommandContext` with fixed argv and no shell.
The child receives only private `HOME` and `TMPDIR` values, not CLASH overrides,
proxy variables, loader settings or inherited secrets. Stdout/stderr go to the
null device; returned errors contain no raw core output, input path, node name,
server or credentials. Errors preserve context cancellation/deadline identity.

Startup has a whole-batch listener deadline (default 10s); `Budget` bounds the
whole process lifetime including startup (default 3m), and the caller context
can shorten it. Any child exit revokes the batch and kills/reaps its peers.
`Stop` is concurrent-safe/idempotent, cancels pending startup and waits for every
child's `Wait` and the owned-directory cleanup attempt. If removal fails,
`Err()` joins `ErrRunnerStorage` and `ErrRunnerCleanup` with the original terminal
error; `errors.Is(err, context.Canceled)` remains true for cancellation. No raw
filesystem error/path/config is returned. A retained private directory requires
manual local attention under the trusted `TempRoot` (or system temp directory);
do not blindly remove another session's private directories. Check retained state
only after confirming all owned children are reaped; repeated Stop preserves the
warning rather than claiming successful cleanup. `Err()` otherwise reports
`context.Canceled` for an ordinary explicit Stop. A runner can restart
after teardown, but another active Start is rejected. Retained endpoint URLs
are invalid after teardown. Only the newly created owned directory is removed;
source files, unrelated siblings and symlink targets are never deleted.

The binary itself is trusted, same-user code; this is **not** an OS sandbox for
malicious executables, an egress firewall, a version/feature probe, or protection
from another same-user process modifying files. No external plugin execution is
accepted. Real-core startup behavior (including build flags/feature availability)
needs separately provisioned, approved-core verification.

## Official configuration/capability evidence

Consulted 2026-10-24; source read only, no core downloaded or built:

- mihomo [`3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8` parser](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/parser.go),
  [outbound option definitions](https://github.com/MetaCubeX/mihomo/tree/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound),
  [listener proxy binding](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/inbound/base.go),
  [mixed listener](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/inbound/mixed.go),
  [HTTP pre-route auth](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/http/proxy.go),
  [CLI/env flags](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/main.go).
  [Official listener docs](https://github.com/MetaCubeX/Meta-Docs/blob/2a6ba6b04a9eecdbe5c88c4e4a09776659c0878b/docs/config/inbound/listeners/index.en.md)
  confirm explicit `proxy`; [mixed docs](https://github.com/MetaCubeX/Meta-Docs/blob/2a6ba6b04a9eecdbe5c88c4e4a09776659c0878b/docs/config/inbound/listeners/mixed.en.md)
  confirm per-listener users.
- sing-box release [`v1.14.4` / `c005f35300ce76427dc285481ec5695f5b179cd2`](https://github.com/SagerNet/sing-box/tree/c005f35300ce76427dc285481ec5695f5b179cd2):
  [option definitions](https://github.com/SagerNet/sing-box/tree/c005f35300ce76427dc285481ec5695f5b179cd2/option),
  [mixed inbound](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/protocol/mixed/inbound.go),
  [CLI run](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/cmd/sing-box/cmd_run.go),
  [CLI flags](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/cmd/sing-box/cmd.go).
  Official [mixed](https://sing-box.sagernet.org/configuration/inbound/mixed/),
  [route final](https://sing-box.sagernet.org/configuration/route/),
  [outbounds](https://sing-box.sagernet.org/configuration/outbound/), and
  [WireGuard endpoint](https://sing-box.sagernet.org/configuration/endpoint/wireguard/)
  documents distinguish support from runner coverage.
  Its pinned sing dependency's [HTTP auth](https://github.com/SagerNet/sing/blob/5dc452e537bf/protocol/http/handshake.go)
  confirms a 407 precedes routing.

Only protocol behavior/schema facts were consulted; no GPL implementation code
was incorporated or linked. YAML validation follows the local representation-tree
pattern examined in PR19 commit `8a73ea1`, not unrelated PR17 app implementation.

## Local evidence and remaining verification

Exact initial base: `origin/main@2c96d6390a5924bee371ad837a527d6ee1f83ae6`
(PR1 merged, includes PR4). Latest integration target fetched:
`origin/main@3a0832284585118d473a7fd08fb4c924831f760b`.

The unchanged regression `TestMihomoStartsIsolatedChannels` was actually run
against the old `Mihomo` implementation before its replacement:
`go test ./internal/nodes -run '^TestMihomoStartsIsolatedChannels$' -count=1`
**failed**, `need two distinct live channels; got map[string]string{}`.

Tests compile the task-owned `testdata/corefixture` helper, launch it as a real
subprocess with each backend's actual CLI, read the actual generated YAML/JSON,
and serve authenticated loopback SOCKS/HTTP identity markers without outbound
connections. These prove configuration wiring, node/process/port isolation,
identity/selection, pre-launch rejection, environment/permissions/redaction,
actual port collision, startup/late exit, deadline/cancel/concurrent Stop,
Wait/reaping, restart and ownership-limited cleanup. They do **not** emulate any
protocol encryption, TLS handshake, UDP upstream, core feature flags or real
mihomo/sing-box configuration acceptance. Neither real core is installed/tested.

Final integrated check results are recorded in the PR. Independent r1 review
blocked the prior head on listener identity, global-policy semantics and silent
cleanup failure. This revision addresses those findings with actual before/after
overlay evidence; it remains Draft and requires the parent's independent r2,
not author self-acceptance. No merge/deployment is authorized. Subsequent app/checker/JSON document
integration, safe conversions, exit-IP/route evidence, purity/scoring and unlock
measurement remain separate work.

### Review r1 regression evidence

The supplied overlay was run unchanged against `ebd6b242d76abfe335a01accb25c07781c63b589`
before edits: both permissive foreign listeners were published, four required
global policies were lost, and real permission-denied cleanup reported only
cancellation. The command exited 1. The same overlay after correction exited 0.
Owned evidence: `/tmp/ipd-pr23-r1-fix.v8tNE4/{before.txt,after-overlay.txt}`.

New checked-in tests cover both backends with an accept-any SOCKS/HTTP impostor
(no credentials/protocol bytes sent to it), a persistent task-owned helper
launch audit for zero-process/zero-probe global-policy rejection, and actual
non-root OS permission-denied cleanup retaining a private config copy. These are
not mocks of the ownership query or filesystem error. The permission test requires
real mode enforcement/non-root execution; it fails honestly rather than skipping
if the environment bypasses those permissions.

Darwin's system lsof path is exercised by real subprocess fixtures locally.
Linux proc parsers are locally unit-tested and the Linux target is compile-checked;
Linux kernel/runtime ownership behavior still requires the Linux CI/r2 run, not a
claim inferred from cross-compilation. Official kernel [TCP proc fields](https://docs.kernel.org/networking/proc_net_tcp.html)
and [proc fd/stat documentation](https://www.kernel.org/doc/Documentation/filesystems/proc.txt),
and [lsof machine-output documentation](https://github.com/lsof-org/lsof/blob/master/Lsof.8)
were checked for the ownership implementation. No core or new system binary was
installed, and no protocol-only fallback is used when this evidence is unavailable.
