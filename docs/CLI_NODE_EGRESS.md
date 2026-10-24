# Explicit CLI node egress measurement (round 8)

## Acceptance contract

Only an explicit `nodes --measure` invocation may launch trusted external cores.
The default Nodes, HTTP and MCP paths remain unchanged and abstain. Accepted input
is bounded local regular-file or inline native Clash YAML / sing-box JSON, subject
to PR23's unchanged allowlists. The batch preserves input sequence and exposes
only 1-based original index, backend, observed public egress IP or unknown status
and controlled reason. No purity, unlock, reachability grade or credential-bearing
configuration is exported.

Verification must exercise both backend helper subprocesses through the real
runner, authenticated loopback proxies and verified HTTPS, without a real airport,
public measurement request or downloaded core. Failure/cancellation/core revocation
must withhold the entire batch and reap processes; no environment proxy or direct
fallback. Regression must actually fail before implementation. Narrow/race/full Go
and web judge checks, plus isolated PR22 composition, are required evidence.

Dependency: PR23 at `8331260018a4b34cc4874e0ea0ba30271a52a24f` (not merged).
This branch merges that accepted candidate and ordinary `origin/main`; PR base is
`main`. PR22 `a25cced46742fc1137212a8e174b7cdb8c6b4b21` remains separate: do not
copy or overwrite its locale/latency changes. This PR's own increment is app/CLI
measurement wiring, tests and this document only. Parent PR21 and closed PR12 are
not modified. Draft only: no merge, main push, force push or deployment.

## Usage and safety

```sh
ipd nodes --measure --backend auto --mihomo-bin /absolute/trusted/mihomo ./nodes.yaml
ipd nodes --measure --backend sing-box --sing-box-bin /absolute/trusted/sing-box ./nodes.json
ipd --offline nodes --measure --mihomo-bin /not/executed ./nodes.yaml
ipd --lang en nodes --help
```

Inline native documents may replace the final file argument (shell quoting is
required). Only the selected core needs a path; any supplied paths must be
absolute. Auto chooses by validated input format, not runtime fallback. Forced
cross-format selection is `unsupported`; no conversion is attempted. No path
search, environment-based core selection, binary installation, URI/base64 or
remote subscription fetch exists on the measurement path. Executables and local
input are trusted against same-user mutation; this is not an OS sandbox.

The application reuses PR23 `SelectBackend` on the original bounded snapshot;
a second representation decode reads only sequence-ordered names/tags internally.
Those names map each original 1-based index to that runner's live authenticated
endpoint. They never enter the output. No runner API or ownership/lifecycle/
allowlist code is changed. A 0700 directory/0600 input snapshot is removed after
runner Stop/Wait; source files are never modified or exported.

There is one HTTP observation function for both backends. Production uses each
node's authenticated HTTP endpoint and HTTPS CONNECT to the fixed
`https://api.ipify.org` plaintext IP service ([official format documentation](https://www.ipify.org/)).
The URL and CA are not flags, environment values, process config or service
fields. Only unexported function arguments let tests supply local HTTPS and a
fixture root. TLS verification remains on (TLS >=1.2). No environment proxy,
DIRECT retry, redirect, shared transport or cross-node connection reuse. Each
client has a 5s request/dial/TLS/header/body deadline, 8KiB response headers and
256-byte body limit. Four workers and a 45s total budget include startup. Report
IP parsing does not treat private/loopback responses as exit observations.

Before dialing, after connecting/reading and before batch publication, the app
checks runner Err and live Endpoints. While requests block, a 5ms monitor cancels
the batch on revocation; the existing runner has no exported invalidation channel.
This is prompt bounded observation, not an atomic guarantee against arbitrary
same-user listener replacement. Retained URLs are never used for another node or
new request after a failed validity gate. SIGINT/SIGTERM cancel the CLI context,
then deferred Stop reaps cores before returning. Cleanup failure withholds results.

Every report has `verdict: abstain`: even complete IP observations are not safety
or reachability judgements. Complete rows have index/backend/egress_ip/observed;
any incomplete, interrupted or revoked batch removes **all** IPs and emits unknown
rows with a controlled reason. No grade, AI/TikTok/unlock, dead/blocked, node name,
server, credentials, endpoint, raw error, source config or renamed YAML is exposed.
HTTP/MCP and default Nodes do not call this method; no core paths were added to
shared Config. Offline returns before source I/O, subprocess or network work.

## Evidence and remaining runtime boundary

The initial checked-in CLI regression was actually run before implementation:
`go test ./internal/cli -run '^TestCoreNodesForcedBackendRegression$' -count=1`
failed: expected controlled unsupported, got `could not read node subscription`.
Evidence log: `/tmp/ipd-r8-cli-before.log`.

The task-owned `internal/app/testdata/egressfixture` executable reads actual
runner-generated mihomo/sing-box configs, implements authenticated loopback mixed
HTTP CONNECT / SOCKS5 tunnels, and dials **only** its configured `127.0.0.1` TLS
origin. Full app production measurement control flow observes different IPs from
two local verified HTTPS origins in reverse lexical node-name order. Separate
transport checks exercise HTTP and SOCKS through the same query function. The
helper never downloads/executes real cores, encrypts a proxy protocol, or contacts
an airport/public exit service. CLI SIGTERM evidence exercises a real blocked
CONNECT with real child reaping/config cleanup and no public connection.

Remaining: real mihomo/sing-box binaries, upstream encrypted protocol handshakes,
UDP, cross-format conversion, advanced runtime capabilities and all purity/unlock
measurements remain unverified/unimplemented. No full-protocol claim. Independent
security review belongs to the parent before any merge/deploy; author tests are
not independent review.

### Final executed checks

Code tested at `bdeb5f31c8ac7389659869f93585c980efff930c` (subsequent changes
are documentation only):

- `go test ./internal/app ./internal/cli -run 'TestCore' -count=1`: PASS.
- `go test -race -p 1 ./internal/app ./internal/cli -run 'TestCore' -count=1`:
  PASS (`/tmp/ipd-r8-race-final.log`).
- `go test -p 1 ./... -count=1`: PASS (`/tmp/ipd-r8-full-final.log`).
- `node --test web/judge.test.mjs`: PASS, 1/1 (`/tmp/ipd-r8-web.log`).
- An owned detached worktree at the tested code head applied PR22
  `a25cced46742fc1137212a8e174b7cdb8c6b4b21` with no conflicts;
  `go test -p 1 ./internal/cli -count=1`: PASS
  (`/tmp/ipd-r8-compose22.log`). The temporary composition was removed; neither
  PR22 nor this branch includes the other's implementation.
- `git diff --quiet 8331260018a4b34cc4874e0ea0ba30271a52a24f HEAD -- internal/nodes`:
  PASS, runner unchanged. Parent `docs/ROADMAP-STATUS.md` matches `origin/main`.

Active Draft is PR25, base `main`, dependent on PR23. Task-owned PR24 scaffolding
was closed and superseded because the initial T3 checkout carried PR21's roadmap
history; the replacement branch starts directly at accepted PR23 and contains no
PR21 roadmap changes. No existing PR/branch was rewritten, no force push was used,
and PR12 was not touched. Independent review and actual-core/runtime verification
remain pending with the parent; no merge or deployment was attempted.
