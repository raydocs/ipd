# Explicit per-node unlock increment

## Scope and dependency

Success means explicit `nodes --measure --unlock <comma IDs>` runs the unchanged
shared unlock engine through the same still-live authenticated loopback runner
endpoint as each node's egress probe, with no host/network fallback. Output stays
overall `abstain`; provisional observations are discarded on whole-run failure.

Dependencies (independent PRs; this Draft still targets **main**):
- PR23 runner `8331260018a4b34cc4874e0ea0ba30271a52a24f`.
- Accepted PR25 egress `676aabffbf08a40010570bc04bc2049cf5072212`.
- Accepted/review-approved PR27 live capability
  `f69809913caa82dd791c3d02ffa32d3571e26b39` (parent authorization).

This branch began at exact PR25, not the parent coordinator summary/doc history.
PR27 and fetched `origin/main` are ordinarily merged, never force-rebased. The
unwired merge checkpoint is `1a7845da1e9f0ef33bfeb011b062c5fbddbcfaa1`.
Own integration diff is measured from that checkpoint; inherited runner changes
are PR27, not app integration changes. No PR27 runner file or shared unlock
verdict logic is edited. PR22 remains separate and is tested in isolation only.

No purity, conversion, UI, account-safety, login or actual-playback claim. Helpers
are not real mihomo/sing-box binaries, real subscriptions or airport evidence.
Parent fresh-context full app/CLI review and acceptance are still required.

## Invocation and limits

```sh
ipd --lang en --json nodes --measure --backend mihomo \
  --mihomo-bin /absolute/trusted/mihomo --unlock apple,meta_ai nodes.yaml
```

- Explicit selection only: 1–4 unique exact IDs from `apple`, `meta_ai`, `netflix`,
  `claude`, `chatgpt`. Unknown IDs, empty entries, duplicates, whitespace/case
  variants and excess IDs fail before source loading, startup or requests.
  CLI `--unlock` requires `--measure`; zh/en help/errors are invocation-local.
- Default PR25 invocation still makes at most one egress GET/node and no unlock
  GET. Offline starts no child and makes no request. Default HTTP/MCP Nodes is
  unchanged. Native input ordering and private metadata boundaries remain intact.
- At most 12 unlock GET attempts/node, 256 KiB wire and decompressed body/request,
  8 KiB response headers/request, 5s/request, 20s/node including egress, 45s/batch
  including startup, 4 workers and at most 64 nodes: at most 768 unlock GET
  attempts/batch plus at most 64 egress GETs. Readiness is separate local-only
  runner probing. New live checks are kernel queries, not added service requests.
- Exact HTTPS catalogue request URLs only, including required trace paths;
  **no redirects**, even catalogue redirects. No cookies, arbitrary headers,
  service auth, environment proxy, native DNS, DIRECT fallback or unverified TLS.
  Resolve is a non-network callback; no engine method label is output.
- Required-path failures, unknown templates, challenges, redirects, truncated or
  oversized bodies/headers abstain. Request/node/batch deadlines and cancellation
  invalidate all egress and unlock rows. Other service evidence gaps abstain for
  that service. Output contains only original index/backend, validated egress,
  fixed service/status/evidence codes and a validated two-letter region.
- URL mapping and CA injection remain unexported function-level fixture seams;
  no public flag, config, environment or Service field enables them.

## PR27 capability integration

Read `internal/nodes/LIVE_OWNERSHIP.md` for the accepted contract and bounds.
`StartWithHandle` supplies the single-run opaque handle; app retains no owner PID,
process path, private owner evidence or duplicate OS ownership implementation.
Every production per-node gate uses `handle.Check(ctx, name, expectedEndpoint)`,
not just `runner.Err` or an endpoint-map snapshot:

1. Client creation, before each request, immediately before and after each dial
   (before returning a socket on which proxy authentication can be sent).
2. After response headers, after the complete bounded body, and when adopting a
   service or complete node result.
3. `handle.CheckAll(batchCtx)` before whole-batch publication, followed by handle
   and context state gates. A failure from any other node clears every earlier
   egress/unlock positive, not just the failed node's row.

The node's authenticated HTTP client has an unpooled per-request transport and a
private active-connection registry. Dial ownership checks inherit the actual
request context even where net/http detaches a speculative dial context; shorter
request/node/batch deadlines are not replaced with a new longer budget. Raw
connection writes additionally check request/handle state before writing.

`handle.Done` drives a blocking signal watcher that cancels the entire app batch;
there is no app 5ms validity ticker. Cancellation closes **active** registered
sockets, including blocked CONNECT/TLS/body operations, not only idle transports.
The watcher is stopped/joined before the app's intentional Stop. Stop then reaps
children and checks terminal errors: `ErrRunnerStopped` alone does not erase a
validated successful batch, but real prior failure/deadline/exit/ownership loss or
joined storage/cleanup warnings do. Report cleanup still withholds all positives.

This uses PR27's **observed invalidation and bounded sampling** contract. Neither
CheckAll nor app state gates are atomic multi-node kernel snapshots. Fast same-PID
rebinds between observations, the check-to-dial/write window, and the identity of
an already-connected receiver are **not absolutely authenticated**. Known loss
prevents later authorization; no claim is made to retract bytes already sent or
to sandbox malicious same-user processes or trusted cores that delegate sockets.

## Historical failures, retained as evidence

1. Before initial implementation, exact accepted PR25 production files plus the
   new compiling CLI regression actually ran:
   `go test ./internal/cli -run '^TestCoreNodesUnlockOptInRegression$' -count=1`
   **FAIL**: explicit offline unlock was rejected as unknown arguments. The same
   opt-in regression passed after wiring; this was not inferred from old code.
2. Code `c00b1bae0ef85ede306a1dc03ccb137b359da33a` / docs head `ba4dafc`:
   narrow race and full Go both **FAILed** only the two-backend
   `TestCoreNodeUnlockRevokesWholeBatch/*/lose-owner` cases. A live child closed
   its listener and returned a positive through an existing authenticated tunnel;
   the app published `completed`, egress and `apple=yes`. Web judge and isolated
   PR22 CLI composition passed. This was the original legitimate blocker, not a
   timeout/cleanup excuse, and the failing assertion has not been removed/skipped.
3. After ordinary merge of approved PR27 but **before app wiring**, checkpoint
   `1a7845d` actually ran the unchanged whole revocation test:
   `go test -p 1 ./internal/app -run '^TestCoreNodeUnlockRevokesWholeBatch$' -count=1 -v`
   **FAIL**, both `lose-owner` cases still published positives. Merely importing
   PR27's sampler does not substitute for active request/adoption Check gates.
4. First integration author run fixed lose-owner, but deadline/exit test setups
   revoked before the other node could obtain any positive with required fresh
   checks. Exit injection is now commanded after actual positive/blocked events,
   not the former 100ms timer. That test's explicit parent deadline is now 1s,
   not 500ms; the positive-before-failure, all-unknown, cleanup and unchanged 2s
   completion assertions remain. A separate actual-client test verifies a 500ms
   request deadline wins over a 2s node deadline at all request/dial/read gates.
   No production budget increased and lose-owner assertions are unchanged.

New app regressions cover old handle/restart separation; an established socket
losing authority before proxy authentication sends zero bytes; known real listener
takeover sends zero bytes; background Done cancellation of a blocked independent
CONNECT peer; and CheckAll failure on another node clearing a real earlier
IP/service positive. Commands/acknowledgements and channel events order the new
faults, not guessed sleeps. All fixtures are loopback-only; no public measurement.

The original missing-API blocker is now addressed by authorized PR27 integration,
not by weakening its requirement. Author checks below are not independent review.
