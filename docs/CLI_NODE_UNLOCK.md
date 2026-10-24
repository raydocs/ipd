# Explicit per-node unlock increment

## Acceptance boundary

Success means an explicit `nodes --measure --unlock <comma IDs>` runs the shared
unlock engine through the **same still-live authenticated loopback runner endpoint**
as each node's egress probe, with no host/network fallback. Two real helper child
processes and local HTTPS fixtures must prove distinct ordered observations,
conservative marker decisions, budgets and whole-batch lifetime revocation.
Default PR25 egress-only invocation must make no additional requests. Offline must
start no children and send no requests. Reports remain overall `abstain`.

Dependencies: PR23 runner `8331260018a4b34cc4874e0ea0ba30271a52a24f` and accepted
PR25 egress `676aabffbf08a40010570bc04bc2049cf5072212`. This branch starts at the
exact PR25 implementation head, **not** the parent coordinator's summary/doc
history, and ordinarily synchronizes fetched `origin/main`. The independent draft
PR targets `main`; the inherited runner/egress diff is dependency code, not this
increment. Runner security and shared unlock decision logic are out of scope.

No purity, conversion, UI, account-safety, login or actual playback claims. Local
helpers are not mihomo/sing-box interoperability or real-airport evidence. Parent
fresh-context independent review/acceptance is still required before integration.

## Implemented invocation and limits

```sh
ipd --lang en --json nodes --measure --backend mihomo \
  --mihomo-bin /absolute/trusted/mihomo --unlock apple,meta_ai nodes.yaml
```

- Explicit selection only: 1–4 unique exact IDs from `apple`, `meta_ai`, `netflix`,
  `claude`, `chatgpt`. Other shared-catalogue IDs, empty entries, duplicates,
  whitespace/case variants and excess IDs are rejected before source loading,
  process startup or requests. CLI `--unlock` requires `--measure`.
- Each selected node shares one authenticated loopback HTTP client for egress
  and the dedicated `unlock.Getter`. `unlock.Engine` and runner safety code are
  unchanged. Resolve is a non-network callback; its method label is not output.
- Exact HTTPS catalogue request URLs only, including required trace paths;
  **no redirects**, even catalogue redirects. No cookies, auth headers, arbitrary
  headers, environment proxy, native DNS, DIRECT fallback or unverified TLS.
- At most 12 unlock GET attempts/node, 256 KiB wire and decompressed body/request,
  8 KiB response headers/request, 5s/request, 20s/node including egress, 45s/batch
  including startup, 4 workers and at most 64 nodes. Thus at most 768 unlock GET
  attempts/batch plus the unchanged at-most-64 egress GETs. Startup readiness is
  separate local-only runner protocol probing, not a service request.
- Required-path failures, unknown templates, challenges, redirects, truncated or
  oversized bodies/headers abstain. Request/node/batch deadlines and cancellation
  invalidate all egress and unlock rows, rather than retaining earlier positives.
  Other per-service evidence gaps abstain for that service. Output projects only
  fixed service/status/evidence codes and a validated two-letter region.
- Test URL mapping and CA roots exist only at unexported function boundaries;
  no public flag, config, environment variable or service field enables them.

## NOT ACCEPTED: live listener ownership blocker

The new regression `TestCoreNodeUnlockRevokesWholeBatch/*/lose-owner` exposes a
remaining requirement that cannot be claimed implemented. A real helper keeps
its PID and existing authenticated TLS tunnel alive, closes its listener, and
then returns a recognizable service positive. The batch currently publishes
`completed`, egress IPs and `apple=yes` instead of clearing everything. This is
not merely slow cleanup or a request-timeout issue.

PR23 verifies kernel listener ownership during startup/final publication, but
`ExecRunner.Endpoints` / `Err` subsequently expose synchronized process/context
lifetime only (`runner_state.go: liveEndpoints/failure`); `execute` waits on
`invalid` after publication. There is no exported endpoint-owner PID/token or
post-publication ownership revalidation API for the app. Rechecking the endpoint
map cannot detect this case. Do **not** infer continuing kernel ownership from
that map or silently weaken the test.

The task expressly forbids changing runner safety code. No such code was changed,
no duplicate OS ownership implementation was added, and no public security hook
was introduced. Parent must authorize a separately reviewed runner API/lifetime
increment (or explicitly narrow the requirement) before this draft can be accepted.
No merge, deployment or real-airport use is appropriate for this candidate.

## Actual regression evidence

Before implementation, on production files exactly at accepted PR25 `676aabf`
(the only prior commit here added this dedicated scope document):

```text
go test ./internal/cli -run '^TestCoreNodesUnlockOptInRegression$' -count=1
FAIL: explicit offline unlock rejected: 节点测量参数无效
```

The corrected, compiling test actually ran and failed; this is not inferred from
reading old code. The implemented opt-in test subsequently passed. The two-core
production fixture checks (distinct IP/region/yes/no, all supported paths), marker,
challenge/unknown, no-env/no-host-fallback, TLS, body/header/gzip/request budgets,
offline/default and cancel/deadline/core-exit cases passed in narrow execution.
The strengthened live-owner-loss regression actually fails for both backends,
returning completed positives after the listener-revoked marker. It is intentionally
retained as a blocker, not special-cased away. Helper binaries are not real cores.
