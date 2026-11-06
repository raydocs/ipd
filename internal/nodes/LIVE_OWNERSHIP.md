# Single-run live ownership capability

## Scope and dependency

Dependency: accepted PR23 runner candidate
`8331260018a4b34cc4874e0ea0ba30271a52a24f` (#23 remains separate).
This branch starts from that exact candidate and synchronizes fetched `origin/main`;
the independent Draft targets **main**, not PR23 or the parent summary branch.
Only `internal/nodes` and its contract/tests change. No app/CLI/PR26 wiring or
failing PR26 implementation is imported; PR26's tests must remain unchanged there.
This draft does not authorize merge, deployment or installation of real cores.

## API and binding

The existing `Runner`, `Start`, `StartFile`, `Stop`, `Endpoints` and `Err` APIs
remain available. `ExecRunner.StartWithHandle(ctx, path)` and
`StartFileWithHandle(ctx, file)` additionally return
`(map[string]string, *RunHandle, error)`. Only a successful start returns a
non-nil handle; failed/busy starts return no capability. Configure the runner
before use, as before.

A `RunHandle` has private fields and no PID/owner-evidence/credential accessor:

- `Check(ctx, name, expected Endpoint) error`: exact run/name/backend/SOCKS/HTTP
  binding plus a **fresh kernel ownership query**, never a protocol-only probe.
  Pass an endpoint from the existing `Endpoints` copy. Missing names, changed or
  cross-node/old-run endpoints fail closed without emitting those values.
- `CheckAll(ctx) error`: fresh queries of the fixed, input-ordered children, then
  a shared state-generation/lifetime gate after the last result. A failure already
  observed by another checker, context callback or child exit cannot be overwritten
  by a queued positive or a late successful query.
- `Done() <-chan struct{}`: closes once at **logical revocation**, not cleanup
  completion. Consumers must use this signal to cancel blocked clients and discard
  the whole batch of provisional observations. It grants no automatic wrapping or
  atomic authentication of an arbitrary HTTP/SOCKS client.
- `Err() error`: promptly reports the sanitized first failure, later joining any
  cleanup errors. It never switches to a later run, even after the runner restarts.

The immutable mapping is run -> direct child -> original endpoint/port. A handle
retains only that run, never `ExecRunner.run`. A stale handle cannot check a new
run, revive itself, or invalidate a later run. The old SOCKS map and endpoint URLs
are not perpetual capabilities; retaining them does not extend their validity.
`Endpoints()` is a synchronized map snapshot, **not** a fresh OS attestation.

## Revocation, budgets and cancellation

Every active check queries the existing Linux proc fd/inode/netns implementation
or Darwin's trusted system `lsof`, with their unchanged fail-closed evidence
rules. Missing, foreign, ambiguous or unavailable ownership; query errors;
query timeout; child exit; and context cancellation/deadline all revoke the
**entire** batch once. There is no credential/protocol request to establish live
ownership, and no fallback when OS evidence is unavailable.

OS queries run outside the state lock. The first invalidation closes `Done`,
clears public endpoints and fixes the cause under the same short lock **before**
cancellation, slow in-flight queries, Kill/Wait or filesystem cleanup can delay
logical revocation. An uncooperative OS query may finish later; its buffered
result cannot republish state. Stop/cleanup do not wait for that query. The monitor
stops at the first failure, rather than accumulating repeated timed-out queries.

Fixed bounds (no public testing/security override):

- Each OS query, including startup: at most **500ms** of allowed wait.
- Each `Check`/`CheckAll` sweep: at most **5s**.
- Background monitor: a **100ms** ticker, serialized bounded sweeps, for every
  successful start including the legacy API. A persistently missing listener is
  eventually sampled, or an intervening slow sweep itself times out and revokes.
- Existing startup and whole-run `Budget`/parent-context deadlines still apply.
  Each query receives the earliest of the caller/node context, its 500ms budget,
  the 5s sweep and the run's batch deadline. Pass the node's context to `Check`
  to impose a node deadline; the handle cannot infer an external client's budget.

**Canceling even one Check call revokes the entire run.** This is intentionally
not a retryable per-call error: partial evidence must not remain publishable.
Cancellation is checked both while waiting and at the final state gate. Canceling
an already-returned check context does not invalidate a later operation; the
original Start context still controls the full lifetime. Startup expiry stops
applying after successful acceptance, as in PR23.

`errors.Is` distinguishes `ErrRunnerStopped` (ordinary explicit Stop, also
`context.Canceled`) from `ErrRunnerExit`, `ErrRunnerOwnership`, and
`context.DeadlineExceeded`/external `context.Canceled`. A lifetime failure pending
callback scheduling wins over a subsequent Stop. `ErrRunnerCleanup` and
`ErrRunnerStorage` can join **any** first cause, including normal Stop; a cleanup
warning must not be treated as clean success. Repeated Stop preserves it.
Consumers should validate provisional results with CheckAll before normal Stop,
then distinguish expected `ErrRunnerStopped` from an actual prior failure and
from cleanup warnings; do not blindly discard success just because Stop canceled
the child context. This PR deliberately does not implement that app policy.

## What is and is not promised

**Observed failure revokes immediately at the logical state transition; sampling
and query waits are bounded in user space.** These are not hard real-time
scheduling guarantees or an atomic multi-node OS snapshot. The generation gate
rejects *known* concurrent invalidation, not an unobserved change to an earlier
node while a later node is queried. Another active check or the next monitor sweep
can observe that change and revoke even if a prior sweep returned successfully.

Rapid close/rebind by the same live PID between samples, the check-to-dial window,
and the identity of an already-connected receiver are **not absolutely
attested**. Kernel ownership at one observation is not cryptographic server
identity. Trusted cores must not delegate their listener fd; this is not a sandbox
against malicious same-user programs. No claim is made to prevent all races,
retract bytes already delivered to a consumer, or prove real-core interoperability.

## Regressions and evidence

`TestRunnerLivePIDListenerLossRevokes` uses only the old public Start/Endpoints
API and new event-driven helper behavior. Both real helper children read the
production private backend config. One retains its live PID and an authenticated
blocked CONNECT tunnel while acknowledging listener closure, then can deliver a
recognizable positive through that old tunnel. The test demands batch revocation,
not a new API compile error. It actually FAILed on exact PR23 production code for
both mihomo and sing-box before the production change.

The new API fixtures cover both backends, two real children, active/all-node
checks, background-only interruption, real external accept-any takeover receiving
no requests, IPv4/IPv6 ambiguity, unavailable/query-error evidence, binding changes,
old handles/restart, cancellation/deadline, a held successful OS query, and actual
cleanup/error identities. A 24-child event-gated sweep retains the original scale:
after the last real query has succeeded but its result is held, the first node
closes its listener and a fresh check invalidates the batch before the held result
or a bounded real 8192-file cleanup tree finishes. Timing wrappers are private,
per-run test function boundaries; ordinary API fixtures call production OS queries
without wrappers. Commands/acknowledgements, channels and deadlines order events;
new tests do not select attack windows with sleeps or reduce the 24-node case.

Local helpers are not mihomo/sing-box binaries and never contact an airport.
Darwin uses real system lsof locally. Linux runtime ownership behavior is a
separate acceptance gate; Linux cross-compilation is not runtime proof. Author
checks are not independent review. PR26 app integration remains separately
blocked until this API increment is reviewed and accepted.

### Actual author checks (Darwin, frozen code c0ccb0a)

Environment: Darwin 25.5.0 arm64, Go 1.27.3, Node v26.12.1.
Fetched/synchronized main: `3a0832284585118d473a7fd08fb4c924831f760b`.
Code head: `c0ccb0a4d83e01403bef37c79257da97fd3e086d`; the following
commit only records this evidence.

- Exact PR23 `git archive 8331260` + only the new regression/helper files:
  `go test ./internal/nodes -run '^TestRunnerLivePIDListenerLossRevokes$' -count=1 -v`
  actually **FAILed** for both backends (exit 1). Both logs first record the
  existing authenticated tunnel returning `fixture-positive`, with PID alive
  at the listener-closed marker, then fail because endpoints remain valid.
- `go test ./internal/nodes -run '^TestLive|^TestRunnerLivePID' -count=1`:
  PASS (24.274s, before the final fail-fast invalid-channel gate).
- `go test -race -p 1 ./internal/nodes -count=1`: PASS (40.451s), all nodes
  tests, no race diagnostic.
- `go test -p 1 ./... -count=1`: PASS, all packages (nodes 37.816s).
- `node --test web/judge.test.mjs`: PASS, 1 test.
- `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o /tmp/ipd-live-nodes-linux-amd64.test ./internal/nodes`:
  PASS **compile only**, no Linux runtime result.
- `git diff --check`: PASS. The entire main-based diff is confined to
  `internal/nodes`; no app/CLI, ROADMAP-STATUS, PR26 code/tests or old PR branches
  were changed. All pre-existing nodes tests remain present.

During test authoring the first new narrow run failed a deadline assertion that
compared a query deadline to a timestamp taken *before* query-context construction.
The assertion was corrected to validate the delivered bound and exact shorter
caller deadline; no production timeout was increased or scenario removed.

Evidence directory: `/tmp/ipd-live-ownership-api.5E4fKJ/` (receipt and raw before/after logs).
The original PR26 arbiter fixture log remains
`/tmp/ipd-pr26-arbiter.jkFQv3/arbiter-fixture.log` and was not modified.
Independent review and Linux runtime verification are still outstanding. No
app/CLI integration, PR merge, deployment, real-core or real-airport test was run.
