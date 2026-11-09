# China probe anchor history (bounded increment)

## Existing behavior and correction

`internal/probe/health.go` already contained a synchronized, binary health
tracker: three failures and a failure majority excluded a vantage. The old
Globalping decoder called `Observe` on **target** results, although `Observe`
was documented as anchor-only. Empty failed target results were immediately
excluded; successful targets could rehabilitate the same bucket. Those are not
independent probe-health observations. This increment removes both inferences.
DNS failure also no longer overrides an independently failed anchor gate.

There is no new anchor scheduler, network request, persistence, provider,
configuration setting, or domestic-machine assumption. BOCE remains optional.
Without an explicit independent anchor producer, production history remains
unknown. This is intentional, not an assertion that unknown probes are reliable.

## History contract

- `Health.ObserveAnchor(bucket, eventID, ok)` accepts an independently collected
  **anchor** outcome. Never call it with the judged target's result. Anchor
  selection and trusted ingestion are outside this increment. A producer must
  establish that it measured an independent anchor from the relevant vantage.
- Globalping lookup uses its existing `ASN/city` bucket. This is not guaranteed
  physical-probe identity; multiple probes can share it. Do not interpret these
  observations as independent physical-machine trials.
- The zero-value tracker is ready to use. Updates, snapshots, expiry and eviction
  are serialized by one mutex. Snapshot pointers refer to detached copies.
- Retain observations younger than 24 hours (exactly 24 hours expires), at most
  32 per bucket and 1,024 buckets. Oldest recently observed bucket is evicted,
  lexical key breaks equal-time ties. Caps are fixed implementation bounds,
  not calibrated parameters. Backward-clock future observations are discarded
  conservatively. Expiry is evaluated lazily on reads/writes.
- Repeated event IDs within a retained bucket are ignored, including conflicting
  replays. Empty bucket/event IDs are rejected. Deduplication ends when an event
  expires or is evicted; this is not a durable idempotency ledger.
- Legacy `Observe` remains an anchor-only compatibility method without event-ID
  deduplication. New producers should use `ObserveAnchor`.
- Fewer than three retained observations means `known:false`, `weight:null`.
  Counts and latest observation time remain visible. Expiry/eviction restores
  unknown history rather than an invented good or bad score.
- With three observations, weight is simply retained anchor successes divided
  by retained anchor observations. It is **not** a calibrated probability of
  target reachability, accuracy, independence, or future probe health.
- The previous binary exclusion rule is retained over this recent window:
  at least three anchor failures and more failures than successes excludes the
  bucket. Recovery/expiry is possible; target success never causes recovery.

## Actual aggregation wiring and scope

`decodeGP` reads an atomic snapshot into `Sample.AnchorHealth`. The single
approved addition in `internal/app/service.go` passes that value to
`gfw.Obs.AnchorHealth`. `gfw.Judge` orders eligible China evidence rows within
each carrier by anchor weight, descending, and exposes `anchor_health` in every
public probe row. Unknown history has neutral **display priority** 0.5, while
its public weight stays null. Equal priorities preserve arrival order. Carrier
order stays ct/cu/cm; control rows are not reprioritized.

This is **exposed evidence prioritization**, not weighted voting. No votes are
multiplied, no probes are synthesized, no observation is deduplicated or
removed by this sort, and no confidence constant is increased. Existing raw
eligible sample counts, carrier diversity, binary health exclusion and
abstention logic remain unchanged. This does not repair or certify unrelated
limitations in the existing state machine. A weight cannot promote no data,
insufficient evidence, or failed evidence into successful evidence.

## Verification

All fixtures are deterministic; the clock is injectable within probe-package
tests. Coverage includes unknown history, event replay, expiry boundary,
recovery, sample/bucket caps, snapshot isolation, concurrency, target failure
and success isolation, and DNS not overriding anchor failure. A local HTTP
Globalping fixture exercises the real decoder, service Sample-to-Obs mapping,
and aggregation ordering. Regression fixtures assert unchanged verdict,
confidence, carrier states and row counts for empty, sparse, failed and
single-carrier observations even with maximum history weight.

Old-code counterexample was actually run by temporarily restoring only
`globalping.go` from `origin/main` (3a08322), running
`go test ./internal/probe -run '^TestTargetResultsAreNotAnchors$' -count=1`, and
restoring the implementation. It failed with exit 1:
`failed target result 0 incorrectly rejected unknown probe`.
The same test passes with the new decoder.

The existing Globalping live test now requires `IPD_LIVE_GLOBALPING=1` so the
normal full-suite command does not create live Globalping measurements. No
live Globalping calls were made for this increment.

Root independent review and combined acceptance remain pending; this is a
Draft PR, not final acceptance or deployment authorization.

Checks on this increment:
- `go test ./internal/probe ./internal/gfw`: passed.
- `go test -race ./internal/probe ./internal/gfw -count=2`: passed.
- `go test -p 1 ./...`: passed all packages.
- `node --test web/judge.test.mjs`: passed (1 test).
- `git diff --check`: passed.
- The requested compact `go test -p1 ./...` invocation failed in this Go
  toolchain (`no Go files` at repo root); the correctly spaced equivalent above
  was run successfully instead.
