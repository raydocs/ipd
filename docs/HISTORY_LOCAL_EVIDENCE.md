# Local history evidence (partial increment)

## Exercised surface
GET /v1/ip/{ip}/history still uses the existing history store and service. It now
includes ordered snapshots (prefix, ASN, CC, type, flags and provenance), bounded
field differences and anonymous local neighbor counts. The response is partial
when observations exist and abstain when none exist. Zero differences is not
evidence of stability, safety, cleanliness, routing continuity or causality.
Empty CC, ASN 0 and unknown/abstained classifications are not upgraded.

Neighbors mean latest stored observations per address within the response window,
including the requested address. The grouping is an explicit /24 IPv4 or /64 IPv6
address bucket, NOT a BGP/routing prefix. Only counts and type counts are returned;
no other observed address is returned. Missing rows are unknown. Future-dated rows
are excluded; ties use insertion ID. No subnet enumeration or network calls occur.
The existing static Prefix composition surface is unchanged and is NOT this local
neighbor evidence. No public BGP archive or external ingestion is implemented.

## Retention
IPD_HISTORY_RETENTION is a positive Go duration (e.g. 2160h); default 90 days.
Invalid, zero and negative values fall back to 90 days, including manually built
configs. History reads and recordHistory writes physically purge rows strictly
older than now minus retention across all targets. The boundary itself is retained.
Lookback days retain the existing 90-day fallback; the window is intersected with
retention. Purge errors abort those history operations. Direct low-level store
writers must explicitly invoke PurgeHistory; Store.Open alone does not purge.

This is lazy enforcement, not a wall-clock deletion SLA: an idle database retains
expired rows until the next history operation. No background scheduler is started.
Existing Risk behavior still ignores recordHistory errors; successful Risk does
not guarantee persistence. No unsupported completeness promise is made.
History differences compare only observations inside the window; there is no
synthetic baseline across the retention boundary.

## Provenance and compatibility
An idempotent SQLite migration adds a nullable provenance column without rewriting
legacy rows. Legacy AddHistory remains available and stores null (unknown)
provenance. New app records persist source IDs, source attribution/license and
matched record metadata from the existing lookup source evidence. [] means no
source hits, NOT a clean result. Observation timestamps are local recording times,
not upstream observation/update times; per-source dataset versions are not yet
persisted. Events describe adjacent local field differences only.
All public history store writes canonicalize/unmap IP text and reject zone-qualified
addresses. Compatibility reads canonicalize legacy stored keys without rewriting
rows, timestamps, ordering or provenance. Observations, History/HistoryUntil and
LocalNeighbors share this identity rule. Latest neighbors are selected per canonical
address by (ts,id), including aliases and same-second ties.

The API derives snapshots, events and aggregate neighbors from one streaming SELECT
and thus one SQLite read snapshot, even if another Store commits during iteration.
Only target snapshots and aggregate neighbor counts leave that view. The additive
migration obtains a dedicated connection, begins IMMEDIATE, then inspects and alters
the schema under the write lock; errors roll back and are propagated.

## Watch boundary and remaining work
The existing Watch create/list/delete/due-run skeleton is unchanged. There is no
new actual scheduler, webhook dispatch, default network activity, scan or download.
Retention-at-idle, source version capture, retention operation metrics, pagination
and indexed address-range neighbor aggregation remain future work. Neighbor
aggregation currently scans rows in the retained window for canonical aggregation; large stores
need scale validation. No raw neighbor IPs are exposed, but aggregates are not
anonymity guarantees or a multi-tenant authorization boundary.

## Validation
Regression TestLocalHistoryEvidence was executed on the unmodified origin/main
implementation: it failed because snapshots/retention/local neighbors were absent
and a 100-day-old row produced a field-change event. The same test passes with this
increment. Added store tests exercise legacy migration/reopen, exact retention
boundary, future exclusion, unknown provenance, metadata roundtrip, same-timestamp
latest selection, IPv6 membership and concurrent read/write/purge. API test uses
httptest directly, checking the real handler and OpenAPI response validation.
No new test makes public network requests.

Evidence logs for this implementation session: /tmp/ipd-history-evidence/.
Full-suite execution must block external networking because the existing repository
contains live public-provider/download tests. Such failures are reported, not
silently changed or treated as passing. Draft requires independent review before
acceptance, especially the additive migration and privacy boundary.

Session check results:
- Narrow store/app/config tests and HTTP/OpenAPI history checks: PASS.
- Targeted race tests across store/config/app/api: PASS.
- Full suite under loopback-only macOS sandbox: PASS (go test -p 1 ./...).
  The requested spelling go test -p1 ./... was attempted first, but Go treated
  the unrecognized flag as a test-binary argument and reported no root Go files;
  full-p1-spelling.log preserves that failure.
- node --test web/judge.test.mjs: PASS.
- Public-network live coverage is deliberately not claimed; external networking
  was blocked for the full suite. Independent diff review remains pending.

## PR36 R1 bounded correction evidence
The original candidate dbd0cda was executed with the unchanged R1 overlay: all four
reported classes failed (legacy IPv6, alias neighbor counts, cross-commit response,
and concurrent duplicate-column migration). Log: /tmp/ipd-pr36-before.log.
New committed deterministic tests were also executed against original production
files via overlay: canonical/mapped public reads, genuine first-row interleaving,
and concurrent legacy Open failed. The interleaving fixture steps a real SQLite
row, commits through another Store, checks the first response against its old view,
and checks that the next response sees the commit; no SQL/results are rewritten.
Log: /tmp/ipd-pr36-correction/new-tests-old-code.log.

Correction checks: narrow history tests and targeted store/app/api/config race PASS.
Full Go (`go test -p 1 ./...`) and Node (`node --test web/judge.test.mjs`) PASS; results are recorded in /tmp/ipd-pr36-correction/ (full.log,
node.log); external network access is blocked, loopback allowed for local fixtures.
The literal `go test -p1 ./...` fails with “no Go files”; the supported equivalent
`go test -p 1 ./...` is used for the full suite. No independent R2 acceptance is
claimed; fresh review and combined verification remain with the root owner.
