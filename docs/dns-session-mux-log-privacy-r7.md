# DNS session mux-path logging privacy (round 7)

## Scope and success criterion

This follow-up starts at PR16 commit
`32c6f992487b163f075ab7bed98a735f923e7035`, with PR base
`fix/dns-sessions-r6-20261024`. It changes only the pre-mux logging guard,
its API regression tests, and the stale OpenAPI token parameter description.
A sensitive request must write neither caller/path logs nor results to SQLite,
even when the mux canonicalizes or rejects it; ordinary request logging must
remain intact. No parent roadmap or earlier branch is modified.

## Source-grounded behavior

The installed Go 1.27.3 implementation was read before implementation:
`net/http/server.go` (`findHandler`, `cleanPath`, `ServeHTTP`) and
`net/http/routing_tree.go` (`matchPath`, `firstSegment`). For non-CONNECT
requests, ServeMux cleans the **escaped** path, then splits on literal slashes
and unescapes individual segments once for matching. CONNECT skips cleaning.
Thus in `/x%2Fy/../v1/dnsleak/<fixture>`, `..` removes the single escaped
`x%2Fy` segment. Splitting `URL.Path` first instead sees two segments and misses
the sensitive namespace. Logging happens before mux dispatch or redirects.

The guard now checks both views:

- The existing decoded-path prefix history remains protected, including encoded
  slashes/dots and sensitive prefixes subsequently removed by `..`.
- The escaped-segment history uses literal dot segments for popping and decodes
  segment values once for comparison. Encoded slashes cannot change pop depth.
  Checking prefixes during traversal also protects paths that leave the namespace.

Neither view is recursively unescaped: a multiply encoded literal namespace
that does not become sensitive in either view is not a session route. Regression
controls preserve its ordinary logging. Nested encoding inside an opaque segment
or bearer does not bypass the guard. This is not a generic URL rewrite, substring
filter, case-folding rule, or change to mux dispatch/redirect responses.

## Actual regression evidence

`TestDNSSessionMuxPathPrivacy` uses the real `Server.Handler`, loopback HTTP
with redirects disabled, and a temporary **file-backed SQLite database**. It
covers 20 path variants, GET/HEAD/POST, and both enabled/disabled sessions
(120 sensitive requests). Cases include upper/lower escaped slashes, percent-
encoded namespace letters and dots, duplicate slashes, subsequently removed
sensitive prefixes, and double/triple encoding. Nine ordinary controls per mode
verify exact decoded persisted paths and the documentation-only caller address.
Errors report case names/counts, never request paths, response bodies or bearers.

Before fixing production code, the new regressions were actually run against the
old implementation; the final regression was also re-run with both production
files restored from the specified base, then the fix restored. Command:

```sh
go test ./internal/api -run 'TestDNSSession(MuxPathPrivacy|TokenParameterDescription)$' -count=1
```

It exited 1: **78 sensitive-request cases** persisted logs, and the token
parameter description test failed. The encoded-slash counterexample reported
`log rows=1 result rows=0 bearer rows=1 caller rows=1`, with no secret values
printed. This is observed SQLite persistence, not an inference from the helper.
The same tests pass with the fix; sensitive requests leave both checked tables
empty and all ordinary controls still log.

## Verification

Local environment: macOS arm64, Go 1.27.3. Logs are retained locally under
`/tmp/ipd-r7-mux-evidence/` (not a portable repository artifact).

- Narrow regression and existing prefix-history/path-privacy tests: PASS.
- `go test -race ./internal/api ./internal/leak -count=1`: PASS.
  This also retains coverage for default-off, complete text output, no-store
  SSE, expiry, wire behavior, bounded state and listener shutdown.
- `go test ./... -count=1`, without portability changes: FAIL only in the known
  macOS cases `TestServeTLSHandshakeAndH2` and `TestSnapshotUncappedMapLoad`.
- With PR2 commit `0511d997db96f541c1a1953be7c08fb1fc99aecb` temporarily applied,
  `go test ./... -count=1`: PASS. The patch was then reversed; none is committed.
- `node --test web/judge.test.mjs`: PASS (1 test).
- `git diff --check`: PASS.

## Boundaries

No delegation, merge, deployment, DNS delegation, public-IP probing, repository
setting changes or CI monitoring was performed. No new independent review was
requested by this implementation child; review/merge acceptance remains with the
parent. External proxy/access logs, real resolvers, physical services and browser
leak detection are unverified and unchanged. Operators must still exclude bearer
paths from external access logs. Session defaults, text/SSE policies, TTL and
other PR16 behavior are not changed by this follow-up.
