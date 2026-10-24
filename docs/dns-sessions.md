# Short-lived authoritative DNS observation sessions

This is an **opt-in backend capability**, not a deployed DNS service or a browser
leak detector. No NS delegation, domain configuration, public reachability or
browser path has been verified by this change. The automated integration uses
loopback sockets only. It does not contact a public resolver/proxy/service.

## Enablement and protocol

`IPD_DNS_SESSIONS_ENABLED` defaults to `false`. Disabled POST/GET requests return
HTTP 503 with `DNS sessions disabled`; the DNS listener returns REFUSED and records
nothing. An invalid configured zone also fails closed. `IPD_DOMAIN` determines
exactly `dns.<domain>.`; `IPD_DNS_ADDR` determines the auxiliary socket address.
Enabling the feature **does not configure delegation or test connectivity**.

1. Explicitly POST `/v1/dnsleak` (no request body). HTTP 200 returns a Report with
   verdict `abstain` and data `{token, query_names, expires_at}`. The bearer token is
   16 bytes from `crypto/rand`, encoded as 32 lowercase hexadecimal characters.
2. Resolve the three returned query names explicitly using the intended path.
   They have the form `q0.<token>.dns.<domain>.` through `q2...`. Each name can
   contribute an observation **once**, across both UDP and TCP. DNS retries still
   receive an answer but cannot add observations. A/AAAA/TXT are supported. Known
   names with other types return NOERROR with no answer and do not consume a name.
3. GET `/v1/dnsleak/{token}` returns a Report with data
   `{expires_at, observations:[{resolver, ecs?, at}]}`. It reads only this session
   and never triggers resolution or calls the comparative `DNSLeak` method.
   Unknown/expired tokens return 404. There is no token echo or `leak` boolean.

A/AAAA answers are fixed documentation-only addresses (`192.0.2.1`,
`2001:db8::1`); TXT answers contain `ipd`. TTL is zero, recursion is unavailable.
Outside-zone/disabled/non-IN queries return REFUSED. Unknown, expired, unissued
or extra-label names inside the zone return authoritative NXDOMAIN. The zone
apex returns NOERROR/NODATA and does not create a session. Invalid question counts return FORMERR and
unsupported opcodes return NOTIMP. A random name merely containing `.dns.` is
never accepted.

## Bounds and privacy

- Lifetime: two minutes, checked at issuance, every query and every GET. Capacity:
  256 live sessions; full capacity returns 503 without evicting a live session.
- At most three query names and three observations per session. Observations are
  deduplicated by recursive source address plus masked ECS prefix. Time `at` is
  the first accepted observation time; retries do not update it. Returned slices
  are copies. A mutex serializes issuance, consumption, reads and cleanup.
- Expired entries are deleted on every operation; a running listener additionally
  sweeps once per second. An idle recorder without a listener retains at most its
  fixed capacity until the next operation. Nothing is persisted across restart.
- The recorder retains only session token, expiry, three consumed bits, recursive
  source address, optional ECS **network prefix**, and observation timestamp. ECS
  is normalized/masked to no more specific than IPv4 /24 or IPv6 /56 (a supplied
  less-specific prefix stays less-specific); invalid ECS is omitted. Raw qnames,
  raw ECS host addresses, HTTP visitor addresses and headers are not retained by
  the session recorder. Derived names are returned to the bearer, not stored.
- Session responses use `Cache-Control: no-store`. Only these HTTP paths (including
  canonicalization redirects) bypass the application's persistent visitor/path
  logging; unrelated HTTP behavior, rate limits and negotiation are unchanged.
  No session or observation is written to SQLite. Operators must separately keep
  bearer paths out of any external proxy/access logs; this change configures none.
- Treat both token and query names as secrets until expiry. They are capabilities,
  not accounts. The existing HTTP rate limiter still applies; capacity exhaustion
  is possible and is reported explicitly, not disguised as empty safe evidence.

## Interpretation

An empty observation list means **unknown/abstain**, never safe. A nonempty list
also remains `abstain`: it identifies the source seen by this authoritative
listener, potentially a forwarder, NAT or spoofed UDP source, not necessarily a
browser's configured recursive resolver. There is no country/ASN comparison or
claim of leak/blocking causality. The existing CLI/MCP comparative DNSLeak behavior
is deliberately unchanged. Browser automation and UI are out of scope.

UDP and TCP share the exact `Service.DNSSessions` recorder. `cli.aux` now serves
that recorder instead of an empty `OnQuery` callback. Both transports bind before
serving; a bind/runtime failure or cancellation closes both sockets and joins
both listener goroutines. The injected clock supports deterministic expiry tests.

## Local verification and integration boundary

Tests issue real HTTP sessions, send actual loopback UDP A / TCP AAAA / UDP TXT
queries, and read the observations through HTTP. Unit fixtures cover strict zone
matching, unknown/expired/disabled sessions, one-time names, deduplication, ECS
masking, capacity, concurrent issuance/reads/queries and listener cleanup. They
also check SQLite remains untouched and unrelated logging is unchanged. This is
**local evidence only**, not proof of NS delegation or a browser test.

This branch starts explicitly at PR14 candidate
`c173c7863c710092f584c9818cdbcc9e2ee09d2a`, dependency branch
`fix/openapi-contract-r5-20261024`. No controller docs or other PR code is included.
PR11 (`feature/cli-language-en-20261024`) also edits `internal/cli/cli.go`: retain
its language/output changes while keeping the one `aux` recorder call here.
PR7 (`t3/aienv-unknown-prioritized-fixes`) also edits `internal/app/service.go`:
retain its diagnosis changes together with this recorder field/import/initializer.
Do not connect this evidence to AIEnv or comparative leak verdicts implicitly.
The parent must independently review the diff and run combined tests before
acceptance; this implementation is not a merge or deployment authorization.
