# Subscription fetch boundary

`Nodes` still has the baseline measurement behavior. This change only replaces
its source reader; it does not change any other probe's destination policy.

## Remote sources

- Parse HTTP(S) with `net/url`; reject userinfo, opaque URLs, malformed hosts and
  ports, scoped IPv6, non-ASCII DNS labels, and legacy ambiguous numeric IP forms.
  Known inline proxy URI schemes are data, not fetch targets.
- Resolve both A and AAAA using the Go resolver with strict errors. Reject an empty
  answer, any lookup error, or **any** unsafe address; do not filter a mixed answer
  down to its public subset. Literal IPs receive the same address validation.
- Unmap IPv4-mapped IPv6 before policy checks and dialing. Reject private,
  loopback, link-local/metadata, shared, multicast, documentation, benchmarking,
  transition and special-purpose ranges. IPv6 must also be in a currently
  allocated RIR global-unicast prefix, not merely inside the broad global pool.
- The policy deliberately excludes even globally reachable special-purpose
  services. Its static ranges need maintenance when IANA allocations change:
  [IPv4 special-purpose registry](https://www.iana.org/assignments/iana-ipv4-special-registry/),
  [IPv6 special-purpose registry](https://www.iana.org/assignments/iana-ipv6-special-registry/),
  [IPv6 global-unicast allocations](https://www.iana.org/assignments/ipv6-unicast-address-assignments/).
  The retrieved registry versions are dated 2025-10-09 and 2025-10-10.
- A fresh transport pins each request's dialing to the validated numeric answers;
  it never gives a hostname back to the dialer. Keepalive reuse is disabled. The
  original URL and Host remain intact for normal HTTPS certificate/SNI checks.
- Each redirect (including a same-host redirect) repeats URL and DNS validation;
  at most 10 redirects are followed. Redirect Referer headers are removed to avoid
  forwarding query tokens. Environment proxies are never used. An explicitly
  configured proxy is rejected because its remote resolution/CONNECT behavior
  cannot preserve this boundary; it is **not** silently ignored.
- A total 20-second context deadline covers DNS, dialing, TLS, headers, redirects
  and body reading; caller cancellation/deadlines also apply. Only final 2xx
  responses are accepted. Reads use `limit + 1`, reject bodies over 2 MiB, and
  return no partial body after a read error. Fetch errors never wrap URL, DNS,
  transport or body errors that could contain subscription secrets.

## Local data and test seams

Local files and inline YAML/proxy URIs remain available; their bodies now have
that same strict 2 MiB limit instead of silently accepting oversized local data.
Explicit proxy configuration does not affect local data. Inline schemes include
ss/ssr/vmess/vless/trojan/hysteria/hysteria2/hy2/tuic/socks/socks5; arbitrary fetch
schemes such as FTP are not subscriptions.

Resolver and dial injection are private, per-transport fields, not global mutable
hooks, CLI/config settings, or trust-private switches. Address policy is always
applied in the validating transport. The low-level pinned-socket helper and the
HTTP/body helper are separately exercised with documentation IPs and loopback
`httptest` servers. Full validating-transport tests use `example.invalid` with a
synthetic answer derived from the allocated-prefix table, routed by the test
**dialer** exclusively to loopback. No real public server or visitor IP is used,
no public connection is made, and no policy predicate is replaced. The fixture's
second DNS answer becomes loopback: the first request must dial its original
numeric answer, and the next request/same-host redirect must fail closed.

These checks constrain application-selected destinations. They cannot defend
against an operator routing public numeric addresses to internal services;
network egress controls remain defense in depth. Ordinary HTTP is not encrypted;
use HTTPS for confidentiality/authenticity against on-path attackers.

## Verification

Before implementation, these three deterministic regressions were added and run
against `19a0b16962a8d249179ce376db3847ba594c3fb4`:

```text
go test ./internal/app -run 'TestSubscriptionRejects' -count=1
FAIL TestSubscriptionRejectsInitialLoopback: accepted and contacted fixture
FAIL TestSubscriptionRejectsOversizedLocalFile: accepted 2 MiB + 1
FAIL TestSubscriptionRejectsNonSubscriptionScheme: accepted FTP as inline data
```

The final subscription suite also covers mixed DNS answers in either order,
IPv4-mapped/IPv6 policy, literal targets, same-host/private redirects, numeric
pinning, environment/configured proxies, TLS verification, redirect loops,
status/body/read failures, exact/over-limit bodies, cancellation in DNS/headers/
body, deadline expiry and credential/query error sanitization.

Required checks are `go test ./...`, `node --test web/judge.test.mjs`, and
`go test -race ./internal/app -run TestSubscription -count=1`.
On this Mac, the unpatched full suite has the two existing Linux-only failures
(TCP MSS and `/proc/self/maps`). The full suite passes with PR2 `0511d997`
temporarily applied. A combined run with PR10 `9035290` plus that platform-only
patch passes, including `go test -race ./internal/app -count=1`. Neither
independent change is included in this branch. Independent parent-thread review
is still required before acceptance.
