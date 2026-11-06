# Read-only terminal /cc

## Contract and use

Independent terminal observation, not the browser/runner/scoring flow. Success
means only a well-formed observation from the configured origin. It does NOT
mean an account is safe, DNS does not leak, or another service sees the same IP.
The source is /cc/ip's transport peer. Behind a reverse proxy that can be the
proxy, not your egress. Forwarding headers are deliberately ignored.

Replace the placeholder with an operator origin you trust. Audit first:

    curl -q -fsS --proto '=https' --connect-timeout 3 --max-time 10 https://YOUR-TRUSTED-ORIGIN/cc

Execute after auditing:

    curl -q -fsS --proto '=https' --connect-timeout 3 --max-time 10 https://YOUR-TRUSTED-ORIGIN/cc | sh

Requires POSIX sh and already-installed curl >= 8.4. Older curl is rejected:
its size limit does not bound unknown-length/chunked responses. Nothing is
installed; no file/profile/proxy/DNS/network setting is changed. No eval, source,
or second downloaded program. Responses are never executed. The script runs
only shell builtins and curl. No account/key, password/token, environment dump,
username/hostname, history, fonts or browser signals are collected/uploaded.
It prints curl's numeric version and presence ONLY of proxy environment
variables, never values/credentials. Proxy settings can affect the path;
failure does not trigger direct fallback.

**Pipeline caveat:** POSIX sh reports the final command's status, not curl's.
Download failure can yield empty stdin and shell exit 0: NOT an observation.
-fsS displays errors but cannot solve pipeline status. For reliable download
status without files, capture first; run only after successful nonempty download:

    script=$(curl -q -fsS --proto '=https' --connect-timeout 3 --max-time 10 https://YOUR-TRUSTED-ORIGIN/cc) &&
        [ -n "$script" ] && printf '%s\n' "$script" | sh

Initial download executes code from that origin. A compromised script origin
cannot be sandboxed by this script. Initial-download curl configuration is the
user's responsibility (-q disables curlrc); do not add credentials or redirects.

## Trusted origin binding

Set IPD_CC_ORIGIN explicitly to your trusted public HTTPS origin. No deployment
default is supplied. Never derive it from Request.Host, X-Forwarded-Host, stdin,
or caller arguments. The handler validates the entire origin before embedding
it as a shell literal: no credentials, query, fragment, non-root path, shell
metacharacters, zone IDs, or invalid ports. HTTPS accepts DNS names/IP literals.
Explicit loopback development origins may use HTTP, e.g.
http://127.0.0.1:8787, http://localhost:8787 or http://[::1]:8787.
No other HTTP origins are accepted. The script knows its origin because the
handler binds this configuration into it, not by discovering its download URL.

Missing/invalid origin or IPD_OFFLINE yields HTTP 503 with an offline explanation
and error script (exit 3 if executed). No default external service. Existing
behavior and default configuration remain unchanged.

## Dedicated endpoint / privacy limits

One fixed GET to the bound origin's /cc/ip: no query, body, API key, cookie,
environment values or local signals. No calls to /v1/me, fingerprint, report,
leak, lookup or other persisted-signal endpoints. /cc/ip returns only canonical
IPv4/IPv6 or unknown as text. No enrichment, storage or forwarding. /cc and
/cc/ip bypass application IP-log persistence and use Cache-Control: no-store.
The ordinary in-memory request limiter still applies.

**No private signal upload is not no server visibility.** HTTP necessarily
reveals connection IP and standard transport/request metadata. Proxies,
hosting and access logs may record requests independently of this application.
Operators must configure access-log retention themselves. This is not anonymity,
an end-to-end egress guarantee, or a promise of no HTTP logs.

## Response / exit contract

Internal curl disables curlrc, verifies TLS, restricts protocols to HTTP(S),
does not follow redirects or retry, and sets 3-second connect / 6-second total
timeouts and a 256-byte response cap, including unknown-length transfers.
HTTP errors, redirects, timeout, offline and oversize yield unknown. Curl stderr
is suppressed to avoid proxy credential disclosure. Only validated IP characters
are printed. Malformed/control-bearing/excessive text is rejected, never eval'd.
Shell substitution may discard NUL bytes; they are never emitted. One trailing
LF is accepted. Text IP or the exact minimal JSON object {"ip":"IP"} is accepted;
other JSON shapes/whitespace/fields are rejected. Server IPv4-mapped addresses
are normalized to IPv4.

* 0: well-formed observation only, NOT a pass/safe verdict.
* 2: missing/unusable/too-old curl.
* 3: request/HTTP/size/timeout failure, offline, or endpoint unknown.
* 4: malformed/untrusted response.

Codes apply to an actually executed script, not an empty failed-download pipeline.

## Verification

httptest + real installed sh/curl, loopback network and documentation IP fixtures
only. Tests cover origin rejection/binding, no persistence, IPv4/IPv6/unknown and
strict JSON/text parsing, shell/control payloads, known/chunked oversize, timeout,
HTTP errors/redirect, TLS verification, proxy failure without direct fallback,
curlrc isolation, secret non-upload, missing curl/offline and unchanged files.

    go test ./internal/api -run 'TestCC|TestOpenAPI' -count=1
    go test -race ./internal/api -run TestCC -count=1
    go test -p 1 ./...
    node --test web/judge.test.mjs

No deployment, real-server IPs, external accounts or real-service probes needed.
Independent security review remains required before merging/deploying.
