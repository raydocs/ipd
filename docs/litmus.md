# Litmus: bounded public challenge evidence (increment 1)

Acceptance: only an explicit CLI command makes one fixed-catalog GET; offline
makes zero requests. Fixture evidence can identify a known challenge without
changing unlock availability, AI, risk scores, HTTP API or MCP behavior. Limits,
unknown responses and contradictions abstain, and JSON never contains raw data.

## Command / 命令

```sh
ipd litmus google_search --offline --json
ipd litmus cloudflare_home --lang en --json
ipd litmus akamai_home --lang zh
```

The last two commands are explicitly online. Tests never run these commands
against public endpoints. Global language selection (including IPD_LANG) follows
the existing CLI contract; machine fields and enums are identical in both locales.
No target defaults, batches, URL/host flags, proxy/server/family overrides,
accounts, cookies, login, scripts, challenge solutions or browser impersonation.
Explicit proxy/server/family flags are rejected. Environment proxy/server values
are not used by this command. IPD_OFFLINE and --offline are honored.

Exit codes: 0 for help, 2 for invalid invocation (without echoing input), 10 for
**every observation**, including affirmative evidence. This command never emits
a clean/risky verdict or claims availability; it does not assign a risk score.
--md/--txt use the same short localized text; --json emits the dedicated contract.

## Fixed catalog and primary sources (verified 2026-11-06)

| ID | Exact URL | Primary provenance |
| --- | --- | --- |
| google_search | https://www.google.com/search?q=ipd | Existing unlock.google_captcha target; [Google Search Help](https://support.google.com/websearch/answer/86640?hl=en-GB) documents Search unusual-traffic observations. The query is project-chosen, not a vendor test endpoint. |
| cloudflare_home | https://www.cloudflare.com/ | [Cloudflare website terms](https://www.cloudflare.com/website-terms/) identify the official website. |
| akamai_home | https://www.akamai.com/ | [Akamai official company attestation](https://www.akamai.com/site/es/documents/corporate/pci-dss-attestation-of-compliance.pdf) identifies its main website. |

These are ordinary public pages, **not** vendor-provided challenge test services.
Official provenance does not establish that a particular page uses a particular
defense. No automatic requests to docs, subresources, redirect destinations,
challenge endpoints, or related sites. Homepage redirects intentionally abstain.

Detection references:
- [Cloudflare's documented cf-mitigated response](https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/):
  only an exact single cf-mitigated: challenge establishes that known marker.
- [Google's unusual traffic help](https://support.google.com/websearch/answer/86640?hl=en-GB):
  the message describes a traffic response, and reCAPTCHA may be shown.
  Our deliberately narrower **heuristic** additionally requires a parsed HTML
  form action /sorry/index or https://www.google.com/sorry/index. CAPTCHA evidence
  further requires a div with the g-recaptcha class. Unknown/localized templates
  abstain. Comments and script/style text cannot supply these markers.
- [Akamai challenge action documentation](https://techdocs.akamai.com/application-security/reference/post-challenge-action)
  describes multiple configurable response types; no universal public response
  signature is established. Increment 1 recognizes only AkamaiGHost server
  presence and **always abstains** on Akamai-specific challenge attribution.
- [Cloudflare Bot Management variables](https://developers.cloudflare.com/bots/reference/bot-management-variables/)
  expose scores to site-side rules/Workers, not this unauthenticated observer.
  Real CF Bot Score is always null with unavailable_public_observation. Even an
  apparent score header cannot change that.

## Evidence contract (CLI-only, schema version implicit in increment 1)

JSON keys: source (public_http), target (catalog ID), url (fixed requested URL),
observed_at (UTC RFC3339 timestamp at completion, or decision time if offline),
http_status (integer or null), scope (single_response_known_markers_only),
provider_presence, challenge_observed, captcha_observed, reason,
matched_markers, cf_bot_score (always null), cf_bot_score_reason.

The three evidence states are yes or abstain; there is intentionally **no no**.
yes means *only* a known marker in that one response, never authenticated provider
identity, globally enabled protection, request reputation, challenge success,
absence of risk, or absence of other CAPTCHA/challenge types. Presence is distinct
from challenge/captcha and is never folded into a score.
server=cloudflare / AkamaiGHost is presence-only; 403/429 alone means nothing.

Marker objects contain only fixed id/category/provider triples:
cf_server / provider_presence / cloudflare;
akamai_server / provider_presence / akamai;
cf_mitigated_challenge / challenge_observed / cloudflare;
google_unusual_traffic / challenge_observed / google;
google_recaptcha_widget / captcha_observed / google.
At most five, deduplicated. Conflicting provider or cf-mitigated values retain
markers but abstain on all three states.

Controlled reasons: offline, invalid_target (internal caller only),
timeout, request_failed, unexpected_redirect, header_limit,
unsupported_encoding, body_limit, empty_response, unexpected_status,
unknown_template, conflicting_markers, presence_only, recognized_challenge.
Live transport failures, including body/header/encoding limits, are intentionally
coalesced to request_failed. No arbitrary error strings are serialized.
No body fragments, raw headers, cookies, locations, credentials or secrets appear.

## Budgets and security boundaries

- One GET maximum; zero redirect follow-ups/retries; no cookie jar or environment
  proxy. No caller-provided header forwarding. TLS verification stays enabled,
  TLS minimum 1.2. Only fixed User-Agent and Accept-Encoding headers are sent.
- Whole observation: 8 seconds; request/body: 6 seconds; dial, TLS handshake and
  response headers: 3 seconds each, nested under the request deadline.
- Response headers: transport 16 KiB cap, then total parsed key/value budget
  16 KiB and 64 values. Excess abstains.
- Body: wire and decoded budgets independently 256 KiB, with one sentinel byte
  for overflow detection. Only identity or a single gzip coding; multiple
  Content-Encoding lines/chains/unknown encodings, truncated reads, corrupt
  gzip/checksum failure and oversized output abstain. No partial body votes.
- Empty response, unknown template, unexpected URL and HTTP errors other than
  the observable denial statuses 403/429 abstain. Network identity is not proof
  of the provider, even with TLS. Fixed targets prevent a new caller URL/Host
  SSRF surface. No bypass, CAPTCHA solving, account operation or evasion.

## Reuse and verification

Read existing unlock.captcha, responseIssue and their evidence/HTTP fixtures:
captcha is an availability check, while responseIssue deliberately rejects
challenges. Litmus reuses their Getter/Response contract; neither existing
function nor its abstention rules change. A separate tightly bounded live getter
is necessary because unlock's client contract permits broader redirects and
does not independently cap header/wire input.

Regression was actually run before implementation:
go test ./internal/cli -run '^TestLitmusOfflineContract$' -count=1 failed,
exit 1: CLI returned 2 (unknown litmus), expected offline observation exit 10.
After implementation the same contract passes.
Fixture checks cover positives, ordinary negative observations (still abstain),
unknowns, contradiction with retained markers, misleading text, injected errors,
limits, compression chains/bombs/truncation, local redirects/timeouts, and
self-signed TLS rejection. No public endpoint is contacted in tests.
