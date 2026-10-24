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
