# Explicit CLI node egress measurement (round 8)

## Acceptance contract

Only an explicit `nodes --measure` invocation may launch trusted external cores.
The default Nodes, HTTP and MCP paths remain unchanged and abstain. Accepted input
is bounded local regular-file or inline native Clash YAML / sing-box JSON, subject
to PR23's unchanged allowlists. The batch preserves input sequence and exposes
only 1-based original index, backend, observed public egress IP or unknown status
and controlled reason. No purity, unlock, reachability grade or credential-bearing
configuration is exported.

Verification must exercise both backend helper subprocesses through the real
runner, authenticated loopback proxies and verified HTTPS, without a real airport,
public measurement request or downloaded core. Failure/cancellation/core revocation
must withhold the entire batch and reap processes; no environment proxy or direct
fallback. Regression must actually fail before implementation. Narrow/race/full Go
and web judge checks, plus isolated PR22 composition, are required evidence.

Dependency: PR23 at `8331260018a4b34cc4874e0ea0ba30271a52a24f` (not merged).
This branch merges that accepted candidate and ordinary `origin/main`; PR base is
`main`. PR22 `a25cced46742fc1137212a8e174b7cdb8c6b4b21` remains separate: do not
copy or overwrite its locale/latency changes. This PR's own increment is app/CLI
measurement wiring, tests and this document only. Parent PR21 and closed PR12 are
not modified. Draft only: no merge, main push, force push or deployment.
