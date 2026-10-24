# Direct-node YAML representation validation (round 7)

## Scope and success criterion

Base: `773ea38e827674e736c5032ebe71f6b20e37e5d8` (PR17,
`t3/direct-node-measurement-r6`). Only the direct-node parser and its tests
change; shared `nodes.Parse`, CLI, transport, field allowlist, opt-in/offline,
environment-proxy isolation, TLS verification and unknown-result policy do not.

Success means the original YAML representation is validated **before** decoding
any mapping. An ambiguous document rejects the whole batch with the fixed
`invalid local node configuration; no requests sent` error. Valid items before
or after a bad item must not open even a proxy TCP connection. Errors/reports
must not expose YAML, names, credentials, keys, or parser diagnostics.

## Conservative policy

- Decode exactly one `yaml.Node` document; validate it, require EOF, and only
  then convert it to the existing Go map/schema. No alias expansion or merge
  application is allowed before validation.
- Every mapping, including the root and maps nested inside unsupported fields
  or sequences, requires scalar `!!str` keys. Reject alias, sequence, mapping,
  boolean, numeric and null keys. Compare the parser's unquoted/unescaped key
  values: quoting, escape spelling and explicit standard string tags cannot
  distinguish duplicate Go string keys. This does not introduce case folding
  or Unicode normalization that Go/YAML string-map decoding does not perform.
- Reject **all aliases**, including otherwise harmless value aliases. Do not
  traverse alias targets; cyclic/self-referential aliases therefore fail without
  expansion. Unreferenced anchors remain allowed, including on scalar keys.
- Reserve/reject `<<` keys even when quoted or explicitly tagged as strings;
  reject YAML merge-tag keys and merges using inline maps or aliases.
- Require standard `!!map` / `!!seq` container tags. Scalar values may use only
  standard string, boolean, integer, float or null tags, with the existing
  field-type checks still applied after conversion. Reject custom tags,
  timestamp and binary tags anywhere, including unsupported metadata.
- Well-formed unknown fields retain the existing unsupported policy; malformed
  structure anywhere is instead a whole-document error. This intentionally
  refuses some valid general-purpose YAML/Clash configurations, rather than
  guessing at inheritance, tags or future configuration semantics.

## Executed old-code counterexample

Added `TestDirectNodesYAMLStructureRejectsBeforeNetwork` and
`TestDirectNodesYAMLUnambiguousStringsKeepPositions` before changing production
code. Actually ran `go test ./internal/app -run 'TestDirectNodesYAML' -count=1`
on the base implementation; it failed behaviorally (not at compilation):

- A middle node with `&k tls: fixture-secret-invalid, *k: false` bypassed the
  original field validation: TCP=3, CONNECT=3, HTTPS endpoint=3, verdict=ok.
- Root `&p proxies: [null]` followed by `*p:` and a valid list overwrote the
  malformed list: TCP=1, CONNECT=1, HTTPS endpoint=1, verdict=ok.
- First/last bad-node placement, custom tags, merges, nested alias/non-string
  keys, and value aliases also demonstrated acceptance and/or network traffic.

The tests use authenticated loopback CONNECT and a trusted loopback TLS
endpoint returning documentation IPs only. They count accepted proxy TCP
connections as well as CONNECT and HTTPS requests. Every rejection case
requires all three to be zero, and the fixed controlled error. Positive tests
retain unreferenced anchors/explicit string tags/escaped keys and original
indices in mixed supported/unsupported lists. Existing ordinary, auth-failure,
no-fallback, environment, TLS, offline and limit regressions are retained.

Raw local logs: `/tmp/ipd-r7-yaml-evidence/` (not committed).
Independent fresh review and parent-stack integration remain with the parent;
this implementation task does not merge, deploy or monitor CI.

## Validation results

- PASS: `go test ./internal/app -run '^TestDirectNodes' -count=1`.
- PASS: `go test -race ./internal/app -run '^TestDirectNodes' -count=1`.
- PASS: `node --test web/judge.test.mjs` (1 test).
- `go test ./... -count=1` on the unmodified Darwin base fails only the two
  known portability assertions: `TestServeTLSHandshakeAndH2` (`mss 0`) and
  `TestSnapshotUncappedMapLoad` (missing `/proc/self/maps`). The app package
  and the other packages pass.
- PASS: the same full Go command with PR2 `0511d997` applied **temporarily**.
  Reversed that patch immediately afterwards and verified no diff in the
  affected listen/lookup files and no leftover added platform test files.
  None of PR2 is committed here.
- PASS: `git diff --check`; no changes to `docs/ROADMAP-STATUS.md`.

No real proxies/public measurement endpoints, secrets, simulator/emulator,
merge, deployment, force push or CI watching were used. Real-service behavior
and stack integration are not verified by these loopback tests.
