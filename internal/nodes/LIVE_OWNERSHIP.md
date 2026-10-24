# Live ownership increment (draft)

Dependency: accepted PR23 runner candidate
`8331260018a4b34cc4874e0ea0ba30271a52a24f` (PR23 remains separate).
This branch starts from that exact candidate and synchronizes fetched `origin/main`;
the independent draft targets **main**, not PR23 or the parent summary branch.
Only `internal/nodes` and its contract/tests are in scope. No app/CLI/PR26 wiring.

Acceptance requires an opaque single-run handle with active per-endpoint/all-node
kernel ownership checks, prompt one-way batch revocation, a bounded background
monitor, cancellation/deadline propagation and reason-preserving cleanup. Real
local helper children must demonstrate the old live-PID/listener-loss defect and
exercise both backend production paths. Helpers are not real cores or airport
interoperability evidence. Linux runtime and independent review remain separate
acceptance gates. No merge or deployment is authorized by this draft.
