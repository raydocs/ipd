# Raw IPv4 traceroute probe correlation

## Scope and success criterion

This follow-up starts at `19a0b16962a8d249179ce376db3847ba594c3fb4`.
It changes only raw ICMP/TCP probe generation and reception, their portable wire
parser/receive-loop fixtures, and this document. It does not change classification,
app behavior, the UDP extended-error implementation, or enable new network probes.
A packet must identify the currently outstanding probe before it can add a hop;
only a correlated destination EchoReply completes an ICMP trace.

## Receive contract

- Every ICMP probe has fresh random ID/sequence (32 bits combined) and a fresh
  16-byte payload token. EchoReply requires destination source address, code zero,
  exact ID/sequence and the entire token. Bad ICMP checksums are ignored.
- TimeExceeded accepts only code zero (TTL exceeded in transit). Destination
  Unreachable accepts known codes as errors, not successful completion. Both must
  quote an IPv4 packet with valid variable IHL, a plausible original packet length,
  no fragmentation, the expected protocol and the exact destination.
- An ICMP quotation must identify an Echo request with code zero and the current
  ID/sequence. An RFC-minimum quotation has only eight transport bytes: token bytes
  cannot be demanded when absent, but every token byte actually quoted must match.
  Declared original length must fit the sent request; malformed or insufficient
  quotations are ignored, not attributed to the outer sender by guesswork.
- Every TCP probe uses a fresh random sequence. A TCP quotation must match source
  port, destination port, sequence and destination, and declare the sent 20-byte
  segment. EchoReply is never evidence for TCP. Even destination-sourced TCP
  unreachable is a retained hop **and error**, never proof that port 443 is open.
  Direct SYN-ACK/RST interpretation is not added; TCP can therefore remain partial.
- Noise, malformed packets and late probe identities are ignored until one fixed
  450 ms receive deadline. Reads are bounded to 25 ms (raw poll rounds to ms), also
  capped by the context deadline. Noise, interrupted reads and temporary timeouts
  do not restart the budget. Cancellation and non-timeout socket errors propagate;
  a correlated unreachable retains its hop and error. Hop-limit exhaustion is an
  error rather than completion. No worker goroutine can outlive the socket/probe.

ICMP is not authenticated. These checks reject unrelated traffic and blind guesses,
not an on-path observer capable of copying current identifiers. Minimum quotations
have only the 32-bit Echo ID/sequence or the TCP ports/sequence, not a full token;
identity collisions remain theoretically possible. This is correlation evidence,
not a claim of cryptographic authenticity or real-network certification.

## Deterministic regression evidence

The baseline's receive-decision bodies were copied verbatim from `icmpTrace` and
`readRawICMP` into temporary host-runnable test adapters (only raw socket I/O was
replaced by fixture inputs). The actual command
`go test ./internal/route -run '^TestBaselineExact' -count=1` exited 1:

- `TestBaselineExactRawDecisionRejectsUnrelatedEcho`: an unrelated EchoReply was
  accepted as hop `192.0.2.10`, `done=true`, `err=nil` for a TCP probe.
- `TestBaselineExactEchoDecisionRejectsLateProbe`: an EchoReply with the preceding
  sequence was accepted as hop `192.0.2.10`, `err=nil`.

The temporary legacy adapters were removed, not shipped. The permanent pure
parser tests exercise those packets and additional wrong protocol/destination,
ID/sequence/ports/token/code/checksum, truncated inner/outer packets, variable IHL,
fragments, correct Echo and minimum/partial/full quoted TimeExceeded, and router/
destination unreachable. They use documentation-only addresses and no raw sockets.
Fake-clock reader tests cover a full 450 ms of unrelated packets, late quotes
followed by a valid reply/error, interrupted/timeout reads, cancellation, context
budget capping and terminal socket errors. The deterministic subset passes with
`-count=1`, including under `-race`.

## Verification and limits

- `go test ./...`: the unmodified Darwin baseline fails only
  `internal/listen.TestServeTLSHandshakeAndH2` (`mss 0`) and
  `internal/lookup.TestSnapshotUncappedMapLoad` (missing `/proc/self/maps`).
- With the explicitly allowed PR2 portability-only patch `0511d997` temporarily
  applied, `go test ./...` passes. That patch was reversed and is not in this PR.
- `node --test web/judge.test.mjs` and `git diff --check` pass.
- `go test -race ./internal/route -run
  'TestProbeReply|TestRawProbeReply|TestAwaitProbeReply' -count=1` passes.
- `GOOS=linux GOARCH=amd64 go test -c ./internal/route` cross-compiles. The Linux
  runtime, raw sockets and actual network behavior were **not executed**.

## Integrating with PR5 (`2eda873762a7fe9dac5d1cfddfd891e0b54e2f1a`)

The combination was built in an isolated source copy, not another owner's worktree.
The combined full Go suite passes with temporary PR2 portability support, as do
Node tests, the correlation race subset and Linux/amd64 route cross-compilation.
PR5's `platformTrace`, UDP, error-retention and destination-completion changes are
retained; none of PR5's other files are included in this branch.

Applying this branch's trace patch after PR5 rejects three hunks: imports, the
ICMP receive block, and TCP generation/reception plus `synPacket`. Resolve exactly:

1. Keep PR5's `trace_linux.go` section from `func platformTrace` through the end of
   `recvErr` verbatim (everything preceding `func icmpTrace`, except imports).
   This preserves its UDP parser, timeout/error and partial-hop handling.
2. Keep PR5's `errors` import once, add `crypto/rand`, remove `os`; retain the other
   imports. Take this branch's complete section from `func icmpTrace` through EOF.
   It already preserves PR5's `return hops, err` on writes and both raw-method
   hop-limit errors, and replaces the unsafe raw completion decisions.
3. Add this branch's `probe_reply.go`, `probe_reply_test.go` and this document.
   Leave PR5's `udp_error*`, classification, app and other files unchanged.
4. Re-run the checks above in the integration branch. Parent-thread independent
   review remains required; this implementation report is not final approval.
