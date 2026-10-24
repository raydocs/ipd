# CLI language

The CLI defaults to Chinese (`zh`). English is an explicit, invocation-local
presentation option; it does not change the app, HTTP API, MCP protocol, model,
probe budget, machine verdicts or exit codes.

```sh
ipd --lang en help
ipd help --lang=en
ipd --offline 192.0.2.10 --lang en
printf 'local report\n' | ipd report --lang=en --json
IPD_LANG=en ipd help
IPD_LANG=en ipd help --lang=zh
```

## Selection and compatibility

- Priority: explicit `--lang en|zh` / `--lang=en|zh`, then nonempty `IPD_LANG`,
  then `zh`. No implicit system-locale detection.
- Global flags work before, between, or after command arguments. Other global
  flags retain their existing behavior. Repeated valid language flags use the
  last value. Every explicit invalid value is an error, even if followed by a
  valid flag. Empty/missing values and unsupported/case-mismatched values fail
  before command execution, with exit code `2` and an explicit English error.
- An explicit valid flag overrides even an invalid environment value; otherwise
  invalid `IPD_LANG` also fails with exit code `2`.
- Without English selection, existing report rendering is unchanged. Chinese
  help gains the language option. English help only advertises commands present
  in this branch; `latency` belongs to the separate PR9 implementation.
- `VERDICT:` / `# VERDICT:`, verdict strings, JSON field names, enums and existing
  command exit codes are unchanged (`0`, `10`, `20`; invocation errors `2`).

## What English covers

English covers help, CLI-owned usage/unknown-command errors, label/deletion/local
report messages, ingest success, agent configuration instructions, serve startup,
and the CLI-owned data-update/snapshot status wrappers. The option also applies
to core results, not just help: egress/IP risk, combined check, AI, unlocking, DNS
leaks, routes, firewall/mail reachability, nodes, batches, watches and reports.

The text first line remains `VERDICT: <unchanged enum> — <English overview>`.
Markdown keeps its machine verdict heading and an English overview immediately
below it; JSON keeps `summary_md` and uses the same overview. Overview details
include structured purity scores and result/observation/fix counts when present.
These counts describe observations, **not** proof of success or availability;
read the unchanged verdict and evidence for uncertainty and the actual diagnosis.

## Evidence boundary (intentional untranslated content)

This is **not** a promise that every byte of output is English:

- `data` is preserved, with its original shape and values, including nested AI
  fixes, errors, routes, returned SVG, report bodies, node names and raw evidence.
- `sources` (including `raw`), attribution, licensing, IP addresses, enums and
  external/app/provider errors are preserved. Updater progress and feed notes
  are upstream text; English labels progress as `Data update (original progress):`
  but never rewrites it. Chinese can therefore still appear in evidence.
- English overviews are controlled command-specific descriptions based on
  structured fields, **not** guessed translations of arbitrary original summaries.
  They point to `data` and `--json` for the complete evidence.
- English CLI reports add **`original_summary_md`** alongside existing JSON
  fields. It retains the original returned summary exactly, including multiline
  source text or an external error. Text appends the same JSON-encoded string;
  Markdown appends an `original_summary_md` JSON block. CLI-owned summaries are
  already localized before this preservation step. Chinese reports gain no field.
- Existing text rendering truncates large data values and only lists source IDs;
  Markdown includes full data but not source `raw`. Use **`--json`** for full data,
  full source records and the preserved summary. No evidence is discarded from
  that JSON envelope, and there is no replacement pass over serialized JSON.

Only explicitly marked CLI templates enter the locale catalog. User arguments
are interpolated afterwards, so even arguments/errors that happen to match a
Chinese template remain unchanged. There is no mutable process-global locale.
For `serve`, only its CLI process messages change; HTTP/MCP responses and
background evidence do not acquire an English API contract.

## Combining with AI PR7 and latency PR9

PR7 `a4cfde6` changes the app's AI diagnosis without changing the CLI. The English
renderer uses a read-only JSON projection for typed and remote data alike; it
preserves the new tri-state evidence, priority, fixes and original summary. No
PR7 implementation is included here.

PR9 `67e87d4cf794ea31a3079e7a397970c3dbc2aa07` (including `74f79a8`) separately adds the latency command and local SVG persistence.
Do not copy its implementation into this language PR. When combining the two
CLI changes, retain both Main/dispatch additions and apply this small integration:

1. Change PR9's help print to
   `fmt.Fprint(os.Stdout, opts.lang.text(latencyHelp))`.
2. Add this line to `englishHelp` (only in the combined branch):
   `  ipd latency <target> [--svg <local-file>]  Local latency card (no overwrite or upload)`.
3. At PR9's CLI-owned error creation sites, use `cliError` instead of `fmt.Errorf`
   for duplicate/missing `--svg`, unknown latency arguments, missing SVG and
   `保存 SVG: %w`, and the new `incomplete` wrapper
   `保存 SVG: %w; empty/partial export may remain (no path cleanup attempted)`.
   The locale catalog registers all these exact templates; `%w` still unwraps
   to the untouched original cause. Nested CLI-owned missing-SVG errors are
   localized for display, while external `svc.Latency`/filesystem causes stay
   original. Keep the empty/partial-export warning in both languages.
4. For PR9's usage-only errors, use
   `cliError("%s", messageText(latencyHelp))`. For its unknown-argument error use
   `cliError("未知 latency 参数 %s\n%s", a, messageText(latencyHelp))`.
   `messageText` explicitly marks only the trusted nested help template; it
   never marks the user argument or an external error.
5. Keep Main's `renderLocalized` call. `latency` already has an English overview
   here; its full original `data.svg`, row evidence and returned verdict remain
   intact. Saving an SVG must still write PR9's original SVG bytes, not a
   translated or regenerated card. This layer does not translate SVG content.

If PR9 changes a CLI message template later, register that exact owned template
rather than broadly replacing Chinese in error/evidence bodies. Test English
latency help and each CLI error in the combined branch as well as the existing
PR9 no-overwrite, permissions, probe-budget and exit-code tests. Keep PR9's latest security corrections verbatim: do not restore `saved` or
`os.Remove(path)` cleanup, and do not reintroduce raw provider errors into the
card. The new `incomplete` warning must survive locale integration. The combined
validation uses latest PR9, including its replaced-path/failed-write tests, not
only its original implementation commit.

PR10 `9035290` independently makes unavailable node measurements abstain. The
English node overview reports counts and explicit measurement status; it does not guess that an
unmeasured node is unreachable or available. Preserve the returned verdict,
status/reason fields and exit code. Combination validation includes PR10 too.

## Verification

The narrow regression is `TestEnglishCoreRegression`: on the unchanged base,
`report --lang=en` returned a Chinese first-line summary (actually run and failed).
The locale tests cover flag placement/precedence/invalid values, core command
results, all report formats, exact default rendering, unchanged verdict/exit
codes, unmodified nested data/sources, retained original summaries and external
errors that deliberately equal owned templates. They use local/documentation
addresses and offline/in-process inputs, not real-service credentials or probes.

Required standalone and PR7+latest-PR9+PR10 combination checks:

```sh
go test ./internal/cli -count=1
go test ./...
node --test web/judge.test.mjs
```

On macOS the base suite has Linux MSS/procfs assumptions. The independently
supplied PR2 `0511d997` test-portability patch may be applied temporarily for both
full-suite runs and then removed; it is not part of this PR. Combination-only
PR7/PR9/PR10 code and the integration edits above must also be removed before commit.
