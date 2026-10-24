# Ordinary feed last-good snapshots

## Scope and format

Ordinary `updater.apply` feeds now write `feeds/<id>.feed.json`: one version-1
JSON envelope containing source metadata and every `lookup.Rec` field. This is
an ingest-private format, not a new lookup API. Existing TSV and metadata files
are read-compatible and are never rewritten or deleted by this path.

The packed IPDS v1 format was not reused for ordinary feeds: its payload omits
GeofeedCC, GeofeedChanged, Eyeball, RTTRegion and ChangedAt, cleans text, stores
ASN as uint32, and its duplicate sorting does not promise input-order winners.
JSON preserves these fields, integer values, tabs/newlines, flag boundaries and
row order. Invalid UTF-8 is rejected rather than silently replaced; non-JSON
values such as NaN/Infinity fail encoding before publication. On read, the original
serialized bytes are checked for valid UTF-8 and paired UTF-16 surrogate escapes
before JSON decoding can replace damaged text. Literal U+FFFD, escaped U+FFFD and
valid surrogate pairs remain valid data. A rejected selected file does not publish
that source; this is not a checksum against arbitrary valid-JSON modifications.
Ordinary snapshots are loaded into the existing in-memory table, not mmap.

Before writing, apply checks matching source IDs, skips invalid prefixes, masks
valid prefixes, sets row Source to the metadata ID, and rejects an empty accepted
set. It sets Enabled=true, Rows to the number of accepted rows (including
duplicates, matching MergeSource). UpdatedAt is preserved, including zero for an
unknown acquisition time; neither preparation nor reload supplies the current
time. Built-in successful feed producers supply their acquisition time themselves.
Known source timestamps are preserved, not replaced with reload time.

The standalone PR1-baseline lookup.MergeSource still fills zero UpdatedAt with
now in its live table. This PR deliberately does not import a lookup fix: its
serialized and parsed source timestamps stay zero, while standalone live/reloaded
engine metadata can still become nonzero and differ. With separate PR8 `c9fcb30`,
both live and reloaded engine timestamps remain unknown. The tagged integration
test verifies known -> unknown -> known refreshes, including the BGP freshness
clock; the ordinary suite does not claim to fix the legacy engine behavior.
Duplicate normalized prefixes keep the last input record, in memory and after
restart. Tests exercise all current Rec fields, duplicate IPv4 prefixes and IPv6.

## Commit and failure boundary

The sequence is: prepare rows and metadata; create a unique same-directory temp;
encode; file Sync; Close; rename to the final JSON name; then MergeSource.
Rename is the **single on-disk visibility commit**, not a two-file transaction.
The prior snapshot is not opened for writing. Create, encode/write, Sync, Close,
and rename errors return an error and zero published rows, do not publish memory,
and do not log success. Cleanup removes only the unique temp created by this
call on failure, never a shared `.tmp` name or another writer's file.

After rename, MergeSource has no ordinary error path for the already validated,
nonempty rows. There is no fallible file operation after that commit. Disk and
memory publication are sequential, not simultaneously atomic: a process crash
between rename and MergeSource can leave the running process unrefreshed until
restart; Load then reads the complete committed file.

## Read precedence and writer ownership

For matching source filenames, Load chooses **IPDS > versioned JSON > legacy
TSV**. IPDS wins regardless of file mtime or metadata UpdatedAt: formats are not
merged, and an old JSON/TSV cannot mask a later streamRows IPDS refresh. Invalid
selected JSON returns an error instead of silently accepting an older TSV;
a skipped lower-priority JSON is not parsed. New snapshots require version 1,
matching source ID, nonempty valid rows and consistent metadata.

The current successful ordinary writers are cloud_ranges, tor_exits, firehol,
ipsum, spamhaus_drop, x4bnet, rir_delegated and ipinfo_lite. Successful streamRows
writers are dbip_lite and bgp. Their apply calls are only download-error reporting
and do not write. Thus successful writer IDs do not currently overlap.
Ordinary apply rejects an existing same-source `<id>.ipds` path rather than
claiming an update which would be hidden on reload (or by a mapped engine table).
It does not delete that path to force migration.

## Explicit limitations

This fixes only ordinary apply persistence. streamRows/IPDS, MMDB replacement,
and all-feed Load/Update are **not** made transactional by this change. There is
no directory fsync/power-loss durability guarantee, cross-process CAS, concurrent
same-source writer ordering, or atomic disk-plus-memory transaction. No crash or
multiwriter stress test was performed. External code must not install a mapped
version of an ordinary source into the supplied engine or remove/replace source
formats behind that engine while updates are running. Supporting that ownership
transfer would require a separate lookup API decision. Strict read validation
buffers the complete serialized JSON in addition to decoded rows; no snapshot
byte/row cap or production-scale RSS/OOM guarantee is introduced here.

## Verification

On baseline `19a0b16962a8d249179ce376db3847ba594c3fb4`, an actual probe saved
192.0.2.0/24 with Org `old fixture`, replaced its `.meta.json` with a directory,
then applied `new fixture`. The update returned an error but changed the TSV and
live record and logged success. The probe was run, not inferred. Fixed-path tests
cover the original metadata-directory scenario, failed temp creation/write/Sync/
Close/rename, a real rename collision with an unowned directory, retained last-good
bytes and source timestamps, reload consistency, unrelated sources, empty/invalid
inputs, all Rec fields, duplicate order, and all three format priorities.

Run focused checks without downloading dependencies:

```
GOPROXY=off GOTOOLCHAIN=local go test ./internal/ingest -run 'TestApplySnapshot|TestLoadFeed|TestLoadRejects|TestUpdater|TestLoadSnapshot' -count=1
GOPROXY=off GOTOOLCHAIN=local go test -race ./internal/ingest -run 'TestApplySnapshot|TestLoadFeed|TestLoadRejects|TestUpdater|TestLoadSnapshot' -count=1
```

Full-suite evidence is reported separately: this baseline has known macOS-only
Linux MSS and `/proc/self/maps` test failures. Live external checks must be blocked
or skipped to obey the no-public-network requirement; these are not evidence of
real provider availability. No real feed downloads, credentials or deployment
are part of this verification.

### R1 follow-up verification

New tests were run against `eadbdfa` before fixing the two P2 findings: unknown
timestamps were fabricated (and existing zero-time files rejected), and damaged
UTF-8 / unpaired surrogate text was accepted and published. With the isolated
PR8 lookup changes, the unknown-time counterexample also failed in live/reloaded
metadata and the BGP clock. These were actual failing runs, not inferred results.

`TestApplySnapshotPreservesSourceTime` and `TestLoadSnapshotUnknownTime` check
serialized/parsed zero times and known-time preservation on the standalone branch.
`TestLoadSnapshotStrictUnicode` checks rejection without source publication,
unchanged input bytes/unrelated source, and valid U+FFFD/surrogate-pair controls.
With **only the separately applied PR8 lookup changes** present, run:

```
GOPROXY=off GOTOOLCHAIN=local go test -tags pr8_integration ./internal/ingest -run '^TestApplySnapshotPR8SourceTimes$' -count=1 -v
```

The `pr8_integration` tag selects only an integration test, never production code.
Its required lookup semantics are not present in the standalone baseline and are
not included in this PR. Temporary PR2 platform-test and PR8 lookup patches used
for full-suite/race verification must be reversed before committing. Evidence and
remaining independent-review status belong in the PR report, not an acceptance
claim based solely on these tests.
