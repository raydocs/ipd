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
values such as NaN/Infinity fail encoding before publication.
Ordinary snapshots are loaded into the existing in-memory table, not mmap.

Before writing, apply checks matching source IDs, skips invalid prefixes, masks
valid prefixes, sets row Source to the metadata ID, and rejects an empty accepted
set. It sets Enabled=true, Rows to the number of accepted rows (including
duplicates, matching MergeSource), and sets UpdatedAt only when it was zero.
Existing source timestamps are preserved, not replaced with reload time.
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
transfer would require a separate lookup API decision.

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
