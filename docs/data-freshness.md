# Prefix data freshness and replacement

`lookup.Engine` publishes a replacement's prefix data, `SourceMeta`, and prefix
clock in one write-locked critical section. A source has exactly one live
backing index: either an in-memory table or a mapped snapshot, never both.

- `MergeSource` replaces just that source, removing and retiring its old mapping.
- `InstallSnapshot` validates/maps the new file before taking the lock, then
  replaces that source's table, metadata, and source time together.
- `Reload` replaces the entire prefix index, including removing mapped sources
  absent from the replacement and discarding their old clocks. An attached MMDB
  is retained; it is not part of the prefix snapshot clock.
- Empty/all-invalid row replacements and failed snapshot opens/validation retain
  the last good data **and** metadata/clock. Partial row input still skips invalid
  prefixes, as before. Reload is not an API for intentionally clearing all data.

Every engine query holds the read lock while accessing mapped bytes. Retirement
holds the write lock through unmapping/closing, after existing readers finish.
Records decoded from the map own their payload strings and remain valid after
retirement. Callers using `OpenSnapshot` directly own its lifetime and must finish
reads before calling `Close`; it is not an independently synchronized handle.

## Meaning of the clock

`SnapshotAge(now)` uses source-supplied `UpdatedAt`, not local install/reload time:

1. Among **loaded, nonempty** `bgp` and `dbip_lite` sources, the oldest source time
   wins. A source's timestamp is replaced, not monotonically maximized: installing
   older authoritative data must make the clock older too.
2. If neither primary source is loaded, use the oldest time among all queryable
   prefix sources. Metadata-only placeholders and MMDB open time do not count.
3. If any source in the selected clock set lacks a timestamp (including missing
   metadata), return zero `time.Time` and age `0`. This means **unknown**, not
   newly built or fresh. A known timestamp on another source must not hide it.
4. Otherwise age is nonnegative whole seconds since that timestamp; future source
   times produce age `0` without changing the source timestamp.

Unknown `UpdatedAt` stays zero in memory and snapshot metadata. Neither merge nor
snapshot building invents a timestamp with the current time. `Sources(now)` marks
known enabled sources stale only when age exceeds twice their declared cadence
(hour/day/week/month; a month is 31 days). `Stale == false` on an unknown timestamp
is not proof of freshness; inspect `UpdatedAt` as well. An unknown cadence also
cannot establish staleness. A later successful replacement with a known time
restores a known clock normally.

Atomicity is per engine operation/publication. Separate calls to `Lookup`,
`Sources`, and `SnapshotAge` are **not** a multi-call read transaction: a
replacement may occur between calls. This change does not alter app/MCP/API/CLI
response assembly or cache semantics, and does not add a report-level generation
handle. Consumers needing that stronger guarantee require a separately scoped
read-transaction API.

## Local verification

The deterministic fixture tests use fixed source times and local files only:

```sh
go test ./internal/lookup -run 'Test(Replacement|Freshness)' -count=1
go test -race ./internal/lookup -run 'Test(Replacement|Freshness)' -count=10
go test ./...
node --test web/judge.test.mjs
```

Replacement tests cover memory → mapped → memory, mapped → reload, removal of
mapped sources, failure retention, reader-pinned retirement, and simultaneous
lookup plus all three same-source writers. Freshness tests cover clock advancement,
oldest-source selection, staleness boundaries, future times, missing timestamps,
and restoration of a known clock. Tests do not download feeds.
