# Residential classifier offline evaluation (v1)

## Scope and claims

`cmd/ipd-eval` calls the actual `score.ClassifyResidential` on frozen feature
vectors. It does **not** call `ClassifyObserved`, the evidence gate, profile
extraction, providers, lookups, probes, or any network service. It does not fit a
model, execute dataset content, or change classifier predictions. This is not an
end-to-end IP classification benchmark.

The existing `internal/score/eval_test.go` repeats synthetic vectors, and
`heldout_test.go` exercises a different, observed-profile path. Neither is imported
or relabeled here as a measured population evaluation. The new four-row fixture
checks evaluator accounting (including an intentional counterfactual error and
withheld evidence), not classifier quality or a representative population.

**No measured public population accuracy is available from this work.** A public
citation is provenance, not evidence of representativeness or independent labels.
Synthetic or mixed reports must not be advertised as measured public accuracy.

## Reproduce locally, offline

From the repository root, with the Go toolchain/dependencies already cached:

```sh
GOPROXY=off GOSUMDB=off go build -o /tmp/ipd-eval ./cmd/ipd-eval
/tmp/ipd-eval -dataset internal/evaluation/testdata/synthetic-v1.json -split test > /tmp/residential-report.json
cmp /tmp/residential-report.json internal/evaluation/testdata/synthetic-v1.report.json
go test ./internal/evaluation ./cmd/ipd-eval
go test -race ./internal/evaluation ./cmd/ipd-eval
```

Only local files are opened. Input is at most 4 MiB, JSON depth at most 16, and
1–10,000 records; no URLs, plugins, dynamic expressions, or downloads are resolved.
CLI exit codes: 0 success/help, 2 argument errors, 1 dataset/evaluation/I/O errors.
Reports go to stdout, diagnostics to stderr; validation finishes before report
output. Store reports outside the dataset path (shell redirection can truncate an
input file). The CLI deliberately has no fetching or output-overwrite option.

## Versioned dataset schema

The executable contract is exported `evaluation.Dataset`, `Load`, and `Validate`
in `internal/evaluation/evaluation.go`. JSON must use exactly these fields; unknown
fields, duplicate object keys, nulls, trailing documents, and invalid types fail.
See `internal/evaluation/testdata/synthetic-v1.json` for a complete valid instance.
Breaking schema/feature/label changes require a new schema version.

| Level | Required fields and constraints |
| --- | --- |
| Dataset | `schema_version`: exactly `residential-evaluation/v1`; `id`, `revision`: identifiers; `group_rationale`, `split_rationale`: nonblank descriptions; `rows`: nonempty array |
| Row | `id`: unique identifier; `group`: grouping identifier; `split`: `train`, `validation`, or `test`; `label`: one of the six classes below; `provenance`: object below; `features`: object (empty allowed) |
| Provenance | `kind`: `synthetic` or `public`; `reference`: nonblank authorship/source citation; `label_method`: nonblank independent label derivation and limitations |

Identifiers match `[a-zA-Z0-9][a-zA-Z0-9_-]{0,79}`; descriptive strings are at most
2048 bytes. Ground-truth labels are `residential_fixed`, `residential_mobile`,
`isp_static`, `business`, `hosting`, `cdn_anycast`. `abstain` is a prediction,
**never ground truth**. Unknown truth must be adjudicated or excluded with the
exclusion count disclosed, not coerced to an abstention label.

Feature values are finite numbers. All are binary 0/1 except `eyeball`, which is
normalized to [0,1]. Missing features mean zero, matching the actual classifier.
Allowed feature names (no arbitrary metadata or address fields):

```
cloud_hit as_cdn anycast tor as_mobile announcer_hosting upstream_hosting
rtt_colo rdns_missing as_hosting as_cable as_dsl as_isp keyword_broadband
rdns_dynamic as_business keyword_idc geo_disagree vpn eyeball
```

Provenance and rationales are human-audited assertions; software cannot establish
truth, licensing, privacy, or independent annotation from a string. Never include
user/customer records, real user/server IPs, credentials, or private sources in
these artifacts. This task adds only invented synthetic feature records, with no
scraping or downloads. Public provenance support is a format capability, not a
claim that a public dataset was collected or validated.

## Deduplication and split policy

Every row has an explicit group. Related observations (same source endpoint,
prefix, ASN, capture campaign, or another relevant dependency) must receive the
same group; choose the appropriate conservative unit and justify it. Groups may
repeat **within** a split, never across splits. Validation checks the entire file
before split selection, so hidden train/test group leakage fails too.

Identical feature vectors are rejected across the entire dataset, even within a
split and after removing explicit zeroes. This conservative policy prevents
repeated synthetic vectors inflating counts, but also excludes natural feature
collisions; disclose that selection bias in any public study. It is not a method
for estimating traffic-weighted population accuracy. Related but nonidentical
vectors cannot be detected automatically: truthful grouping is still required.

All example rows are test-only, unique authored scenarios; no train/held-out
independence is claimed. Evaluation defaults to `-split test`; selecting a split
with no records fails. Do not tune thresholds on test rows. Changes to dataset
content, provenance, or rationale require a new `revision`.

## Metric definitions

Confusion matrix rows are true labels (six classes); columns are predicted
labels (six classes plus `abstain`), including zero cells. Every selected record
has equal weight and contributes to exactly one cell. Abstention is counted from
the actual classifier's `Abstained` flag or its `abstain` output class.

- Class support: row sum, **including abstentions**.
- Class predicted count: column sum.
- Class precision: diagonal / predicted count.
- Class recall: diagonal / support; abstention on a labeled class is a miss.
- Coverage: decided / all selected records.
- Abstention rate: abstained / all selected records (= 1 − coverage).
- Accuracy including abstentions as errors: correct / all selected records.
- Accuracy on decided (selective accuracy): correct / decided. This is not
  per-class precision and must always be accompanied by coverage.

Every ratio exposes numerator, denominator and value; denominator zero produces
JSON `null`, not zero, NaN, Infinity or an apparent perfect score. No macro score
is emitted that could silently ignore unsupported classes. Provenance counts
refer to selected rows; mixed provenance is not separated into population metrics.

Report ordering and output are deterministic: no timestamps or random splits;
row predictions retain input order. The SHA-256 is over Go `encoding/json` of the
validated Dataset (sorted map keys, struct field order), not original file bytes;
whitespace differences do not matter, row order and explicit zero entries do.
`model_version` identifies the bundled classifier; also record the exact git SHA
and toolchain externally to reproduce future code changes under the same version.
The report intentionally omits top-feature ordering (ties in the classifier may
be unordered); it records actual class and confidence, without interpreting
confidence as calibrated probability.

## Checked-in synthetic example

`internal/evaluation/testdata/synthetic-v1.report.json` is actual CLI output for
the adjacent fixture: 4 synthetic records, 3 decisions, 1 abstention, 2 correct;
coverage 3/4, abstention 1/4, accuracy 2/4, selective accuracy 2/3. Hosting support
is 2, precision 1/1 and recall 1/2. Unsupported class metrics are null as defined
above. **These numbers are regression/accounting results, not public accuracy.**
Tests compare the example byte-for-byte and independently check counts and real
classifier predictions.

## Public report template (unfilled; not measured results)

Copy this section for a future approved evaluation. Replace every placeholder
with audited evidence; do not fill in synthetic results as public results.

- Study/status: **NOT MEASURED** / `<scope and actual status>`
- Target population and intended use: `<definition; no generalization beyond it>`
- Dataset ID/revision/schema/hash: `<from validated report>`
- Code git SHA / model version / Go version: `<record exact versions>`
- Reproduction command and report artifact: `<local command and immutable path>`
- Provenance: `<public/synthetic counts; source citations, licenses, collection
  dates and permitted uses; no identifying addresses or private data>`
- Label method: `<independent evidence, annotators/adjudication, uncertainty,
  missing labels, exclusions and disagreements; never classifier output as truth>`
- Sampling frame: `<selection process, dates, geography, class balance,
  dependency units, deduplication and resulting bias>`
- Group/split rationale: `<units, counts per split/class; prior tuning and leakage audit>`
- Full confusion matrix: `<six true labels × seven prediction columns>`
- Per-class support, predicted count, precision and recall: `<counts, ratios,
  null where undefined>`
- Coverage, abstention, all-row and selective accuracy: `<counts and denominators>`
- Uncertainty: `<interval method respecting dependent groups, or explicitly not
  estimated; this evaluator emits no confidence intervals>`
- Limitations: `<representativeness, label noise, time drift, unsupported classes,
  synthetic/mixed rows, feature-only scope, no calibrated confidence claim>`
- Independent review and publication approval: **PENDING** / `<review evidence>`

### 输入键完整性修正

独立审查发现 Go 的 Unicode 字段折叠会把长 s（ſ）视为 ASCII s。
Load 的 token 扫描现在只接受 ASCII 小写 schema 键（字母起始、随后字母/数字/下划线），
再执行精确重复/未知字段检查；值中的正常 Unicode 不受影响。
新增 literal/escaped 别名、重复 split/features/rows 回归在旧16341f4实际失败，修正后通过；
真实CLI对合成unicode-features反例返回非零且不产出成功报告。日志见 /tmp/ipd-batch-root-checks/pr34-*。
