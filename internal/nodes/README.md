# Clash node renaming

`RenameYAML` changes top-level proxy names and exact node references in:

- `proxy-groups[].proxies` lists;
- policy targets in `rules` and each `sub-rules` list;
- `proxies[].dialer-proxy`, `proxy-providers.*.override.dialer-proxy`, and
  `proxy-providers.*.payload[].dialer-proxy` (inline provider proxies).

Nested groups and sub-rule labels keep their names and links. Credentials,
conditions, rule-provider names, trailing rule options, group settings and other
configuration stay intact. Neither the input `File` nor the supplied outcomes
are mutated.

Names are allocated in proxy order. Existing node names (even those being
renamed), outcome source names, group names, external targets in all supported
reference fields and built-in targets
(`DIRECT`, `REJECT`, `REJECT-DROP`, `PASS`, `COMPATIBLE`, `GLOBAL`) are reserved.
A collision receives the first available ` (2)`, ` (3)`, etc. suffix. The emitted
YAML contains the resolved names. On success, `Run` returns `Outcome.Renamed`
matching those actual names, including collision suffixes and unchanged nodes.

Missing or empty rename outcomes leave nodes unchanged. Outcomes for non-node
targets do not rename those targets. Reapplying the same outcomes to the same
input or to its renamed output is stable. A requested rename of a duplicate
source name, a source sharing a group name, or a built-in source name fails
without modifying the input: those references cannot be disambiguated safely.

## Rule syntax boundaries

Policy positions follow mihomo's [rule parser](https://github.com/MetaCubeX/mihomo/blob/Meta/rules/common/base.go):
the second field for `MATCH`, the last field for logical (`AND`/`OR`/`NOT`) and
regex rules, and the third field for the supported ordinary rule types listed
in `rewriteRule`. Commas within logical/regex conditions and trailing ordinary
rule options are preserved, as is whitespace around the target field.

Only an exact target match is rewritten. A `SUB-RULE` target is a
[sub-rule label](https://github.com/MetaCubeX/Meta-Docs/blob/main/docs/config/sub-rule.md),
not a proxy: it stays unchanged even if a node has the same name. Unknown rule
types and incomplete records stay unchanged; this is not a full config validator.
Rules cannot encode a renamed target containing a comma, line break, or outer
whitespace, so such a replacement returns an error without output or input mutation.
External rule-provider payloads, DNS strings, filters, arbitrary nested keys and
provider node names are not rewritten. No external files are read or fetched.
Supported dialer locations follow the [dialer-proxy documentation](https://github.com/MetaCubeX/Meta-Docs/blob/main/docs/config/proxies/dialer-proxy.en.md);
proxy groups do not themselves support that field.
