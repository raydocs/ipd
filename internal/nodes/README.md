# Clash node renaming

`RenameYAML` changes proxy names and exact node references in each
`proxy-groups[].proxies` list. Nested groups keep their group names and links;
credentials, group options, provider settings and other configuration stay intact.
The input `File` is not mutated.

Names are allocated in proxy order. Existing node names (even those being
renamed), outcome source names, group names, group members supplied externally
and built-in targets
(`DIRECT`, `REJECT`, `REJECT-DROP`, `PASS`, `COMPATIBLE`, `GLOBAL`) are reserved.
A collision receives the first available ` (2)`, ` (3)`, etc. suffix. The emitted
YAML contains the resolved names; outcomes remain the requested names.

Missing or empty rename outcomes leave nodes unchanged. Outcomes for non-node
targets do not rename those targets. Reapplying the same outcomes to the same
input or to its renamed output is stable. A requested rename of a duplicate
source name, a source sharing a group name, or a built-in source name fails
without modifying the input: those references cannot be disambiguated safely.
