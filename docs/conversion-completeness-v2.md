# Conversion completeness v2: configured filtering

This candidate extends the v1 source/field ledger only for explicit, bounded
remark-regex filtering. It does not enable strict mode, deploy an image, broaden
protocol support, or authorize arbitrary omission. The paired admin changes also
account for exact canonical Tailscale additions after conversion.

## Negotiation and rollout boundary

Strict requests use `completeness=2` and a fresh 32-lowercase-hex `report_nonce`.
The media type remains `application/vnd.subconverter.completeness+json`, and the
schema is `subconverter.completeness/v2`. Requests for version 1 or any other
version receive a non-publishable failure. Ordinary requests with no completeness
parameter retain legacy behavior. The public summary's independent version 1
shape is unchanged.

Both producer and consumer must be upgraded before v2 strict use. A v2 consumer
rejects v1 reports; an old consumer rejects v2 reports. There is no automatic
fallback to legacy, and a report from a version-mismatched pair cannot mint a
publication receipt or promote a generated LKG. Existing `legacy` configuration
remains the default and reports completeness as NOT_EVALUATED.

## Exact policy witness

The report adds:

```json
"filter_policy": {
  "engine": "subconverter.regex/v1",
  "include": ["nonce-bound rule digest"],
  "exclude": ["nonce-bound rule digest"]
}
```

Each digest is SHA256 over UTF-8 bytes of
`nonce + NUL + "filter" + NUL + kind + NUL + exact_rule`, with `kind` equal to
`include` or `exclude`. Array order, duplicate rules, exact Unicode spelling and
include/exclude roles are significant. Names, rules and source values are not
copied into diagnostics. The producer witnesses effective arrays after ordinary
external/request override handling. Admin independently loads saved
`[common].include_remarks` and `exclude_remarks` and requires an exact ordered
match. An effective override can pass only if it leaves those arrays unchanged.

Limits are 256 rules per array, 4096 UTF-8 bytes per rule, and 65536 rule bytes in
total. Empty or invalid regexes, `!!` extended matcher syntax, enabled script
filters, and unknown engines are unverified. This version does not evaluate
JavaScript or claim compatibility for arbitrary config/filter overrides.

## Per-occurrence accounting

Every original source and node occurrence is registered before parsing,
filtering or renaming. Emitted nodes retain their existing PASS/EXACT result,
complete input/output field inventories and one-to-one output ordinal. They now
also carry `filter: null`.

An intentionally omitted occurrence has:

```json
{
  "ordinal": 1,
  "status": "FILTERED",
  "reason": "CONFIG_EXCLUDE_MATCH",
  "output_ordinal": null,
  "filter": {"kind": "exclude", "rule_ordinal": 0},
  "fields": [{"path": [], "disposition": "FILTERED", "reason": "CONFIG_EXCLUDE_MATCH"}],
  "output_fields": []
}
```

The fields array above is abbreviated. The real ledger includes every original
container/leaf; URI inputs retain their original component/query ledger. An
exclude witness names the first matching exclusion index. An include miss uses
`CONFIG_INCLUDE_MISS`, `kind: include`, and `rule_ordinal: null`; it is legal only
with a nonempty configured inclusion array. Exclusion takes precedence.

A generic `SourceNodeIdentity::Filtered` flag is not permission. The report
requires an actual filterNodes observation of the same source identity and exact
policy. It independently evaluates the same PCRE2 options with a three-state
result. Compile, match-limit, UTF, or other evaluation errors produce
FILTER_UNVERIFIED, never an inclusion miss. Unexplained omissions, rejected
parses, unsupported protocols, unknown fields, malformed types/ports, duplicate
mappings and empty output still fail. Source occurrence multiplicity, per-source
ordinals and aggregate field/node bounds remain checked.

## Trust and freshness

These remain private trusted-service witnesses, not signatures proving truth
against a compromised converter. Admin does not refetch private inputs or
independently rerun PCRE2 against names absent from its redacted ledger. It does
independently reject absent/mismatched policy, invented reasons, malformed filter
evidence, unknown fields and inconsistent retained output accounting. No user
"ignore" checkbox or node-count-only exception exists.

The request nonce, exact source-locator multiset, fetched-content/context
witnesses, whole-output digest, process HMAC, source freshness, saved-authority
currentness, final validation and LKG gates are retained. A saved filter change
invalidates the request/receipt, including after successful conversion.

## Offline checks

Build the existing production static target/test driver, then run:

```sh
python3 tests/completeness-report.py --driver /path/to/completeness-convert
python3 tests/completeness-filter-report.py --driver /path/to/completeness-convert
```

The companion admin includes a real producer→consumer→canonical-finalizer suite
selected by `SUBCONVERTER_COMPLETENESS_DRIVER`. All fixtures are synthetic,
including 248 input occurrences, 28 configured exclusions, 220 exact retained
nodes, and one saved-authority Tailscale addition. These tests do not establish
full HTTP server build, live source, device, handshake or rollout acceptance.
