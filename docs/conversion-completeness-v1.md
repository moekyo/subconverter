# Conversion completeness check v1 candidate

The user-facing name is **转换完整性检查** (English: **Conversion completeness check**).
The technical `strict` / `legacy` values and wire protocol names are unchanged.

This opt-in candidate is based on `038432394b1a3bd0e3f69ca5a8701e75abb0a5de`.
It is not deployed. A successful conversion without this protocol remains
`NOT_EVALUATED` for completeness. Syntax validation alone is not completeness.

## Request and result

Request `completeness=1&report_nonce=<32 lowercase hexadecimal characters>`.
The response media type is `application/vnd.subconverter.completeness+json`;
schema is `subconverter.completeness/v1`. PASS contains the exact serialized
output and its SHA-256. FAIL or UNVERIFIED returns HTTP 422, empty output, and
the empty-output digest. Invalid version/nonce and incompatible upload/HEAD
requests cannot produce a publishable result. Ordinary requests retain the
legacy response contract.

Each source is registered before fetch and each input occurrence before node
parsing, filtering, or renaming. Source and node ordinals do not depend on
surviving nodes or display names. Source witnesses bind the exact configured
locator, fetched bytes, and existing fetch/cache context. Stale fallback cannot
pass. Witnesses are not executable attestation or proof against a compromised
converter.

The report inventories original input fields and actual serialized output
fields separately, including containers, scalar types and list order. Native
Clash nodes are compared directly. URI fields are independently read from the
original URI, not reconstructed from the production Proxy model. Additions
require a narrow generated-default or explicit configuration-default mapping.
Unknown keys, missing or changed fields, unsupported nodes, ambiguous identity,
unaccounted occurrences and unverified transformations prevent PASS.

## Coverage, including explicit refusal

| Input | Strict v1 behavior |
| --- | --- |
| Native Clash YAML or JSON, optionally Base64 wrapped | Direct recursive field comparison against actual Clash output; protocol and field support still must succeed |
| Raw URI lists, optionally Base64 wrapped | Independent mapping for supported SS, VMess JSON TCP/WS, Trojan, VLESS, HY2, AnyTLS and TUIC subsets |
| SSR URI, unsupported URI plugins/options or transports | Explicit UNVERIFIED or field/node rejection; no claim of losslessness |
| Legacy INI and other legacy JSON formats | Explicit UNVERIFIED; ordinary conversion remains available |
| Malformed, multi-document, cyclic, duplicate-key or excessive inputs | Controlled failure, no publishable payload |
| Source root configuration beyond the supported node collection | SOURCE_CONFIGURATION_UNHANDLED; settings are not silently treated as imported |

The producer can verify `clash`/`clashr` serialization. The companion admin
consumer only enables `clash`. Other output targets and auto selection remain
explicitly unverified. Existing QX, Surge, sing-box and other conversion paths
are regression-tested where applicable; this does not certify all protocols
for every client. TUIC remains experimental as documented in the existing PR.

The strict contract intentionally refuses unsupported filtering/transformations
instead of granting a general permission to lose nodes. A future mapping must
have independent input expectations and consumer validation before expanding
coverage. There is no automatic allowlist for unknown fields.

## Field corrections

SOCKS5 UDP/TFO/certificate-skip tri-state values now survive native input.
Clash scalar strings that resemble booleans, numbers or dates retain string
type, including the admin parser's floating-point forms. Numeric REALITY short
IDs retain their exact digit spelling through an explicit representation map.

SIP003 plugin options use escaped semicolon/equal/backslash parsing. Values
such as `host=tls.example`, `path=/mux`, or `path=/x?foo=1&tls` cannot turn on
TLS or mux merely by containing those words. Standard ampersands stay inside
values. Native v2ray-plugin options use the pinned Mihomo defaults only when
absent: `mux: true` and `host: bing.com`. Explicit false and empty host remain
unchanged. These are native Clash defaults, not raw SIP003 defaults; see
[Mihomo v1.19.29](https://github.com/MetaCubeX/mihomo/blob/v1.19.29/adapter/outbound/shadowsocks.go#L332-L346).
Raw SIP003 TLS uses key-presence semantics and mux uses integer semantics;
conflicting duplicate options fail. The narrow legacy mode-first ampersand
syntax remains compatible and does not receive an unsupported strict claim.
Clash and QuanX consume the same parsed options.

Both field inventories compare core boolean and decimal integer values after matching
their types. Equivalent spellings such as `TRUE`/`true` or `+443`/`443` are
accepted without floating-point conversion. Strings, credentials and REALITY
short-ID spelling retain their exact-value requirements. Invalid types,
changed values and integer overflow cannot use this equivalence.

## Private service boundary and rollout

Report field paths use numeric ordinals. Reports contain no original field
values, custom keys, node names, URLs, credentials or raw parser exceptions.
Hashes and nonces remain private service evidence. Public admin errors expose
fixed codes only. The companion admin uses a process-local sealed receipt,
checks exact full node semantics across its existing finalizer, and requires
matching source/body/cache/authority evidence before Generated LKG promotion.

Admin defaults to `SUBCONVERTER_COMPLETENESS_MODE=legacy`. Strict mode refuses
an older converter that returns raw output or lacks the report. Deploy the
compatible producer before deliberately enabling the strict consumer; this
candidate does not perform either deployment. Receipt binding to a configured
image descriptor is not measurement of the running image.

## Tests and remaining acceptance

`tests/completeness-report.py`, `tests/plugin-options-contract.cpp`, and
`tests/fetch-provenance.py` add producer and provenance checks. Existing protocol,
input-boundary, chain, automatic-group, final-group, fetch and REALITY suites
remain applicable. The accompanying review package includes independent field
and output-mutation controls, full original admin output oracles, actual pinned
Mihomo group members, and admin LKG preservation tests.

Cloud synthetic acceptance does not establish real airport-source coverage,
production image identity, the deployed admin transport path, or client
handshakes. Real frozen input comparison should run on an explicitly authorized
device with secrets retained there and only a redacted result returned. Existing
TLS verification, redirect/routing policy and broader cache durability issues
are outside this change.
