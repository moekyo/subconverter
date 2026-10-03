# Selective protocol upgrades

The integration is based on `moekyo/subconverter@37761233af84b2ffc8ef1112da553751a087306b`, with selected ideas audited against `asdlokj1qpi233/subconverter@ecb63a9b49c8a269a80578704117b20c3e8a19f9`. It is not a merge of that fork.

See [the review reconciliation and remaining P0 gates](reviews/PRO_REVIEW_RECONCILIATION.md). AnyTLS, HY1/HY2 and Clash VLESS REALITY already existed; their fixes are not advertised as newly added protocols.

## Tested input and output scope

Clash `proxies` / legacy `Proxy` mappings, including JSON object form, feed the existing typed model. Plaintext and Base64 URI feeds can mix SS, SSR, VMess, Trojan, VLESS, HY2, AnyTLS and TUIC. This is not a general Xray or sing-box JSON importer. Bare YAML arrays are not newly enabled.

| Protocol | Mihomo via target=clash | QX | Surge | Loon | Quantumult | Mellow | sing-box | mixed URI output |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| SS | yes | limited | limited | limited | limited | limited | limited | yes |
| SSR | limited | limited | external-executor path | limited | limited | no | legacy schema only | yes |
| VMess | limited | TCP/WS only | limited | limited | limited | limited | limited | yes |
| Trojan | limited | TCP only in this exporter | limited | limited | no | no | limited | yes |
| VLESS | TCP/WS/gRPC/H2 and existing HTTP YAML form | no new mapping | no | no | no | no | no new mapping | no |
| HY1 | existing YAML subset | no | no | no | no | no | existing subset | no |
| HY2 | URI/YAML fixes | no | basic only | basic only | no | no | restricted pin handling | no |
| AnyTLS | field/URI fidelity fixes | basic, explicit constraints | basic, explicit constraints | basic, explicit constraints | no | no | password/TLS fixes, pin guard | no |
| TUIC v4/v5 | typed URI/YAML subset | no | no | no | no | no | no | no |
| HTTP/SOCKS5 | existing paths | existing paths | existing paths | existing paths | existing paths | existing paths | existing paths | no |
| Snell | existing version <4 gate | no | existing | no | no | no | no | no |
| WireGuard | existing subset | no | existing subset | existing subset | no | no | existing schema | no |

“yes/limited” describes converter coverage, not a universal client-version compatibility or connection guarantee. Target versions matter. There is no new `target=mihomo`, `target=tuic` or `target=vless` HTTP endpoint. Unsupported protocols and selected unsupported/security-sensitive fields now produce redacted diagnostics; expected subset omissions must still be reviewed.

Certificate SHA256 and TLS ClientHello fingerprints remain distinct. SPKI pins are not silently converted into certificate pins. AnyTLS+REALITY and unimplemented ECH/TLS combinations are rejected for the modern Mihomo paths rather than weakened. sing-box whole-certificate pin output is withheld until a version-specific mapping is selected; Surge/Loon/QX text paths reject combinations whose pin precedence or quoting cannot be safely preserved.

## Run the offline checks

Dependencies: C++20 compiler, CMake, pkg-config, yaml-cpp, RapidJSON, PCRE2 and Python PyYAML.

```sh
python3 tests/reality-roundtrip.py
python3 tests/protocol-roundtrip.py
python3 tests/pro-review-regressions.py
# Optional real-curl tests, using synthetic 127.0.0.1 services only.
cmake -S tests -B build/reality-roundtrip -DBUILD_FETCH_TESTS=ON
cmake --build build/reality-roundtrip -j2
python3 tests/fetch-loopback.py --binary build/reality-roundtrip/fetch-contract-driver
bash tests/modern-mihomo-contract.sh
# Optional: caller provides an independently verified client binary.
python3 tests/mihomo-protocol-parse.py --mihomo /path/to/mihomo
```

The production static library is built with `NO_JS_RUNTIME` / `NO_WEBGET` for deterministic conversion tests. The separate optional real-curl target validates selected HTTP/cache failures; neither suite validates complete service reload/redirect/TLS policy. The protocol test runs `policy-contracts` and the existing route helper test, too.

Tested cloud toolchain: GCC 14.2.0, CMake 4.4.3, PyYAML 6.0.3, yaml-cpp 0.8.0, and official RapidJSON headers pinned at `24b5e7a8b27f42fa16b96fc70aade9106cf7102f`. Old unpatched RapidJSON v1.1.0 failed to compile with GCC14; this was an isolated test dependency issue, not hidden by modifying the project build recipe.

Mihomo parser validation used official v1.19.29. The release gzip SHA256 was `60de76a35a6cbf7b4fa4a20f5c257c24345d1d635ab1aa3877022a1997ef413c`, with decompressed executable SHA256 `9c397be7489538628fae781bc005e4c5b8cd7b0961b8bb2ca815c8150f193577`.

TUIC is an EXPERIMENTAL source-level unit, not release-ready: complete source/node/field accounting, admin eligibility/finalizer integration, real frozen-source coverage, and server handshakes are still pending. Do not deploy this branch solely because its parser tests pass.

No NAS deployment, production source fetch, source URL/token read, automatic CI run, PR, master update, or new client connection is part of these tests. Existing manual-only build/release workflow, custom Alpine base, fetch-route plumbing, base-group preservation and rule ordering are retained. Retention is not a claim that every old implementation is secure; the reconciliation documents remaining defects and acceptance gates.
