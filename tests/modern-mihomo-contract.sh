#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

grep -q 'VLESS,' "$ROOT/src/parser/config/proxy.h"
grep -q 'case "vless"_hash:' "$ROOT/src/parser/subparser.cpp"
grep -q '{ProxyType::VLESS,        "VLESS"}' "$ROOT/src/generator/config/subexport.cpp"
grep -q 'singleproxy\["reality-opts"\]\["public-key"\]' "$ROOT/src/generator/config/subexport.cpp"
grep -q 'singleproxy\["reality-opts"\]\["short-id"\]' "$ROOT/src/generator/config/subexport.cpp"
grep -q 'singleproxy\["client-fingerprint"\]' "$ROOT/src/generator/config/subexport.cpp"

hy2_block="$(awk '/case ProxyType::Hysteria2:/,/case ProxyType::AnyTLS:/' "$ROOT/src/generator/config/subexport.cpp" | head -n 100)"
grep -q 'singleproxy\["fingerprint"\] = x.Fingerprint;' <<<"$hy2_block"

grep -q '.fun<&Proxy::Flow>("Flow")' "$ROOT/src/script/script_quickjs.cpp"
grep -q '.fun<&Proxy::ShortId>("ShortId")' "$ROOT/src/script/script_quickjs.cpp"

echo 'modern Mihomo source contract: PASS'
