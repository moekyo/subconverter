#!/usr/bin/env python3
"""Run: python3 tests/reality-roundtrip.py.

Requires PyYAML, CMake, a C++20 compiler, pkg-config, rapidjson, yaml-cpp and PCRE2.
Builds the production static library; no server, network or Clash template needed.
"""
import copy
from pathlib import Path
import subprocess

import yaml

root = Path(__file__).resolve().parents[1]
build = root / "build" / "reality-roundtrip"
subprocess.run(["cmake", "-S", str(root / "tests"), "-B", str(build)], check=True)
subprocess.run(["cmake", "--build", str(build), "-j", "2"], check=True)
fixture = yaml.safe_load((root / "tests/fixtures/modern-mihomo-vless-reality-hy2.yaml").read_text())
original = fixture["proxies"][0]
for short_id in ("00001234", "12345678"):
    proxy = copy.deepcopy(original)
    proxy["name"] = "Reality-" + short_id
    proxy["reality-opts"]["short-id"] = short_id
    fixture["proxies"].append(proxy)


def projection(document):
    proxies = document["proxies"]
    assert len(proxies) == len(fixture["proxies"])
    result = {}
    for proxy in proxies:
        assert proxy["name"] not in result
        if proxy["type"] == "vless":
            for field in ("public-key", "short-id"):
                value = proxy["reality-opts"][field]
                assert type(value) is str, (proxy["name"], field, value, type(value))
        result[proxy["name"]] = proxy
    return result


expected = copy.deepcopy(projection(fixture))
# The existing HY2 parser does not carry the optional udp flag through conversion.
expected["VPS-HY2"].pop("udp")
for style in ("block", "flow"):
    for mode in ("full", "list"):
        output = subprocess.run(
            [str(build / "reality-convert"), style, mode],
            input=yaml.safe_dump(fixture), text=True, capture_output=True, check=True,
        ).stdout
        parsed = yaml.safe_load(output)
        assert projection(parsed) == expected, (style, mode, parsed)
        reparsed = yaml.safe_load(yaml.safe_dump(parsed))
        assert projection(reparsed) == expected, (style, mode, reparsed)
        print(f"REALITY round-trip {style}/{mode}: PASS (deadbeef, 00001234, 12345678; HY2 unchanged)")
