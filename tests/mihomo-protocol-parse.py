#!/usr/bin/env python3
"""Parse synthetic converted output with an explicitly supplied Mihomo binary.

Build tests first, then run:
  python3 tests/mihomo-protocol-parse.py --mihomo /path/to/verified/mihomo
This never downloads a binary, fetches a subscription, starts a proxy service,
or proves server connectivity. Use the same pinned client version as deployment.
"""
import argparse
import copy
from pathlib import Path
import subprocess
import tempfile

import yaml

parser = argparse.ArgumentParser()
parser.add_argument("--mihomo", type=Path, required=True)
parser.add_argument("--converter", type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
converter = (args.converter or root / "build/reality-roundtrip/protocol-convert").resolve()
mihomo = args.mihomo.resolve()
fixture = yaml.safe_load((root / "tests/fixtures/mixed-airport.yaml").read_text())
fixture["proxies"].extend([
    {"name": "TUIC-v4", "type": "tuic", "server": "127.0.0.1", "port": 443,
     "token": "synthetic:v4-token", "alpn": [], "reduce-rtt": False, "fast-open": False},
    {"name": "AnyTLS-pin", "type": "anytls", "server": "127.0.0.1", "port": 443,
     "password": "00001234", "fingerprint": "0" * 63 + "1", "client-fingerprint": "chrome",
     "alpn": ["h2", "http/1.1"], "idle-session-check-interval": 30, "min-idle-session": 0},
    {"name": "VLESS-REALITY", "type": "vless", "server": "127.0.0.1", "port": 443,
     "uuid": "00000000-0000-4000-8000-000000000003", "network": "tcp", "tls": True,
     "flow": "xtls-rprx-vision", "servername": "tls.example", "client-fingerprint": "chrome",
     "reality-opts": {"public-key": "A" * 43, "short-id": "00001234", "support-x25519mlkem768": True}},
])
for style in ("block", "flow"):
    for mode in ("full", "list"):
        result = subprocess.run([str(converter), "clash", style, mode],
                                input=yaml.safe_dump(fixture), text=True, capture_output=True, check=True)
        output = yaml.safe_load(result.stdout)
        assert len(output["proxies"]) == len(fixture["proxies"])
        output.update({"mode": "rule", "dns": {"enable": False},
                       "proxy-groups": [{"name": "Synthetic", "type": "select",
                                         "proxies": ["REJECT"] + [p["name"] for p in output["proxies"]]}],
                       "rules": ["MATCH,REJECT"]})
        with tempfile.TemporaryDirectory(prefix="subconverter-mihomo-") as directory:
            config = Path(directory) / "synthetic.yaml"
            config.write_text(yaml.safe_dump(output, sort_keys=False))
            subprocess.run([str(mihomo), "-t", "-d", directory, "-f", str(config)],
                           capture_output=True, text=True, check=True, timeout=30)
        print(f"Mihomo parse {style}/{mode}: PASS ({len(fixture['proxies'])} synthetic nodes)")
