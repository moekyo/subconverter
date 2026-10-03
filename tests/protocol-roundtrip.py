#!/usr/bin/env python3
"""Offline contract tests using production parser/exporters and synthetic data.

Run python3 tests/protocol-roundtrip.py. Same dependencies as reality-roundtrip.py.
No fetched subscriptions, real credentials, server, CI, or client connections.
"""
import base64
import copy
import json
import os
from pathlib import Path
import subprocess
import unittest
from urllib.parse import quote

import yaml

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build/reality-roundtrip"
if not os.environ.get("SUBCONVERTER_TEST_SKIP_BUILD"):
    subprocess.run(["cmake", "-S", str(ROOT / "tests"), "-B", str(BUILD)], check=True)
    subprocess.run(["cmake", "--build", str(BUILD), "-j", "2"], check=True)
BIN = os.environ.get("SUBCONVERTER_TEST_BINARY", str(BUILD / "protocol-convert"))


def convert(content, target="clash", style="block", mode="list", encoded=False, ok=True):
    if isinstance(content, dict):
        content = yaml.safe_dump(content, sort_keys=False)
    if encoded:
        content = base64.b64encode(content.encode()).decode()
    p = subprocess.run([BIN, target, style, mode], input=content, text=True, capture_output=True)
    if ok:
        assert p.returncode == 0, (p.returncode, p.stderr)
    else:
        return p
    if target == "clash":
        return yaml.safe_load(p.stdout), p.stderr
    if target == "singbox":
        return json.loads(p.stdout), p.stderr
    return p.stdout, p.stderr


def proxy(kind, name=None, **fields):
    return dict(name=name or kind, type=kind, server="proxy.example", port=443, **fields)


class AnyTLSContracts(unittest.TestCase):
    def test_clash_fields_and_types(self):
        rich = proxy("anytls", password="00001234", sni="tls.example", udp=False, tfo=False,
                     **{"skip-cert-verify": False, "client-fingerprint": "chrome",
                        "fingerprint": "ab" * 32, "alpn": ["h2", "http/1.1", "custom"],
                        "idle-session-check-interval": 45, "idle-session-timeout": 90,
                        "min-idle-session": 0, "dialer-proxy": "Upstream"})
        plain = proxy("anytls", "anytls-default", password="other")
        doc = {"proxies": [rich, plain]}
        for style in ("block", "flow"):
            for mode in ("full", "list"):
                out, _ = convert(doc, style=style, mode=mode)
                self.assertEqual(out["proxies"], doc["proxies"])
                again, _ = convert(out, style=style, mode=mode)
                self.assertEqual(again["proxies"], doc["proxies"])

    def test_uri_encoding_ipv6_and_flags(self):
        password = "p@ss:word+%/中文"
        link = ("anytls://" + quote(password, safe="") + "@[2001:db8::1]:443/?sni=tls.example"
                "&fp=chrome&fingerprint=" + "ab" * 32 + "&alpn=h2%2Chttp%2F1.1%2Ccustom"
                "&udp=0&tfo=0&insecure=0#" + quote("AnyTLS 中文"))
        out, _ = convert(link, encoded=True)
        p = out["proxies"][0]
        self.assertEqual(p["password"], password)
        self.assertEqual(p["server"], "2001:db8::1")
        self.assertEqual(p["client-fingerprint"], "chrome")
        self.assertEqual(p["fingerprint"], "ab" * 32)
        self.assertEqual(p["alpn"], ["h2", "http/1.1", "custom"])
        for field in ("udp", "tfo", "skip-cert-verify"):
            self.assertIs(p[field], False)

    def test_singbox_outbound_password(self):
        out, _ = convert({"proxies": [proxy("anytls", password="synthetic", sni="tls.example")]}, "singbox")
        p = out["outbounds"][0]
        self.assertEqual(p["password"], "synthetic")
        self.assertNotIn("users", p)
        self.assertEqual(p["tls"]["server_name"], "tls.example")

    def test_invalid_idle_does_not_drop_other_nodes(self):
        for invalid in (-1, "oops", 2**40, [1], True):
            bad = proxy("anytls", "invalid", password="secret", **{"min-idle-session": invalid})
            good = proxy("ss", password="synthetic", cipher="aes-128-gcm")
            out, warnings = convert({"proxies": [bad, good]})
            self.assertEqual([p["name"] for p in out["proxies"]], ["ss"])
            self.assertIn("invalid idle-session parameter", warnings)
            self.assertNotIn("secret", warnings)

    def test_cross_target_pin_safety(self):
        pin = "ab" * 32
        p = proxy("anytls", password="synthetic", **{"fingerprint": pin, "skip-cert-verify": True})
        out, warnings = convert({"proxies": [p]}, "singbox")
        self.assertEqual(out["outbounds"], [])
        self.assertIn("skipped", warnings)
        text, warnings = convert({"proxies": [p]}, "quanx")
        self.assertNotIn("anytls =", text)
        self.assertIn("skipped", warnings)
        p["skip-cert-verify"] = False
        text, _ = convert({"proxies": [p]}, "quanx")
        self.assertIn("tls-cert-sha256=" + pin, text)
        self.assertIn("tls-verification=true", text)
        self.assertIn("over-tls=true", text)
        for target, key in (("surge", "server-cert-fingerprint-sha256"), ("loon", "tls-cert-sha256")):
            text, _ = convert({"proxies": [p]}, target)
            self.assertIn(key + "=" + pin, text)

    def test_singbox_clienthello_and_detour(self):
        p = proxy("anytls", password="synthetic", **{"client-fingerprint": "chrome", "dialer-proxy": "Upstream"})
        out, _ = convert({"proxies": [p]}, "singbox")
        self.assertEqual(out["outbounds"][0]["tls"]["utls"], {"enabled": True, "fingerprint": "chrome"})
        self.assertEqual(out["outbounds"][0]["detour"], "Upstream")

    def test_anytls_default_port_and_invalid_uri(self):
        for authority in ("proxy.example", "[2001:db8::1]"):
            out, _ = convert("anytls://secret@" + authority + "/?sni=tls.example", encoded=True)
            self.assertEqual(out["proxies"][0]["port"], 443)
        for authority in ("proxy.example:0", "proxy.example:65536", "proxy.example:99999999999999999999", "bad,server:443"):
            self.assertNotEqual(convert("anytls://secret@" + authority, encoded=True, ok=False).returncode, 0)
        for suffix in ("?sni=x&sni=y", "?sni=%GG", "?sni=%00", "?udp=maybe", "?security=reality"):
            self.assertNotEqual(convert("anytls://secret@proxy.example:443" + suffix, encoded=True, ok=False).returncode, 0)

    def test_anytls_text_delimiters_cannot_inject_options(self):
        for field in ("password", "sni", "name"):
            for value in ('p,skip-cert-verify=true', 'p"quoted', "p\\escape", "p\nnext"):
                p = proxy("anytls", password="synthetic")
                p[field] = value
                out, _ = convert({"proxies": [p]})
                self.assertEqual(out["proxies"][0][field], value.replace("=", "-") if field == "name" else value)
                for target in ("surge", "quanx", "loon"):
                    text, warnings = convert({"proxies": [p]}, target)
                    self.assertNotIn("anytls", text.lower())
                    self.assertIn("skipped", warnings)
                    self.assertNotIn(value, warnings)

    def test_no_cross_node_transport_leak(self):
        doc = {"proxies": [
            proxy("vmess", uuid="00000000-0000-4000-8000-000000000001", alterId=0,
                  cipher="auto", tls=True, network="ws", **{"ws-opts": {"path": "/vmess", "headers": {"Host": "ws.example"}}}),
            proxy("vmess", "vmess-default", uuid="00000000-0000-4000-8000-000000000002", alterId=0, cipher="auto"),
            proxy("ss", "ss-plugin", password="p", cipher="aes-128-gcm", plugin="v2ray-plugin",
                  **{"plugin-opts": {"mode": "websocket", "host": "plugin.example", "path": "/first", "tls": True}}),
            proxy("ss", "ss-plugin-default", password="p", cipher="aes-128-gcm", plugin="v2ray-plugin",
                  **{"plugin-opts": {"mode": "websocket"}}),
            proxy("trojan", password="p"),
        ]}
        together, _ = convert(doc)
        alone = [convert({"proxies": [p]})[0]["proxies"][0] for p in doc["proxies"]]
        self.assertEqual(together["proxies"], alone)


class VlessURIContracts(unittest.TestCase):
    UUID = "00000000-0000-4000-8000-000000000001"
    BASE = "vless://" + UUID + "@[2001:db8::2]:443?"

    def test_reality_raw_and_base64(self):
        for short_id in ("deadbeef", "00001234", "12345678", ""):
            uri = self.BASE + "security=reality&pbk=" + "A" * 43 + "&sid=" + short_id + "&flow=xtls-rprx-vision&fp=chrome&sni=tls.example&udp=0&tfo=0&allowInsecure=0&alpn=h2%2Chttp%2F1.1&packet-encoding=xudp#Reality"
            for encoded in (False, True):
                for style in ("block", "flow"):
                    for mode in ("full", "list"):
                        out, _ = convert(uri, encoded=encoded, style=style, mode=mode)
                        p = out["proxies"][0]
                        self.assertEqual(p["uuid"], self.UUID)
                        self.assertEqual(p["reality-opts"].get("short-id", ""), short_id)
                        self.assertEqual(p["client-fingerprint"], "chrome")
                        self.assertEqual(p["alpn"], ["h2", "http/1.1"])
                        self.assertEqual(p["packet-encoding"], "xudp")
                        self.assertIs(p["skip-cert-verify"], False)
                        self.assertIs(p["udp"], False)
                        self.assertIs(p["tfo"], False)
                        again, _ = convert(out, style=style, mode=mode)
                        self.assertEqual(again["proxies"], out["proxies"])

    def test_transport_host_and_sni_remain_distinct(self):
        uri = self.BASE + "security=tls&type=ws&sni=tls.example&host=ws.example&path=%2Fhello%3Fed%3D2048#WS"
        p = convert(uri)[0]["proxies"][0]
        self.assertEqual(p["servername"], "tls.example")
        self.assertEqual(p["ws-opts"], {"path": "/hello?ed=2048", "headers": {"Host": "ws.example"}})
        uri = self.BASE + "security=tls&type=grpc&mode=gun&serviceName=hello%2Fworld&sni=tls.example#GRPC"
        p = convert(uri)[0]["proxies"][0]
        self.assertEqual(p["grpc-opts"]["grpc-service-name"], "hello/world")
        p = convert(self.BASE + "encryption=none#TCP")[0]["proxies"][0]
        self.assertEqual(p["network"], "tcp")
        self.assertIs(p["tls"], False)

    def test_invalid_and_unsupported_are_diagnosed_without_credentials(self):
        valid = "anytls://neighbor@proxy.example:443#neighbor"
        for query in ("type=xhttp", "type=quic", "security=unknown", "encryption=unknown", "security=reality&pbk=bad", "security=tls&ech=secret", "type=tcp&headerType=http", "type=grpc&mode=multi", "security=tls&allowInsecure=0&insecure=1", "security=tls&fp=chrome&fp=firefox"):
            out, warnings = convert(self.BASE + query + "#rejected" + "\n" + valid)
            self.assertEqual([p["name"] for p in out["proxies"]], ["neighbor"])
            self.assertIn("Skipped invalid or unsupported", warnings)
            self.assertNotIn("neighbor@", warnings)
            self.assertNotIn(self.UUID, warnings)


if __name__ == "__main__":
    unittest.main(verbosity=2)
