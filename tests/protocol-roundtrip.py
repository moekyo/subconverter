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
        doc = {"proxies": [rich, plain, proxy("ss", "Upstream", password="p", cipher="aes-128-gcm")]}
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
        out, _ = convert({"proxies": [p, proxy("ss", "Upstream", password="p", cipher="aes-128-gcm")]}, "singbox")
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


class TuicContracts(unittest.TestCase):
    UUID = "00000000-0000-4000-8000-000000000005"

    def test_v4_v5_complete_typed_roundtrip(self):
        v4 = proxy("tuic", "TUIC-v4", token="00001234", alpn=[])
        v5 = proxy("tuic", "TUIC-v5", uuid=self.UUID, password="00001234", udp=False, tfo=False,
            **{"sni": "tuic.example", "alpn": ["h3", "custom", "123"], "skip-cert-verify": False,
               "fingerprint": "0" * 63 + "1", "ip": "192.0.2.1", "congestion-controller": "bbr",
               "udp-relay-mode": "quic", "disable-sni": False, "reduce-rtt": False,
               "fast-open": False, "heartbeat-interval": 10000, "request-timeout": 8000,
               "max-udp-relay-packet-size": 1200, "max-open-streams": 100, "cwnd": 32,
               "recv-window-conn": 100000, "recv-window": 200000, "max-datagram-frame-size": 1300,
               "disable-mtu-discovery": False, "udp-over-stream": False, "udp-over-stream-version": 0})
        plain = proxy("tuic", "TUIC-defaults", uuid=self.UUID, password="")
        doc = {"proxies": [v4, v5, plain]}
        for style in ("block", "flow"):
            for mode in ("full", "list"):
                out, _ = convert(doc, style=style, mode=mode)
                self.assertEqual(out["proxies"], doc["proxies"])
                again, _ = convert(out, style=style, mode=mode)
                self.assertEqual(again["proxies"], doc["proxies"])
        only_fast = proxy("tuic", token="token", **{"fast-open": True})
        out, _ = convert({"proxies": [only_fast]})
        self.assertEqual(out["proxies"], [only_fast])

    def test_uri_v4_token_v5_encoded_password_and_aliases(self):
        for encoded in (False, True):
            token = "token:with@plus+%/"
            out, _ = convert("tuic://" + quote(token, safe="") + "@[2001:db8::3]:443#v4", encoded=encoded)
            self.assertEqual(out["proxies"][0]["token"], token)
            uuid_token = self.UUID + ":token"
            out, _ = convert("tuic://" + quote(uuid_token, safe="") + "@proxy.example:443#v4-uuid-token", encoded=encoded)
            self.assertEqual(out["proxies"][0]["token"], uuid_token)
            self.assertNotIn("uuid", out["proxies"][0])
            password = "secret:with@plus+%/中文"
            uri = "tuic://" + self.UUID + ":" + quote(password, safe="") + "@[2001:db8::3]:443?congestion_control=bbr&udp_relay_mode=quic&allow_insecure=0&disable_sni=0&reduce_rtt=0&alpn=h3%2Ch2#v5"
            out, _ = convert(uri, encoded=encoded)
            p = out["proxies"][0]
            self.assertEqual(p["password"], password)
            self.assertNotIn("token", p)
            self.assertEqual(p["udp-relay-mode"], "quic")
            self.assertEqual(p["congestion-controller"], "bbr")
            self.assertIs(p["skip-cert-verify"], False)
            self.assertIs(p["reduce-rtt"], False)
            self.assertIs(p["disable-sni"], False)
            self.assertEqual(p["alpn"], ["h3", "h2"])
            self.assertNotIn("request-timeout", p)

    def test_invalid_options_do_not_drop_valid_neighbors(self):
        good = proxy("ss", password="synthetic", cipher="aes-128-gcm")
        for fields in ({"uuid": self.UUID, "password": "p"}, {"request-timeout": -1}, {"udp-over-stream-version": 99}, {"reduce-rtt": "maybe"},
                       {"udp-relay-mode": "invalid"}, {"alpn": [{}]}, {"ech-opts": {"enable": True}}, {"unknown-setting": 1}):
            bad = proxy("tuic", "invalid", token="sensitive-token", **fields)
            out, warnings = convert({"proxies": [bad, good]})
            self.assertEqual([p["name"] for p in out["proxies"]], ["ss"])
            self.assertIn("Skipped", warnings)
            self.assertNotIn("sensitive-token", warnings)
        for params in ("insecure=0&allow_insecure=1", "udp_relay_mode=bad", "request-timeout=-1", "unknown=secret"):
            p = convert("tuic://token@proxy.example:443?" + params, ok=False)
            self.assertNotEqual(p.returncode, 0)
            self.assertIn("Skipped", p.stderr)

    def test_unsupported_output_has_explicit_diagnostic(self):
        doc = {"proxies": [proxy("tuic", token="sensitive-token")]}
        for target in ("quanx", "surge", "loon", "quan", "mellow", "mixed", "singbox"):
            output, warning = convert(doc, target)
            self.assertIn("TUIC", warning)
            self.assertIn("unsupported protocol", warning)
            self.assertNotIn("sensitive-token", str(output) + warning)


class MixedSafetyContracts(unittest.TestCase):
    def test_new_vless_types_are_contained_per_node(self):
        for fields in ({"fingerprint": []}, {"packet-encoding": {}}, {"alpn": [{}]}):
            bad = proxy("vless", uuid=VlessURIContracts.UUID, **fields)
            good = proxy("ss", password="synthetic", cipher="aes-128-gcm")
            out, warnings = convert({"proxies": [bad, good]})
            self.assertEqual([p["name"] for p in out["proxies"]], ["ss"])
            self.assertIn("Skipped malformed Clash node", warnings)

    def test_numeric_pin_and_alpn_stay_strings(self):
        p = proxy("anytls", password="p", fingerprint="0" * 63 + "1", alpn=["123", "h2"])
        out, _ = convert({"proxies": [p]})
        self.assertEqual(out["proxies"], [p])

    def test_chain_reference_follows_normalized_name(self):
        first = proxy("ss", "Up=stream", password="p", cipher="aes-128-gcm")
        second = proxy("anytls", password="p", **{"dialer-proxy": "Up=stream"})
        for target, collection, key in (("clash", "proxies", "dialer-proxy"), ("singbox", "outbounds", "detour")):
            out, _ = convert({"proxies": [first, second]}, target)
            self.assertEqual(out[collection][1][key], "Up-stream")

    def test_omitted_upstream_prunes_transitive_dependents(self):
        upstream = proxy("tuic", "TUIC-upstream", token="synthetic")
        middle = proxy("ss", "Middle", password="p", cipher="aes-128-gcm", **{"dialer-proxy": "TUIC-upstream"})
        last = proxy("anytls", "Last", password="p", **{"dialer-proxy": "Middle"})
        independent = proxy("ss", "Independent", password="p", cipher="aes-128-gcm")
        # Dependents before upstream exercise fixed-point pruning, not input order.
        fixture = {"proxies": [last, middle, upstream, independent]}
        for target in ("surge", "singbox"):
            failed = convert(fixture, target, mode="full", ok=False)
            self.assertEqual(failed.returncode, 3)
            self.assertFalse(failed.stdout.strip())
            for mode in ("list",):
                result, warning = convert(fixture, target, mode=mode)
                text = json.dumps(result) if isinstance(result, dict) else result
                for omitted in ("Last", "Middle", "TUIC-upstream"):
                    self.assertNotIn(omitted, text)
                self.assertIn("Independent", text)
                self.assertIn("dependent nodes", warning)
        out, _ = convert(fixture)
        self.assertEqual(len(out["proxies"]), 4)
        # Unresolved names cannot be assumed to be external groups in a node list.
        out, _ = convert({"proxies": [proxy("ss", password="p", cipher="aes-128-gcm", **{"dialer-proxy": "Base group"})]})
        self.assertFalse(out.get("proxies"))

    def test_duplicate_names_do_not_share_dependency_identity(self):
        one = proxy("ss", "Duplicate", password="p", cipher="aes-128-gcm")
        two = proxy("ss", "Duplicate", password="p", cipher="aes-128-gcm", **{"dialer-proxy": "TUIC-upstream"})
        upstream = proxy("tuic", "TUIC-upstream", token="synthetic")
        for target in ("singbox", "surge"):
            result, warning = convert({"proxies": [one, two, upstream]}, target)
            text = json.dumps(result) if isinstance(result, dict) else result
            self.assertIn("Duplicate", text)
            self.assertNotIn("Duplicate 2", text)
            self.assertNotIn("TUIC-upstream", text)
            self.assertIn("dependent nodes", warning)
        # A reference to an ambiguous original name is explicitly rejected.
        last = proxy("anytls", "Last", password="p", **{"dialer-proxy": "Duplicate"})
        result, warning = convert({"proxies": [one, dict(one), last]})
        self.assertEqual([p["name"] for p in result["proxies"]], ["Duplicate", "Duplicate 2"])
        self.assertIn("ambiguous", warning)

    def test_empty_vless_encryption_is_default(self):
        p = proxy("vless", uuid=VlessURIContracts.UUID, encryption="")
        out, _ = convert({"proxies": [p]})
        self.assertEqual(out["proxies"][0]["type"], "vless")

    def test_security_extensions_are_not_silently_removed(self):
        for kind in ("anytls", "vless"):
            for key in ("ech-opts", "smux", "shadow-tls-opts"):
                p = proxy(kind, password="p", uuid=VlessURIContracts.UUID, **{key: {"enabled": True}})
                good = proxy("ss", password="synthetic", cipher="aes-128-gcm")
                out, warning = convert({"proxies": [p, good]})
                self.assertEqual([p["name"] for p in out["proxies"]], ["ss"])
                self.assertIn("unsupported security", warning)

    def test_reality_mlkem_flag_is_typed_and_preserved(self):
        for value in (False, True):
            p = proxy("vless", uuid=VlessURIContracts.UUID, network="tcp", tls=True,
                      **{"reality-opts": {"public-key": "A" * 43, "short-id": "00001234", "support-x25519mlkem768": value}})
            out, _ = convert({"proxies": [p]})
            self.assertEqual(out["proxies"], [p])

    def test_vless_uri_http_and_default_tls_identity(self):
        uri = VlessURIContracts.BASE + "security=tls&type=http&host=h2.example&path=%2Frpc"
        p = convert(uri)[0]["proxies"][0]
        self.assertEqual(p["network"], "h2")
        self.assertEqual(p["h2-opts"], {"host": ["h2.example"], "path": "/rpc"})
        self.assertEqual(p["servername"], "2001:db8::2")
        self.assertEqual(p["client-fingerprint"], "chrome")


class AirportMatrixContracts(unittest.TestCase):
    def test_clash_all_protocols_and_legacy_output_matrix(self):
        fixture = yaml.safe_load((ROOT / "tests/fixtures/mixed-airport.yaml").read_text())
        names = [p["name"] for p in fixture["proxies"]]
        out, _ = convert(fixture)
        self.assertEqual([p["name"] for p in out["proxies"]], names)
        expected = {
            "surge": {"ss", "vmess", "trojan", "hysteria2", "anytls", "socks5", "http", "snell", "wireguard"},
            "quanx": {"ss", "ssr", "vmess", "trojan", "anytls", "socks5", "http"},
            "loon": {"ss", "ssr", "vmess", "trojan", "hysteria2", "anytls", "socks5", "http", "wireguard"},
            "quan": {"ss", "ssr", "vmess", "socks5", "http"},
            "mellow": {"ss", "vmess", "socks5", "http"},
            "mixed": {"ss", "ssr", "vmess", "trojan"},
            "singbox": {"ss", "ssr", "vmess", "trojan", "hysteria", "hysteria2", "anytls", "socks5", "http", "wireguard"},
        }
        for target, supported in expected.items():
            for p in fixture["proxies"]:
                result, warning = convert({"proxies": [p]}, target)
                if target == "singbox":
                    emitted = len(result["outbounds"]) == 1
                elif target == "mellow":
                    emitted = p["name"] in result
                else:
                    emitted = bool(result.strip())
                self.assertEqual(emitted, p["type"] in supported, (target, p["type"], result))
                if not emitted:
                    self.assertTrue("unsupported" in warning or "omitted" in warning, (target, p["type"]))
                elif target != "mixed":
                    self.assertNotIn("omitted", warning, (target, p["type"]))

    def test_mixed_plaintext_and_base64_legacy_and_modern_nodes(self):
        fixture = yaml.safe_load((ROOT / "tests/fixtures/mixed-airport.yaml").read_text())
        legacy = convert(fixture, "mixed")[0]
        modern = "\n".join([
            "vless://" + VlessURIContracts.UUID + "@proxy.example:443?security=tls#VLESS-URI",
            "hy2://synthetic@proxy.example:443?sni=tls.example&pinSHA256=" + "ab" * 32 + "#HY2-URI",
            "anytls://synthetic@proxy.example:443#AnyTLS-URI",
            "tuic://" + TuicContracts.UUID + ":synthetic@proxy.example:443#TUIC-URI",
        ])
        expected = ["P-ss", "P-ssr", "P-vmess", "P-trojan", "VLESS-URI", "HY2-URI", "AnyTLS-URI", "TUIC-URI"]
        for encoded in (False, True):
            out, _ = convert(legacy + "\n" + modern, encoded=encoded)
            self.assertEqual([p["name"] for p in out["proxies"]], expected)
            self.assertEqual(out["proxies"][5]["fingerprint"], "ab" * 32)
            again, _ = convert(out)
            self.assertEqual(again["proxies"], out["proxies"])

    def test_protected_policy_contracts(self):
        with (ROOT / "tests/fixtures/mixed-airport.yaml").open() as fixture:
            subprocess.run([str(BUILD / "policy-contracts")], stdin=fixture, check=True)
        subprocess.run([str(BUILD / "subscription-proxy-route")], check=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
