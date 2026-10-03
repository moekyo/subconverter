#!/usr/bin/env python3
"""Known-defect gate derived from the 2026-10-03 independent review.

These tests assert desired invariants, NOT current buggy baseline output.
They were initially all red; keep the correct invariants as repairs land.
Build the production test harness first and check every failure rather than
weakening assertions to match the old baseline.
All credentials and endpoints are synthetic. No network traffic is made.
"""
import base64
import json
import os
from pathlib import Path
import runpy
import unittest
from urllib.parse import quote

os.environ["SUBCONVERTER_TEST_SKIP_BUILD"] = "1"
helpers = runpy.run_path(str(Path(__file__).with_name("protocol-roundtrip.py")))
convert, proxy = helpers["convert"], helpers["proxy"]
KEY = "AAAAAAAAAAAAAAAAAAAAAA=="


class ExistingDefectGate(unittest.TestCase):
    def test_standard_ss2022_plain_userinfo(self):
        uri = "ss://2022-blake3-aes-128-gcm:" + quote(KEY, safe="") + "@proxy.example:443#SS2022"
        out, _ = convert(uri)
        self.assertEqual(out["proxies"][0]["password"], KEY)
        self.assertEqual(out["proxies"][0]["cipher"], "2022-blake3-aes-128-gcm")

    def test_unknown_ss_plugin_never_becomes_plain_ss(self):
        node = proxy("ss", password="synthetic", cipher="aes-128-gcm", plugin="future-plugin",
                     **{"plugin-opts": {"required-option": "synthetic"}})
        p = convert({"proxies": [node]}, ok=False)
        if p.returncode:
            self.assertIn("unsupported", p.stderr.lower())
        else:
            import yaml
            output = yaml.safe_load(p.stdout)
            nodes = output.get("proxies") or []
            self.assertTrue(not nodes or nodes[0].get("plugin") == "future-plugin", "unknown plugin became bare SS")

    def test_ss_hy2_delimiters_cannot_become_text_options(self):
        for scheme, auth in (("ss", "aes-128-gcm:"), ("hy2", "")):
            for password in ('p,skip-cert-verify=true', 'p"quote', 'p\\backslash'):
                uri = scheme + "://" + auth + quote(password, safe="") + "@proxy.example:443#safe"
                out, _ = convert(uri)
                self.assertEqual(out["proxies"][0]["password"], password)
                for target in ("surge", "loon", "quanx"):
                    text, warning = convert(uri, target)
                    self.assertFalse(text.strip())
                    self.assertIn("skipped", warning)
        credentials = base64.urlsafe_b64encode(b"aes-128-gcm:p\nInjected = direct").decode()
        p = convert("ss://" + credentials + "@proxy.example:443#safe", ok=False)
        self.assertNotEqual(p.returncode, 0)
        self.assertNotIn("Injected", p.stderr)

    def test_quantumult_full_output_cannot_inject_password_options(self):
        password = 'p",certificate=0,foo="'
        uri = "ss://aes-128-gcm:" + quote(password, safe="") + "@proxy.example:443#safe"
        text, warning = convert(uri, "quan", mode="full")
        self.assertNotIn("certificate=0", text)
        self.assertNotIn("safe =", text)
        self.assertIn("skipped", warning)
        encoded, warning = convert(uri, "quan", mode="list")
        self.assertTrue(encoded)
        self.assertNotIn("skipped", warning)

    def test_hy2_default_port(self):
        out, _ = convert("hy2://synthetic@proxy.example/?sni=tls.example#HY2")
        self.assertEqual(out["proxies"][0]["port"], 443)

    def test_hy2_authentication_decodes_once(self):
        password = "p@ss:word+%/"
        out, _ = convert("hy2://" + quote(password, safe="") + "@proxy.example:443#HY2")
        self.assertEqual(out["proxies"][0]["password"], password)

    def test_hy2_target_sensitive_options_are_preserved_or_rejected(self):
        uri = "hy2://synthetic@proxy.example:443,20000-20100?obfs=salamander&obfs-password=obfs%40pass#hy2"
        clash, _ = convert(uri)
        self.assertEqual(clash["proxies"][0]["ports"], "443,20000-20100")
        singbox, _ = convert(uri, "singbox")
        self.assertEqual(singbox["outbounds"][0]["server_ports"], ["443:443", "20000:20100"])
        self.assertEqual(singbox["outbounds"][0]["obfs"], {"type": "salamander", "password": "obfs@pass"})
        for target in ("surge", "loon"):
            text, warnings = convert(uri, target)
            self.assertFalse(text.strip())
            self.assertIn("skipped", warnings)
        pin = "ab" * 32
        out, warnings = convert("hy2://synthetic@proxy.example:443?pinSHA256=" + pin, "singbox")
        self.assertEqual(out["outbounds"], [])
        self.assertIn("whole-certificate pin", warnings)

    def test_hy2_port_overflow_is_invalid(self):
        p = convert("hy2://synthetic@proxy.example:65537#bad", ok=False)
        self.assertNotEqual(p.returncode, 0, "port overflow must not wrap to 1")

    def test_qx_anytls_input_produces_a_node(self):
        out, _ = convert("anytls = proxy.example:443, password=synthetic, over-tls=true, tls-host=tls.example, tag=QX-AnyTLS")
        self.assertEqual(len(out["proxies"]), 1)
        self.assertEqual(out["proxies"][0]["type"], "anytls")

    def test_surge_password_padding_is_not_split_away(self):
        line = "SS2022 = ss, proxy.example, 443, encrypt-method=2022-blake3-aes-128-gcm, password=" + KEY
        out, _ = convert(line)
        self.assertEqual(out["proxies"][0]["password"], KEY)

    def test_single_protocol_export_does_not_repeat_previous_uri(self):
        good = proxy("ss", "first", password="p", cipher="aes-128-gcm")
        incompatible = proxy("ssr", "second", password="p", cipher="aes-128-cfb", protocol="auth_aes128_md5", obfs="tls1.2_ticket_auth")
        text, _ = convert({"proxies": [good, incompatible]}, "ss-uri")
        self.assertEqual(len(text.strip().splitlines()), 1, "unsupported SSR repeated prior SS URI")

    def test_qx_unsupported_transport_cannot_become_tcp(self):
        node = proxy("vmess", uuid="00000000-0000-4000-8000-000000000001", cipher="auto", alterId=0,
                     network="grpc", tls=True, **{"grpc-opts": {"grpc-service-name": "synthetic"}})
        text, warning = convert({"proxies": [node]}, "quanx")
        self.assertFalse(text.strip(), "gRPC was emitted as a different transport")
        self.assertIn("unsupported", warning.lower())

    def test_clash_json_version_key_does_not_trigger_legacy_ss_parser(self):
        fixture = {"proxies": [proxy("ss", password="synthetic", cipher="aes-128-gcm"), proxy("snell", psk="synthetic", version=3)]}
        out, _ = convert(json.dumps(fixture))
        self.assertEqual(len(out["proxies"]), 2)

    def test_hy2_all_alpn_and_udp_are_preserved(self):
        p = proxy("hysteria2", password="synthetic", alpn=["h3", "custom"], udp=False)
        out, _ = convert({"proxies": [p]})
        self.assertEqual(out["proxies"], [p])


if __name__ == "__main__":
    unittest.main(verbosity=2)
