#!/usr/bin/env python3
"""Focused C1/F2/H1 gates using the repository's production conversion drivers.

No build, download, service, or real subscription is used. Run the same script
against independently built Debug and Release drivers. Fixtures are synthetic.
Assertions express desired behavior; historical buggy output is not a golden.
Requires PyYAML. Optional Mihomo validates untouched successful full Clash bytes.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess

import yaml

try:
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
except (ImportError, ValueError, OSError):
    pass

UUID = "11111111-1111-4111-8111-111111111111"
TARGETS = ("clash", "surge", "singbox")


def b64(text):
    return base64.b64encode(text.encode()).decode()


def ss(name="Good", server="fixture.invalid", **options):
    return dict(name=name, type="ss", server=server, port=443,
                cipher="aes-128-gcm", password="synthetic", **options)


def uri(name="Good", server="fixture.invalid"):
    return "ss://" + b64("aes-128-gcm:synthetic") + "@" + server + ":443#" + name


def require(condition, message):
    # Do not use Python assert: the gate must also work under python -O.
    if not condition:
        raise AssertionError(message)


def parse_nodes(target, output, list_mode):
    if target == "clash":
        doc = yaml.safe_load(output)
        nodes = {p["name"]: p for p in doc["proxies"]}
        require(len(nodes) == len(doc["proxies"]), "duplicate emitted proxy names")
        return nodes
    if target == "singbox":
        doc = json.loads(output)
        proxies = [p for p in doc["outbounds"]
                   if p["type"] not in ("direct", "block", "dns", "selector", "urltest")]
        nodes = {p["tag"]: p for p in proxies}
        require(len(nodes) == len(proxies), "duplicate emitted proxy tags")
        return nodes
    nodes, section = {}, "Proxy" if list_mode else None
    for line in output.decode().splitlines():
        line = line.strip()
        if re.fullmatch(r"\[[^\]]+\]", line):
            section = line[1:-1]
        elif section == "Proxy" and "=" in line:
            name, value = (part.strip() for part in line.split("=", 1))
            if value not in ("direct", "reject"):
                require(name not in nodes, "duplicate emitted proxy name")
                nodes[name] = value
    return nodes


def dependency(target, node):
    if target == "clash":
        return node.get("dialer-proxy")
    if target == "singbox":
        return node.get("detour")
    match = re.search(r"(?:^|,)\s*underlying-proxy=([^,]+)", node)
    return match.group(1) if match else None


class Gate:
    def __init__(self, args):
        self.args, self.results = args, []
        self.root = args.artifacts.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def run(self, name, command, payload, check):
        if self.args.case_prefix and not any(name.startswith(prefix) for prefix in self.args.case_prefix):
            return
        raw = payload.encode() if isinstance(payload, str) else json.dumps(payload).encode()
        stem = self.root / name
        stem.with_suffix(".input").write_bytes(raw)
        item = dict(case=name, command=command, input_sha256=hashlib.sha256(raw).hexdigest())
        self.results.append(item)
        try:
            proc = subprocess.run(command, input=raw, capture_output=True, timeout=self.args.timeout)
            stem.with_suffix(".stdout").write_bytes(proc.stdout)
            stem.with_suffix(".stderr").write_bytes(proc.stderr)
            item.update(exit=proc.returncode, output_bytes=len(proc.stdout),
                        output_sha256=hashlib.sha256(proc.stdout).hexdigest())
            require(proc.returncode >= 0, f"driver terminated by signal {-proc.returncode}")
            check(proc, item, stem)
            item["passed"] = True
        except (AssertionError, KeyError, ValueError, TypeError, OSError, yaml.YAMLError, subprocess.TimeoutExpired) as error:
            item.update(passed=False, error=str(error))
        print(("PASS " if item["passed"] else "FAIL ") + name +
              (": " + item["error"] if "error" in item else ""), flush=True)

    def protocol(self, name, content, expected=None, reject=False):
        def check(proc, item, stem):
            require(proc.returncode == (2 if reject else 0), f"unexpected status {proc.returncode}")
            if reject:
                require(proc.stdout == b"", "invalid input emitted output")
                return
            doc = yaml.safe_load(proc.stdout)
            require(doc.get("proxies") == expected,
                    f"node semantics differ: expected {expected!r}, got {doc.get('proxies')!r}")
        self.run(name, [str(self.args.driver), "clash", "block", "list"],
                 content, check)

    def chain(self, name, documents, fail, list_mode=False, expected=None):
        request = dict(documents=documents, list=list_mode,
                       groups=[dict(name="Exit", members=["^(Entry|Leaf|Good)$"])])
        for target in TARGETS:
            label = name + "-" + target + ("-list" if list_mode else "-full")

            def check(proc, item, stem, target=target):
                metas = [line[len(b"CHAIN_META "):] for line in proc.stderr.splitlines()
                         if line.startswith(b"CHAIN_META ")]
                require(len(metas) == 1, "repository chain driver metadata missing")
                meta = json.loads(metas[0])
                item["meta"] = meta
                require(proc.returncode == (3 if fail else 0), f"unexpected status {proc.returncode}")
                require(meta["failed"] is fail, "chain failure flag mismatch")
                require(not meta["mutated"] and meta["before_export"] == meta["after_export"],
                        "export changed original nodes or source registry")
                if fail:
                    require(proc.stdout == b"", "incomplete chain emitted full configuration")
                    require(b"Conversion refused:" in proc.stderr, "missing refusal diagnostic")
                    return
                nodes = parse_nodes(target, proc.stdout, list_mode)
                require(set(nodes) == set(expected), f"expected nodes {list(expected)}, got {list(nodes)}")
                for name, upstream in expected.items():
                    require(dependency(target, nodes[name]) == upstream,
                            f"wrong or silently removed chain: {name} -> {upstream}")
                if target == "clash":
                    # Exact fields prevent the positive control from accepting a
                    # renamed node, changed endpoint, or altered credentials.
                    wanted = [ss(name, **({"dialer-proxy": upstream} if upstream else {}))
                              for name, upstream in expected.items()]
                    require(yaml.safe_load(proc.stdout)["proxies"] == wanted,
                            "successful Clash conversion changed source node semantics")
                    if not list_mode and self.args.mihomo:
                        home = self.root / "mihomo-home"
                        home.mkdir(exist_ok=True)
                        output_path = stem.with_suffix(".stdout")
                        checked = subprocess.run([str(self.args.mihomo), "-t", "-d", str(home),
                                                  "-f", str(output_path)], capture_output=True,
                                                 timeout=self.args.timeout)
                        stem.with_suffix(".mihomo.log").write_bytes(checked.stdout + checked.stderr)
                        item["mihomo_exit"] = checked.returncode
                        require(checked.returncode == 0, "Mihomo rejected unchanged full output")
                        require(hashlib.sha256(output_path.read_bytes()).hexdigest() == item["output_sha256"],
                                "validator input bytes changed")
            self.run(label, [str(self.args.chain_driver), target], request, check)


def c1(gate):
    independent = {"Entry": None, "Good": None}
    valid = [ss("Entry"), ss("Leaf", **{"dialer-proxy": "Entry"}), ss("Good")]
    for list_mode in (False, True):
        gate.chain("C1-valid-chain", [{"proxies": valid}], False, list_mode,
                   {"Entry": None, "Leaf": "Entry", "Good": None})
    malformed = {}
    for label, name in (("sequence", ["Leaf"]), ("map", {"nested": "Leaf"}),
                        ("null", None), ("missing", None), ("empty", "")):
        node = ss(name, **{"dialer-proxy": "Entry"})
        if label == "missing":
            del node["name"]
        malformed["name-" + label] = node
    for key in ("dialer-proxy", "underlying-proxy"):
        for label, value in (("sequence", ["Entry"]), ("map", {"name": "Entry"}), ("null", None)):
            malformed[key + "-" + label] = ss("Leaf", **{key: value})
    malformed["rejected-plugin"] = ss("Leaf", plugin="unsupported", **{"dialer-proxy": "Entry"})
    for label, node in malformed.items():
        documents = [{"proxies": [ss("Entry"), node, ss("Good")]}]
        gate.chain("C1-" + label, documents, True)
        gate.chain("C1-" + label, documents, False, True, independent)
    # An entirely rejected first OR last source must still contribute its failure.
    # Use both container names and null/missing names, which historically took
    # different parser branches. Do not coerce [Leaf] into a new source identity.
    for label in ("name-sequence", "name-map", "name-null", "name-missing"):
        invalid = {"proxies": [malformed[label]]}
        good = {"proxies": [ss("Entry"), ss("Good")]}
        for order, documents in (("first", [invalid, good]), ("last", [good, invalid])):
            name = "C1-all-rejected-" + label + "-" + order
            gate.chain(name, documents, True)
            gate.chain(name, documents, False, True, independent)
    yaml_document = yaml.safe_dump({"proxies": [ss("Entry"), malformed["name-sequence"], ss("Good")]},
                                   sort_keys=False)
    gate.chain("C1-yaml-name-sequence", [yaml_document], True)
    gate.chain("C1-yaml-name-sequence", [yaml_document], False, True, independent)
    # No declared chain: preserve existing independent successes. This guard
    # must not turn every parser rejection into a global full-output failure.
    for label, bad in (("sequence", ss(["Bad"])), ("map", ss({"name": "Bad"})),
                       ("whole-null", None), ("whole-sequence", ["Bad"])):
        gate.chain("C1-unchained-" + label, [{"proxies": [ss("Entry"), bad, ss("Good")]}],
                   False, expected=independent)


def f2(gate):
    one, two = uri(), uri("Second", "second.invalid")
    expected = [ss(), ss("Second", "second.invalid")]
    gate.protocol("F2-clean", one + "\n" + two, expected)
    for junk_name, junk in (("garbage", "garbage"), ("unknown", "novel://fixture.invalid/#unknown"),
                            ("invalid-known", "ss://malformed")):
        for position, lines in (("first", [junk, one, two]), ("middle", [one, junk, two]),
                                ("last", [one, two, junk])):
            body = "\n".join(lines)
            gate.protocol("F2-" + junk_name + "-" + position, body, expected)
            if junk_name == "garbage":
                gate.protocol("F2-base64-" + position, b64(body), expected)
                gate.protocol("F2-crlf-" + position, "# comment\r\n" + body.replace("\n", "\r\n") + "\r\n", expected)
    gate.protocol("F2-comment-garbage-first", "# comment\n\ngarbage\n" + one, [ss()])
    for remark, server in (("vnext-name", "vnext.invalid"), ("proxies:fragment", "fixture.invalid"),
                           ("trojan=fragment", "fixture.invalid")):
        content = uri(remark, server)
        for encoding, body in (("raw", content), ("base64", b64(content))):
            gate.protocol("F2-keyword-" + remark.split(":")[0].split("=")[0] + "-" + encoding,
                          # Existing exporter processRemark normalizes '=' to '-'.
                          body, [ss(remark.replace("=", "-"), server)])
    # The URI deliberately describes a DIFFERENT node from the real container:
    # same-name fixtures could hide a dispatch bug which parses only metadata.
    embedded, actual = uri("Embedded", "embedded.invalid"), ss("Container")
    yaml_proxy = yaml.safe_dump({"proxies": [actual]}, sort_keys=False)
    containers = {
        "json": json.dumps({"notes": embedded, "proxies": [actual]}),
        "yaml-comment": "# " + embedded + "\n" + yaml_proxy,
        "yaml-block": "notes: |\n  " + embedded + "\n" + yaml_proxy,
        "yaml-flow": "{notes: '" + embedded + "', proxies: [" + json.dumps(actual) + "]}",
        "ini": "[General]\n# " + embedded + "\nnotes = " + embedded +
               "\n[Proxy]\nContainer = ss, fixture.invalid, 443, encrypt-method=aes-128-gcm, password=synthetic\n",
    }
    for label, body in containers.items():
        gate.protocol("F2-container-" + label, body, [actual])
        gate.protocol("F2-container-base64-" + label, b64(body), [actual])
    for label, prefix in (("semicolon", "; comment\n"), ("slash", "// comment\n")):
        for encoding, body in (("raw", prefix + containers["ini"]), ("base64", b64(prefix + containers["ini"])),
                               ("double-base64", b64(b64(prefix + containers["ini"])))):
            gate.protocol("F2-ini-leading-" + label + "-" + encoding, body, [actual])
    for label, prefix in (("document", "---\n"), ("directive", "%YAML 1.2\n---\n"), ("inline-document", "--- ")):
        body = prefix + "|\n  " + embedded + "\n"
        for encoding, content in (("raw", body), ("base64", b64(body)), ("double-base64", b64(b64(body)))):
            gate.protocol("F2-yaml-scalar-" + label + "-" + encoding, content, reject=True)
    legacy = {"version": 1, "servers": [dict(remarks="Legacy", server="fixture.invalid",
               server_port=443, method="aes-128-gcm", password="synthetic")]}
    gate.protocol("F2-legacy-json", legacy, [ss("Legacy")])
    android = [dict(legacy["servers"][0], proxy_apps={"enabled": False})]
    gate.protocol("F2-legacy-android", android, [ss("Legacy")])
    for label, body in (("garbage", "garbage"), ("unknown", "novel://fixture.invalid/#unknown"),
                        ("comments", "# " + embedded), ("json-metadata", json.dumps({"notes": embedded})),
                        ("yaml-metadata", "notes: |\n  " + embedded + "\n"),
                        ("malformed-json-container", "{\n" + embedded + "\n"),
                        ("malformed-yaml-directive", "%YAML 1.3\n---\n|\n  " + embedded + "\n"),
                        ("yaml-root-literal", "|\n  " + embedded + "\n"),
                        ("yaml-root-folded", ">\n  " + embedded + "\n"),
                        ("yaml-root-tagged", "!!str |\n  " + embedded + "\n"),
                        ("yaml-sequence-metadata", "- notes: |\n    " + embedded + "\n"),
                        ("ini-uri-only", "[Proxy]\n" + embedded + "\n"),
                        ("ini-empty-real-nodes", "[General]\n" + embedded + "\n[Proxy]\nDIRECT = direct\n"),
                        ("ini-rejected-real-node", "[Proxy]\nBad = ss, fixture.invalid, 0, encrypt-method=aes-128-gcm, password=synthetic\n" + embedded + "\n")):
        gate.protocol("F2-negative-" + label, body, reject=True)
        gate.protocol("F2-negative-base64-" + label, b64(body), reject=True)


def v2ray(stream=None):
    outbound = dict(protocol="vmess", settings=dict(vnext=[dict(address="fixture.invalid", port=443,
                    users=[dict(id=UUID, alterId=0, security="auto")])]))
    if stream is not None:
        outbound["streamSettings"] = stream
    return {"outbounds": [outbound]}


def h1(gate):
    expected = dict(name="fixture.invalid:443", server="fixture.invalid", port=443,
                    type="vmess", uuid=UUID, alterId=0, cipher="auto", tls=False)
    gate.protocol("H1-valid-no-stream", v2ray(), [expected])
    gate.protocol("H1-valid-tcp", v2ray(dict(network="tcp", security="none", tcpSettings={})), [expected])
    ws = dict(network="ws", security="tls", wsSettings=dict(path="/synthetic",
              headers={"Host": "front.invalid", "Edge": "edge.invalid"}))
    ws_expected = dict(expected, tls=True, network="ws", **{"ws-opts": {"path": "/synthetic",
                          "headers": {"Host": "front.invalid", "Edge": "edge.invalid"}}})
    gate.protocol("H1-valid-ws", v2ray(ws), [ws_expected])
    malformed = {"outbounds-missing": {}}
    for label, value in (("null", None), ("object", {}), ("string", "bad"), ("number", 7),
                         ("empty", []), ("item-null", [None]), ("item-number", [7]), ("item-empty", [{}])):
        malformed["outbounds-" + label] = {"outbounds": value}
    for label, value in (("null", None), ("array", []), ("string", "bad"), ("empty", {})):
        malformed["settings-" + label] = {"outbounds": [{"protocol": "vmess", "settings": value}]}
    for label, value in (("null", None), ("object", {}), ("number", 7), ("empty", []),
                         ("item-null", [None]), ("item-empty", [{}])):
        malformed["vnext-" + label] = {"outbounds": [{"protocol": "vmess", "settings": {"vnext": value}}]}
    for label, value in (("missing", None), ("null", None), ("object", {}), ("number", 7)):
        body = v2ray()
        server = body["outbounds"][0]["settings"]["vnext"][0]
        if label == "missing":
            del server["users"]
        else:
            server["users"] = value
        malformed["users-" + label] = body
    # Nested explicit wrong types must never reach RapidJSON assertions. These
    # fixtures keep the rest of the document valid to isolate the target field.
    for label, value in (("null", None), ("array", []), ("string", "bad"), ("number", 7)):
        body = v2ray()
        body["outbounds"][0]["streamSettings"] = value
        if value is None:
            gate.protocol("H1-stream-null", body, [expected])
        else:
            malformed["stream-" + label] = body
        for key, network in (("tcpSettings", "tcp"), ("wsSettings", "ws")):
            body = v2ray({"network": network, key: value})
            if value is None:
                # Optional StreamConfig pointers use null as absent. Keep
                # these prior fixtures, correcting their over-strict oracle.
                gate.protocol("H1-" + key + "-null", body,
                              [dict(expected, **({"network": "ws", "ws-opts": {
                                  "path": "/", "headers": {"Host": "fixture.invalid"}}} if network == "ws" else {}))])
            else:
                malformed[key + "-" + label] = body
        malformed["ws-headers-" + label] = v2ray({"network": "ws", "wsSettings": {"headers": value}})
        malformed["tcp-header-" + label] = v2ray({"network": "tcp", "tcpSettings": {"header": value}})
        malformed["tcp-request-" + label] = v2ray({"network": "tcp", "tcpSettings":
                                                {"header": {"type": "http", "request": value}}})
    for label, value in (("null", None), ("object", {}), ("string", "/wrong-shape"), ("number", 7),
                         ("item-null", [None]), ("item-object", [{}])):
        malformed["tcp-request-path-" + label] = v2ray({"network": "tcp", "tcpSettings":
                                      {"header": {"type": "http", "request": {"path": value}}}})
    for label, body in malformed.items():
        gate.protocol("H1-" + label, body, reject=True)
    # Explicit repair decision: no unusable VMess user is emitted. This tightens
    # historical acceptance of empty/null users; it is not a compatibility oracle.
    for label, users in (("empty", []), ("item-null", [None]), ("item-empty", [{}]),
                         ("id-missing", [{"alterId": 0}]), ("id-empty", [{"id": ""}]),
                         ("id-number", [{"id": 7}]), ("id-null", [{"id": None}])):
        body = v2ray()
        body["outbounds"][0]["settings"]["vnext"][0]["users"] = users
        gate.protocol("H1-users-" + label, body, reject=True)
    multiple = v2ray()
    multiple["outbounds"][0]["settings"]["vnext"][0]["users"].append(
        dict(id="22222222-2222-4222-8222-222222222222", alterId=5, security="aes-128-gcm"))
    gate.protocol("H1-valid-first-of-multiple-users", multiple, [expected])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--driver", type=Path, help="repository protocol-convert executable")
    parser.add_argument("--chain-driver", type=Path, help="repository chain-convert executable")
    parser.add_argument("--mihomo", type=Path, help="optional independently verified Mihomo executable")
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--section", action="append", choices=("C1", "F2", "H1"),
                        help="repeat to select focused sections; default: all")
    parser.add_argument("--case-prefix", action="append", default=[],
                        help="repeat to run only named case prefixes within selected sections")
    parser.add_argument("--timeout", type=float, default=15)
    args = parser.parse_args()
    sections = args.section or ["C1", "F2", "H1"]
    if "C1" in sections and not args.chain_driver:
        parser.error("C1 requires --chain-driver")
    if set(sections) & {"F2", "H1"} and not args.driver:
        parser.error("F2/H1 require --driver")
    provenance = {}
    for key in ("driver", "chain_driver", "mihomo"):
        binary = getattr(args, key)
        if binary:
            binary = binary.resolve(strict=True)
            setattr(args, key, binary)
            provenance[key] = dict(path=str(binary), sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    if args.mihomo and provenance["mihomo"]["sha256"] != "9c397be7489538628fae781bc005e4c5b8cd7b0961b8bb2ca815c8150f193577":
        parser.error("Mihomo binary differs from the pinned v1.19.29 Linux amd64 fixture")
    gate = Gate(args)
    for name in dict.fromkeys(sections):
        {"C1": c1, "F2": f2, "H1": h1}[name](gate)
    if not gate.results:
        parser.error("no cases matched the selected sections and prefixes")
    summary = dict(cases=len(gate.results), passed=sum(r["passed"] for r in gate.results),
                   mihomo_checks=sum("mihomo_exit" in r for r in gate.results),
                   provenance=provenance, results=gate.results)
    (gate.root / "results.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
    print(f"{summary['passed']}/{summary['cases']} passed; "
          f"{summary['mihomo_checks']} unchanged full-output Mihomo checks")
    return int(summary["passed"] != summary["cases"])


if __name__ == "__main__":
    raise SystemExit(main())
