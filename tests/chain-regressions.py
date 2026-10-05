#!/usr/bin/env python3
"""Synthetic production-chain regressions; validation never rewrites export bytes."""
import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

import yaml


def ss(name, dependency=None, **options):
    node = dict(name=name, type="ss", server="fixture.invalid", port=443,
                cipher="aes-128-gcm", password="synthetic")
    if dependency is not None:
        node["dialer-proxy"] = dependency
    node.update(options)
    return node


def request(nodes, **options):
    result = dict(documents=[dict(proxies=nodes)], groups=[
        dict(name="Transit", members=[".*Entry$"]),
        dict(name="Exit", members=[".*Leaf$"]),
        dict(name="Protected", members=["[]REJECT"]),
    ])
    result.update(options)
    return result


def members_and_nodes(target, raw, list_mode=False):
    if target == "clash":
        config = yaml.safe_load(raw)
        nodes = {p["name"]: p for p in config.get("proxies", [])}
        groups = {g["name"]: g.get("proxies", []) for g in config.get("proxy-groups", [])}
        return config, nodes, groups
    if target == "singbox":
        config = json.loads(raw)
        outbounds = config.get("outbounds", [])
        nodes = {p["tag"]: p for p in outbounds if p["type"] not in ["selector", "urltest", "direct", "block", "dns"]}
        groups = {g["tag"]: g.get("outbounds", []) for g in outbounds if g["type"] in ["selector", "urltest"]}
        return config, nodes, groups
    nodes, groups, sections = {}, {}, {}
    section = "Proxy" if list_mode else None
    for line in raw.decode().splitlines():
        line = line.strip()
        if re.fullmatch(r"\[[^\]]+\]", line):
            section = line[1:-1]
            continue
        sections.setdefault(section, []).append(line)
        if " = " not in line:
            continue
        name, content = line.split(" = ", 1)
        if section == "Proxy":
            nodes[name] = content
        elif section == "Proxy Group":
            groups[name] = [p.strip() for p in content.split(",")[1:]]
    return sections, nodes, groups


def dependency_of(target, value):
    if target == "clash":
        return value.get("dialer-proxy")
    if target == "singbox":
        return value.get("detour")
    match = re.search(r"(?:^|,)\s*underlying-proxy=([^,]+)", value)
    return match.group(1) if match else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--mihomo", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    args = parser.parse_args()
    args.driver = args.driver.resolve()
    args.mihomo = args.mihomo.resolve()
    args.artifacts.mkdir(parents=True, exist_ok=True)
    expected_hash = "9c397be7489538628fae781bc005e4c5b8cd7b0961b8bb2ca815c8150f193577"
    assert hashlib.sha256(args.mihomo.read_bytes()).hexdigest() == expected_hash, "Mihomo must be the pinned v1.19.29 executable"
    version = subprocess.run([str(args.mihomo), "-v"], capture_output=True, check=True).stdout.decode()
    assert "v1.19.29" in version
    (args.artifacts / "mihomo-version.txt").write_text(version)
    home = args.artifacts / "mihomo-home"
    home.mkdir(exist_ok=True)
    results = []

    def run(case, target, req, *, fail=False, expected=None, absent=(), present=(), filtered=(), rejected=(), prior_failures=None, check_client=True):
        label = f"{case}-{target}"
        (args.artifacts / f"{label}.request.json").write_text(json.dumps(req, ensure_ascii=False, indent=2))
        proc = subprocess.run([str(args.driver), target], input=json.dumps(req, ensure_ascii=False).encode(), capture_output=True)
        suffix = {"clash": ".yaml", "surge": ".ini", "singbox": ".json"}[target]
        path = args.artifacts / f"{label}{suffix}"
        # These are the exact stdout bytes. PyYAML is used to inspect only.
        path.write_bytes(proc.stdout)
        (args.artifacts / f"{label}.stderr").write_bytes(proc.stderr)
        item = dict(case=case, target=target, exit=proc.returncode, output=str(path),
                    bytes=len(proc.stdout), output_sha256=hashlib.sha256(proc.stdout).hexdigest())
        results.append(item)
        try:
            metas = [line[len(b"CHAIN_META "):] for line in proc.stderr.splitlines() if line.startswith(b"CHAIN_META ")]
            assert len(metas) == 1, "driver did not report exactly one metadata object"
            meta = json.loads(metas[0])
            item["meta"] = meta
            assert proc.returncode == (3 if fail else 0), f"unexpected driver status {proc.returncode}"
            assert meta["failed"] is fail, "full failure flag disagrees with expected behavior"
            assert not meta["mutated"], "export mutated original nodes or source registry"
            assert all(not p["mutated"] for p in meta["pre_exports"]), "earlier target export mutated source state"
            if prior_failures is not None:
                assert [p["failed"] for p in meta["pre_exports"]] == prior_failures, "prior export statuses did not exercise the intended failure/success sequence"
            assert meta["before_export"] == meta["after_export"], "export changed request-local source state"
            records = meta["filtered"]["records"]
            for name in filtered:
                assert any(r["name"] == name and r["state"] == 2 for r in records), f"{name} missing filtered tombstone"
            for name in rejected:
                assert any(r["name"] == name and r["state"] == 0 for r in records), f"{name} missing parser-rejection tombstone"
            if fail:
                assert proc.stdout == b"", "incomplete full chain emitted a partial/DIRECT policy configuration"
                assert b"Conversion refused:" in proc.stderr
            else:
                assert proc.stdout, "successful conversion returned empty output"
                config, nodes, groups = members_and_nodes(target, proc.stdout, req.get("list", False))
                for leaf, upstream in (expected or {}).items():
                    assert leaf in nodes, f"missing chain member {leaf}; available: {list(nodes)}"
                    assert dependency_of(target, nodes[leaf]) == upstream, f"{leaf} did not reference final identity {upstream}"
                    assert upstream in nodes or upstream in groups or upstream in ("DIRECT", "REJECT"), f"unresolved emitted dependency {upstream}"
                for name in absent:
                    assert name not in nodes, f"omitted/invalid chain member {name} leaked into output"
                for name in present:
                    assert name in nodes, f"independent valid member {name} was incorrectly removed"
                for name, node in nodes.items():
                    upstream = dependency_of(target, node)
                    assert not upstream or upstream in nodes or upstream in groups or upstream in ("DIRECT", "REJECT"), f"dangling output reference: {name} -> {upstream}"
                if not req.get("list", False):
                    assert "Exit" in groups or "Exit" in nodes, "actual rule target missing"
                    for leaf, upstream in (expected or {}).items():
                        if leaf.endswith("Leaf"):
                            assert leaf in groups.get("Exit", []), "rule target group no longer selects the valid leaf"
                        if upstream == "Transit":
                            entry = "[SS] Entry" if req.get("append") else "Entry"
                            nested = next((g["members"] for g in req["groups"] if g["name"] == "Transit"), []) == ["[]Inner"]
                            if nested:
                                assert groups["Transit"] == ["Inner"] and groups["Inner"] == [entry], "nested chain group no longer reaches Entry"
                            else:
                                assert groups["Transit"] == [entry], "stable upstream group no longer selects Entry"
                    if target == "surge":
                        assert "FINAL,Exit" in config["Rule"], "full Surge rule was lost"
                        assert nodes.get("Protected") == "reject", "explicit []REJECT became DIRECT"
                    elif target == "clash":
                        assert "MATCH,Exit" in config["rules"], "full Clash rule was lost"
                        assert groups["Protected"] == ["REJECT"], "explicit []REJECT became DIRECT"
                    else:
                        assert config["route"]["final"] == "Exit", "full sing-box route was lost"
                        assert groups["Protected"] == ["REJECT"], "explicit []REJECT became DIRECT"
                    if target == "clash" and check_client:
                        checked = subprocess.run([str(args.mihomo), "-t", "-d", str(home.resolve()), "-f", str(path.resolve())], capture_output=True)
                        (args.artifacts / f"{label}.mihomo.log").write_bytes(checked.stdout + checked.stderr)
                        item["mihomo_exit"] = checked.returncode
                        assert checked.returncode == 0, "Mihomo rejected the unmodified full converter output"
                        assert hashlib.sha256(path.read_bytes()).hexdigest() == item["output_sha256"], "validator input bytes changed"
            item["passed"] = True
        except (AssertionError, KeyError, ValueError, TypeError) as error:
            item["passed"] = False
            item["error"] = str(error)
        print(("PASS " if item["passed"] else "FAIL ") + label + (": " + item["error"] if "error" in item else ""), flush=True)
        return proc.stdout, item

    targets = ("clash", "surge", "singbox")
    for target in targets:
        prefix = "[SS] "
        run("r1-stable-group-append", target, request([ss("Entry"), ss("Leaf", "Transit")], append=True), expected={prefix + "Leaf": "Transit"})
        run("r1-source-node-append", target, request([ss("Upstream"), ss("Leaf", "Upstream")], append=True), expected={prefix + "Leaf": prefix + "Upstream"})
        run("r2-remove-emoji", target, request([ss("🇺🇸 Upstream"), ss("Leaf", "🇺🇸 Upstream")], remove_emoji=True), expected={"Leaf": "Upstream"})
        run("r2-regex-rename", target, request([ss("Upstream"), ss("Leaf", "Upstream")], rename=[["^Upstream$", "Renamed"]]), expected={"Leaf": "Renamed"})
        run("r2-add-emoji", target, request([ss("Upstream"), ss("Leaf", "Upstream")], add_emoji=True, emoji=[["^Upstream$", "🇺🇸"]]), expected={"Leaf": "🇺🇸 Upstream"})
        run("r2-legacy-underlying", target, request([ss("🇺🇸 Upstream"), dict(ss("Leaf"), **{"underlying-proxy": "🇺🇸 Upstream"})], remove_emoji=True), expected={"Leaf": "Upstream"})
        run("normalized-distinct-source-identities", target, request([ss("Upstream"), ss("🇺🇸 Upstream"), ss("Leaf", "🇺🇸 Upstream")], remove_emoji=True), expected={"Leaf": "Upstream 2"})
        run("normalized-alias-cannot-rescue-missing-source", target, request([ss("Other"), ss("Leaf", "Missing")], rename=[["^Other$", "Missing"]]), fail=True)
        run("unknown-upstream", target, request([ss("Leaf", "Missing"), ss("Good")]), fail=True)
        run("parser-plugin-rejected-upstream", target, request([ss("Upstream", plugin="unknown-plugin"), ss("Leaf", "Upstream"), ss("Good")]), fail=True, rejected=["Upstream"])
        run("parser-rejected-chained-leaf", target, request([ss("Upstream"), ss("Leaf", "Upstream", plugin="unknown-plugin"), ss("Good")]), fail=True, rejected=["Leaf"])
        run("actual-exclude-filter", target, request([ss("Upstream"), ss("Leaf", "Upstream"), ss("Good")], exclude=["^Upstream$"]), fail=True, filtered=["Upstream"])
        run("actual-include-filter", target, request([ss("Upstream"), ss("Leaf", "Upstream"), ss("Good")], include=["^(Leaf|Good)$"]), fail=True, filtered=["Upstream"])
        run("filtered-chained-leaf", target, request([ss("Upstream"), ss("Leaf", "Upstream"), ss("Good")], exclude=["^Leaf$"]), fail=True, filtered=["Leaf"])
        run("referenced-group-empty-after-filter", target, request([ss("Entry"), ss("Leaf", "Transit")], exclude=["^Entry$"]), fail=True, filtered=["Entry"])
        run("simulate-script-erase-boundary", target, request([ss("Upstream"), ss("Leaf", "Upstream"), ss("Good")], simulate_filter_erase=["Upstream"]), fail=True, filtered=["Upstream"])
        run("transitive-omission", target, request([ss("Upstream", plugin="unknown-plugin"), ss("Middle", "Upstream"), ss("Leaf", "Middle"), ss("Good")]), fail=True, rejected=["Upstream"])
        run("transitive-list-pruning", target, request([ss("Upstream", plugin="unknown-plugin"), ss("Middle", "Upstream"), ss("Leaf", "Middle"), ss("Good")], list=True), absent=["Upstream", "Middle", "Leaf"], present=["Good"], rejected=["Upstream"])
        run("unverified-external-group-list", target, request([ss("Entry"), ss("Leaf", "Transit")], list=True), absent=["Leaf"], present=["Entry"])
        run("duplicate-original-name", target, request([ss("Upstream"), ss("Upstream"), ss("Leaf", "Upstream")]), fail=True)
        run("duplicate-original-includes-parser-reject", target, request([ss("Upstream", plugin="unknown-plugin"), ss("Upstream"), ss("Leaf", "Upstream")]), fail=True, rejected=["Upstream"])
        run("duplicate-unreferenced-original-preserves-suffixes", target, request([ss("Other"), ss("Other"), ss("Upstream"), ss("Leaf", "Upstream")]), expected={"Leaf": "Upstream"}, present=["Other", "Other 2"])
        run("source-group-collision", target, request([ss("Transit"), ss("Leaf", "Transit")]), fail=True)
        run("renamed-source-group-collision", target, request([ss("Upstream"), ss("Leaf", "Upstream")], rename=[["^Upstream$", "Transit"]]), fail=True)
        run("cycle", target, request([ss("Upstream", "Leaf"), ss("Leaf", "Upstream")]), fail=True)
        run("merged-documents-valid", target, request([], documents=[dict(proxies=[ss("Upstream")]), dict(proxies=[ss("Leaf", "Upstream")])]), expected={"Leaf": "Upstream"})
        _, merged = run("merged-all-rejected-source", target, request([], documents=[dict(proxies=[ss("Upstream", plugin="unknown-plugin")]), dict(proxies=[ss("Leaf", "Upstream"), ss("Good")])]), fail=True, rejected=["Upstream"])
        if merged.get("passed"):
            assert merged["meta"]["documents"][0]["parsed"] == 0
            assert merged["meta"]["documents"][1]["parsed"] == 2
        run("merged-duplicate-original", target, request([], documents=[dict(proxies=[ss("Upstream")]), dict(proxies=[ss("Upstream"), ss("Leaf", "Upstream")])]), fail=True)
        run("explicit-reject-preserved", target, request([ss("Leaf")]))
        omitted = (dict(name="Upstream", type="snell", server="fixture.invalid", port=443, psk="synthetic", version=4)
                   if target == "clash" else dict(name="Upstream", type="tuic", server="fixture.invalid", port=443, token="synthetic"))
        run("target-omission-transitive", target, request([omitted, ss("Middle", "Upstream"), ss("Leaf", "Middle"), ss("Good")]), fail=True)
        run("target-omission-list", target, request([omitted, ss("Middle", "Upstream"), ss("Leaf", "Middle"), ss("Good")], list=True), absent=["Upstream", "Middle", "Leaf"], present=["Good"])
        seq_request = request([ss("Upstream"), ss("Leaf", "Upstream")], append=True)
        control, _ = run("sequence-control", target, seq_request, expected={prefix + "Leaf": prefix + "Upstream"})
        sequence = copy.deepcopy(seq_request)
        sequence["pre_exports"] = ["clash", "singbox", "surge", target, target]
        output, seq = run("sequence-repeat-no-mutation", target, sequence, expected={prefix + "Leaf": prefix + "Upstream"})
        if seq.get("passed") and control != output:
            seq["passed"] = False
            seq["error"] = "cross-target/repeated export differs from fresh control bytes"

    for target in ("clash", "singbox"):
        leaf = dict(name="Leaf", type="anytls", server="leaf.invalid", port=443,
                    password="synthetic", **{"dialer-proxy": "🇺🇸 Upstream"})
        run("anytls-rename-chain", target, request([ss("🇺🇸 Upstream"), leaf], remove_emoji=True), expected={"Leaf": "Upstream"})

    target_local = request([dict(name="Upstream", type="tuic", server="fixture.invalid", port=443, token="synthetic"), ss("Leaf", "Upstream")])
    fresh, _ = run("target-local-failure-control", "clash", target_local, expected={"Leaf": "Upstream"})
    target_local["pre_exports"] = ["singbox", "clash", "surge", "clash"]
    repeated, result = run("target-local-failure-does-not-poison-other-export", "clash", target_local, expected={"Leaf": "Upstream"}, prior_failures=[True, False, True, False])
    if result.get("passed") and repeated != fresh:
        result["passed"] = False
        result["error"] = "target-local rejection changed a later supported export"

    for target in targets:
        raw_up = "ss://YWVzLTEyOC1nY206cA@fixture.invalid:443#Upstream"
        for key in ("dialer-proxy", "underlying-proxy"):
            for fragment in ("#Leaf", ""):
                body = raw_up + "\ntuic://token@fixture.invalid:443?" + key + "=Upstream&congestion-controller=invalid" + fragment
                for encoding, source in (("raw", body), ("base64", base64.b64encode(body.encode()).decode())):
                    label = "rejected-tuic-chain-" + key + ("-named" if fragment else "-default") + "-" + encoding
                    run(label, target, request([], documents=[source, {"proxies": [ss("Good")]}]), fail=True)
                    run(label + "-list", target, request([], documents=[source, {"proxies": [ss("Good")]}], list=True), present=["Good"], absent=["Leaf"])
        run("legacy-uri-lost-chain-prunes-dependents", target,
            request([], documents=["trojan://p@fixture.invalid:443?dialer-proxy=Upstream#Bad", {"proxies": [ss("Leaf", "Bad"), ss("Good")]}], list=True), present=["Good"], absent=["Bad", "Leaf"])
        for label, uri, name in (("legacy-plus", "trojan://p@fixture.invalid:443#A+B", "A B"),
                                 ("empty-fragment", "ss://YWVzLTEyOC1nY206cA@fixture.invalid:443#", "fixture.invalid:443")):
            run("accepted-source-name-" + label, target, request([], documents=[uri, {"proxies": [ss("Leaf", name)]}]), expected={"Leaf": name})
        run("comments-not-source-identities", target, request([], documents=["#Upstream\n" + raw_up, {"proxies": [ss("Leaf", "Upstream")]}]), expected={"Leaf": "Upstream"})
        run("surge-builtins-not-proxy-tombstones", target, request([], documents=["[Proxy]\nDIRECT = direct\nREJECT = reject\nEntry = ss, fixture.invalid, 443, encrypt-method=aes-128-gcm, password=p\n", {"proxies": [ss("Leaf", "DIRECT")]}]), expected={"Leaf": "DIRECT"})
        nested = request([ss("Entry"), ss("Leaf", "Transit")])
        nested["groups"][0]["members"] = ["[]Inner"]
        nested["groups"].append(dict(name="Inner", members=["^Entry$"]))
        run("nested-chain-group-valid", target, nested, expected={"Leaf": "Transit"})
        nested["exclude"] = ["^Entry$"]
        run("nested-chain-group-empty", target, nested, fail=True)
        cyclic = request([ss("Leaf", "Transit")])
        cyclic["groups"][0]["members"] = ["^Leaf$"]
        run("source-group-cycle", target, cyclic, fail=True)
        old_record = dict(remarks="Transit", server="fixture.invalid", server_port=0, method="aes-128-gcm", password="p")
        sources = {
            "ss": {"version": 1, "servers": [old_record]},
            "ss-android": [dict(old_record, proxy_apps={"enabled": False})],
            "ssr": {"serverSubscribes": [], "configs": [dict(old_record, group="g", protocol="origin", obfs="plain")]},
            "sstap": {"idInUse": 0, "configs": [dict(old_record, group="g", type=6)]},
            "netch": {"ModeFileNameType": False, "Server": [dict(Type="SS", Remark="Transit", Hostname="fixture.invalid", Port=0, EncryptMethod="aes-128-gcm", Password="p")]},
            "vmess": {"uiItem": {}, "subItem": [], "vmess": [dict(remarks="Transit", address="fixture.invalid", port=0, id="00000000-0000-4000-8000-000000000001")]},
            "ssd": "ssd://" + base64.b64encode(json.dumps({"airport": "fixture", "port": 443, "encryption": "aes-128-gcm", "password": "p", "servers": [dict(remarks="Transit", server="fixture.invalid", port=0)]}).encode()).decode(),
        }
        sources["netch-uri"] = "Netch://" + base64.b64encode(json.dumps(sources["netch"]["Server"][0]).encode()).decode()
        sources["vmess-uri"] = "vmess://" + base64.b64encode(json.dumps({"v": "2", "ps": "Transit", "add": "fixture.invalid", "port": "0", "id": "00000000-0000-4000-8000-000000000001", "net": "tcp"}).encode()).decode()
        sources["ssr-uri"] = "ssr://" + base64.b64encode(b"fixture.invalid:0:origin:aes-128-cfb:plain:cA/?remarks=VHJhbnNpdA").decode()
        for format_name, source in sources.items():
            run("legacy-rejected-source-group-collision-" + format_name, target, request([], documents=[source, {"proxies": [ss("Entry"), ss("Leaf", "Transit")]}]), fail=True, rejected=["Transit"])

    for label, address in (("mapped", "::ffff:192.0.2.1"), ("numeric-full", "1:2:3:4:5:6:7:8")):
        uri = "ss://YWVzLTEyOC1nY206cA@[" + address + "]:443#Upstream"
        run("raw-full-ipv6-" + label, "clash", request([], documents=[uri, {"proxies": [ss("Leaf", "Upstream")]}]), expected={"Leaf": "Upstream"})
    run("raw-full-ss-none", "clash", request([ss("Upstream", cipher="none"), ss("Leaf", "Upstream")]), expected={"Leaf": "Upstream"})

    base_only = request([ss("Entry"), ss("Leaf", "Transit")])
    base_only["groups"] = [g for g in base_only["groups"] if g["name"] != "Transit"]
    base_only["bases"] = dict(
        clash="mode: rule\nproxy-groups:\n  - name: Transit\n    type: select\n    proxies: [Entry]\nrules: ['MATCH,Exit']\n",
        surge="[Proxy]\n[Proxy Group]\nTransit = select,Entry\n[Rule]\nFINAL,Exit\n",
        singbox=json.dumps(dict(outbounds=[dict(type="selector", tag="Transit", outbounds=["Entry"])], route=dict(final="Exit"))),
    )
    run("actual-clash-base-group", "clash", base_only, expected={"Leaf": "Transit"})
    run("removed-surge-base-group", "surge", base_only, fail=True)
    run("removed-singbox-base-group", "singbox", base_only, fail=True)

    summary = dict(cases=len(results), passed=sum(x["passed"] for x in results),
                   mihomo_checks=sum("mihomo_exit" in x for x in results),
                   mihomo_sha256=expected_hash, results=results)
    (args.artifacts / "results.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"{summary['passed']}/{summary['cases']} chain regressions passed; {summary['mihomo_checks']} direct raw full-output Mihomo checks")
    return int(summary["passed"] != summary["cases"])


if __name__ == "__main__":
    raise SystemExit(main())
