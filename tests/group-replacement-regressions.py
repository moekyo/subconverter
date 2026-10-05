#!/usr/bin/env python3
"""R3 independent final-group regressions against the real chain-convert driver.

No downloads/builds or production edits. Requires Python 3 + PyYAML and the
caller-supplied repository tests/chain-convert executable. Pin-verified Mihomo
runs on raw full/new converter bytes: -t then loopback /proxies only. Legacy
full output and provider-list output receive structural checks only; neither
is passed off as a runnable modern Mihomo full configuration.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time
from urllib.request import ProxyHandler, Request, build_opener
from urllib.error import URLError

import yaml

PIN = '9c397be7489538628fae781bc005e4c5b8cd7b0961b8bb2ca815c8150f193577'


def must(ok, message):
    if not ok:
        raise AssertionError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def selected(name, members, **fields):
    return dict(name=name, type='select', proxies=members, **fields)


def generated(name, members):
    return {'name': name, 'members': members}


def ss(name, dependency=None):
    result = {'name': name, 'type': 'ss', 'server': '127.0.0.1', 'port': 9,
              'cipher': 'aes-128-gcm', 'password': 'synthetic-offline-only'}
    if dependency:
        result['dialer-proxy'] = dependency
    return result


def corpus():
    t = selected('Transit', ['Entry'])
    e = selected('Exit', ['Leaf'])
    tg = generated('Transit', ['[]Entry'])
    eg = generated('Exit', ['^Leaf$'])
    cases = []

    def add(name, base, custom, expected, *, fail=False, runtime=True, chained=True):
        cases.append(dict(name=name, base=base, custom=custom, expected=expected,
                          fail=fail, runtime=runtime, chained=chained))

    for pattern, tag in [('^Absent$', 'auto-empty'), ('^Leaf$', 'auto-self')]:
        base = [dict(name='Transit', type='select', **{'include-all-proxies': True, 'filter': pattern})]
        add('generated-entry-replaces-' + tag, base, [tg, eg], [t, e])
    add('generated-entry-replaces-static-self', [selected('Transit', ['Leaf'])], [tg, eg], [t, e])
    rich = dict(name='Transit', type='url-test', proxies=['Leaf'], url='http://127.0.0.1:9/never',
                interval=999999, lazy=True, tolerance=51, **{'include-all-proxies': True,
                'filter': '^Leaf$', 'exclude-filter': '^Entry$', 'exclude-type': 'Direct',
                'disable-udp': True, 'icon': 'old-icon', 'hidden': True, 'use': []})
    add('complete-node-replacement-removes-old-fields', [rich], [tg, eg], [t, e], runtime=False)
    before = selected('Before', ['REJECT', 'DIRECT'], **{'disable-udp': True, 'hidden': True})
    after = selected('After', ['DIRECT', 'REJECT'], icon='untouched-icon')
    tail = selected('Tail', ['DIRECT'])
    add('replacement-keeps-base-position-and-unrelated-groups',
        [before, selected('Transit', ['Leaf'], **{'include-all-proxies': True, 'filter': '^Leaf$'}), after],
        [eg, tg, generated('Tail', ['[]DIRECT'])], [before, t, after, e, tail])
    add('unmodified-base-content-and-order', [before, t, after, e], [], [before, t, after, e])
    anonymous = {'type': 'select', 'proxies': ['DIRECT'], 'hidden': True}
    add('nameless-base-mapping-preserved-without-exception', [anonymous], [tg, eg],
        [anonymous, t, e], runtime=False)
    add('generated-only-duplicates-last-valid-wins', [],
        [generated('Transit', ['[]Leaf']), eg, tg], [t, e])
    add('generated-only-three-duplicates-last-valid-wins', [],
        [generated('Transit', ['[]Leaf']), eg, generated('Transit', ['^Absent$']), tg], [t, e])
    add('base-and-generated-duplicates-last-valid-wins', [selected('Transit', ['Leaf'])],
        [generated('Transit', ['[]Leaf']), eg, tg], [t, e])
    add('generated-empty-then-valid-clears-empty-state', [],
        [generated('Transit', ['^Absent$']), eg, tg], [t, e])
    add('generated-valid-then-empty-rejected', [],
        [tg, eg, generated('Transit', ['^Absent$'])], None, fail=True)
    add('generated-valid-then-self-rejected', [],
        [tg, eg, generated('Transit', ['[]Leaf'])], None, fail=True)
    add('generated-valid-then-direct-explicit-wins', [],
        [generated('Transit', ['[]Leaf']), eg, generated('Transit', ['[]DIRECT'])],
        [selected('Transit', ['DIRECT']), e])
    for members, tag in [(['[]Leaf'], 'leaf-cycle'), (['[]Transit'], 'group-self-cycle'),
                         (['[]Missing'], 'missing-member'), (['^Absent$'], 'empty')]:
        add('dangerous-generated-overrides-safe-base-' + tag, [t],
            [generated('Transit', members), eg], None, fail=True)
    add('duplicate-base-name-rejected', [t, selected('Transit', ['DIRECT'])], [eg], None, fail=True)
    add('duplicate-base-name-not-rescued-by-generated', [t, selected('Transit', ['Leaf'])],
        [tg, eg], None, fail=True)
    add('nested-final-graph-replaces-both-base-groups',
        [selected('Transit', ['Leaf']), selected('Inner', ['Leaf'])],
        [generated('Transit', ['[]Inner']), generated('Inner', ['[]Entry']), eg],
        [selected('Transit', ['Inner']), selected('Inner', ['Entry']), e])
    add('no-chain-still-obeys-generated-last-wins', [],
        [generated('Transit', ['[]Leaf']), eg, tg], [t, e], chained=False)
    return cases


def reserve_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def make_request(case, field_name, list_mode, port):
    key = 'proxy-groups' if field_name == 'new' else 'Proxy Group'
    base = {'mode': 'rule', 'port': 0, 'socks-port': 0, 'mixed-port': 0,
            'redir-port': 0, 'tproxy-port': 0, 'allow-lan': False,
            'bind-address': '127.0.0.1', 'external-controller': f'127.0.0.1:{port}',
            'log-level': 'silent', 'dns': {'enable': False}, 'tun': {'enable': False},
            'listeners': [], 'profile': {'store-selected': False, 'store-fake-ip': False},
            'geo-auto-update': False, 'find-process-mode': 'off', key: case['base'],
            'rules': ['MATCH,Exit']}
    return {'documents': [yaml.safe_dump({'proxies': [ss('Entry'), ss('Leaf', 'Transit' if case['chained'] else None)]}, sort_keys=False)],
            'groups': case['custom'], 'bases': {'clash': yaml.safe_dump(base, sort_keys=False)},
            'clash_new_field_name': field_name == 'new', 'list': list_mode}


def runtime_safe(parsed, port):
    must(parsed.get('external-controller') == f'127.0.0.1:{port}', 'controller changed')
    for name in ['port', 'socks-port', 'mixed-port', 'redir-port', 'tproxy-port']:
        must(parsed.get(name) == 0, f'{name} must be disabled')
    must(parsed.get('listeners') == [], 'custom inbounds prohibited')
    must(parsed.get('tun', {}).get('enable') is False, 'TUN prohibited')
    must(parsed.get('dns', {}).get('enable') is False, 'DNS listener prohibited')
    must(not parsed.get('proxy-providers') and not parsed.get('rule-providers'), 'providers prohibited')
    must(not parsed.get('external-ui') and not parsed.get('external-ui-url'), 'external UI prohibited')
    must(parsed.get('rules') == ['MATCH,Exit'], 'only static MATCH rule permitted')
    for group in parsed['proxy-groups']:
        must(group.get('type') == 'select', 'active or unknown group type prohibited')
        must(not set(group).intersection({'url', 'interval', 'health-check', 'use'}), 'health checks/providers prohibited')
    for proxy in parsed['proxies']:
        must(proxy['type'] == 'ss' and proxy['server'] == '127.0.0.1' and proxy['port'] == 9, "Invariant failed: proxy['type'] == 'ss' and proxy['server'] == '127.0.0.1' and proxy['port'] == 9")
        must(not proxy.get('plugin'), 'plugins prohibited')


def check_core(args, case, output, parsed, port, record):
    runtime_safe(parsed, port)
    before = sha(output.read_bytes())
    home = output.parent / (output.stem + '-home')
    home.mkdir()
    check = subprocess.run([str(args.mihomo), '-t', '-d', str(home), '-f', str(output)],
                           capture_output=True, timeout=20)
    output.with_suffix('.mihomo-test.log').write_bytes(check.stdout + check.stderr)
    record['mihomo_test_exit'] = check.returncode
    must(sha(output.read_bytes()) == before, '-t changed raw converter output')
    must(check.returncode == 0, 'Mihomo -t rejected raw full output')
    log = output.with_suffix('.mihomo-runtime.log')
    process = None
    opener = build_opener(ProxyHandler({}))
    payload = None
    try:
        with log.open('wb') as sink:
            process = subprocess.Popen([str(args.mihomo), '-d', str(home), '-f', str(output)],
                                       stdout=sink, stderr=subprocess.STDOUT, start_new_session=True)
            record['runtime_pid'] = process.pid
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                must(process.poll() is None, f'Mihomo stopped before /proxies ({process.returncode})')
                try:
                    with opener.open(Request(f'http://127.0.0.1:{port}/proxies', method='GET'), timeout=.5) as reply:
                        payload = json.load(reply)
                    break
                except (URLError, TimeoutError, ConnectionError, json.JSONDecodeError):
                    time.sleep(.04)
            must(payload is not None, 'loopback /proxies was unavailable')
            output.with_suffix('.proxies.json').write_text(json.dumps(payload, ensure_ascii=False, indent=2))
            got = {g['name']: payload['proxies'].get(g['name'], {}).get('all') for g in case['expected']}
            wanted = {g['name']: g['proxies'] for g in case['expected']}
            record['runtime_members'] = got
            record['expected_runtime_members'] = wanted
            record['runtime_members_correct'] = got == wanted
            record['runtime_group_types'] = {g['name']: payload['proxies'].get(g['name'], {}).get('type') for g in case['expected']}
            must(got == wanted, f'actual /proxies groups differ: {got!r} != {wanted!r}')
            must(all(t == 'Selector' for t in record['runtime_group_types'].values()), 'runtime group type mismatch')
    finally:
        if process is not None:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=3)
            record['runtime_reaped'] = process.poll() is not None
            record['runtime_exit'] = process.returncode
        record['unchanged_after_runtime'] = sha(output.read_bytes()) == before
        must(record['unchanged_after_runtime'], 'runtime changed raw converter output')


def run_case(args, case, field_name, list_mode):
    label = case['name'] + '-' + field_name + ('-list' if list_mode else '-full')
    request = make_request(case, field_name, list_mode, reserve_port())
    base = yaml.safe_load(request['bases']['clash'])
    port = int(base['external-controller'].rsplit(':', 1)[1])
    stem = args.out / label
    stem.with_suffix('.request.json').write_text(json.dumps(request, ensure_ascii=False, indent=2))
    proc = subprocess.run([str(args.driver), 'clash'], input=json.dumps(request).encode(),
                          capture_output=True, timeout=20)
    output = stem.with_suffix('.yaml')
    output.write_bytes(proc.stdout)
    stem.with_suffix('.stderr').write_bytes(proc.stderr)
    fail = case['fail'] and not list_mode
    record = {'case': label, 'expected_exit': 3 if fail else 0, 'exit': proc.returncode,
              'output_bytes': len(proc.stdout), 'raw_output_sha256': sha(proc.stdout), 'errors': []}
    def require(check, message):
        if not check:
            record['errors'].append(message)
    require(proc.returncode == record['expected_exit'], 'unexpected conversion exit')
    metas = [line[len(b'CHAIN_META '):] for line in proc.stderr.splitlines() if line.startswith(b'CHAIN_META ')]
    if len(metas) == 1:
        meta = json.loads(metas[0])
        record['meta'] = meta
        require(meta['failed'] is fail, 'failure metadata mismatch')
        require(not meta['mutated'] and meta['before_export'] == meta['after_export'], 'source identity or input nodes mutated')
    else:
        require(False, 'missing chain driver metadata')
    if fail:
        require(proc.stdout == b'', 'refused full conversion emitted bytes')
    elif proc.returncode == 0:
        try:
            parsed = yaml.safe_load(proc.stdout)
            if list_mode:
                require(set(parsed) == {'proxies'}, 'list output must be only provider proxies')
                expected_names = ['Entry'] if case['chained'] else ['Entry', 'Leaf']
                require([p['name'] for p in parsed['proxies']] == expected_names, 'list must drop unresolved group-dependent node')
                require(all('dialer-proxy' not in p for p in parsed['proxies']), 'list has dangling group dependency')
            else:
                group_key = 'proxy-groups' if field_name == 'new' else 'Proxy Group'
                proxy_key = 'proxies' if field_name == 'new' else 'Proxy'
                other_group_key = 'Proxy Group' if field_name == 'new' else 'proxy-groups'
                other_proxy_key = 'Proxy' if field_name == 'new' else 'proxies'
                actual_groups = parsed.get(group_key)
                record['emitted_groups'] = actual_groups
                record['expected_groups'] = case['expected']
                require(actual_groups == case['expected'], 'full final group sequence differs (name/type/members/fields/order)')
                require(other_group_key not in parsed and other_proxy_key not in parsed, 'wrong field-name family leaked')
                require([p['name'] for p in parsed.get(proxy_key, [])] == ['Entry', 'Leaf'], 'full proxy list missing node')
                leaf = next((p for p in parsed.get(proxy_key, []) if p['name'] == 'Leaf'), {})
                require(leaf.get('dialer-proxy') == ('Transit' if case['chained'] else None), 'Leaf dependency changed')
                require(parsed.get('rules') == ['MATCH,Exit'], 'base rule changed')
                # Run even if static assertions failed, so -t PASS cannot conceal
                # a wrong /proxies membership. Every launched raw config is gated.
                if field_name == 'new' and args.mihomo and case['runtime']:
                    try:
                        check_core(args, case, output, parsed, port, record)
                    except (AssertionError, KeyError, OSError, subprocess.TimeoutExpired) as error:
                        require(False, 'runtime: ' + str(error))
        except (TypeError, ValueError, KeyError, yaml.YAMLError) as error:
            require(False, 'output parse/assertion: ' + str(error))
    record['raw_output_unchanged'] = sha(output.read_bytes()) == record['raw_output_sha256']
    require(record['raw_output_unchanged'], 'raw output bytes changed')
    record['passed'] = not record['errors']
    print(('PASS ' if record['passed'] else 'FAIL ') + label + (': ' + '; '.join(record['errors']) if record['errors'] else ''), flush=True)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--driver', required=True, type=Path)
    parser.add_argument('--mihomo', type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--field-names', choices=['new', 'both'], default='both',
                        help='new-only is useful for baseline driver lacking the new request switch')
    parser.add_argument('--case', help='optional substring filter')
    args = parser.parse_args()
    args.driver = args.driver.resolve()
    args.out = args.out.resolve()
    args.out.mkdir(parents=True, exist_ok=False)
    provenance = {'driver': str(args.driver), 'driver_sha256': sha(args.driver.read_bytes()),
                  'script_sha256': sha(Path(__file__).read_bytes()),
                  'runtime_scope': 'raw full/new bytes; loopback GET /proxies; no inbounds/providers/healthchecks/proxy requests',
                  'legacy_scope': 'full/old and both provider-list variants are structural only'}
    if args.mihomo:
        args.mihomo = args.mihomo.resolve()
        must(sha(args.mihomo.read_bytes()) == PIN, 'Mihomo must be the pinned official v1.19.29 binary')
        version = subprocess.run([str(args.mihomo), '-v'], capture_output=True, check=True, timeout=5).stdout.decode()
        must('v1.19.29' in version, version)
        provenance.update(mihomo=str(args.mihomo), mihomo_sha256=PIN, mihomo_version=version)
    (args.out / 'provenance.json').write_text(json.dumps(provenance, indent=2))
    cases = [c for c in corpus() if not args.case or args.case in c['name']]
    must(cases, 'no cases selected')
    (args.out / 'cases.json').write_text(json.dumps(cases, ensure_ascii=False, indent=2))
    results = []
    for case in cases:
        for field_name in (['new'] if args.field_names == 'new' else ['new', 'old']):
            for list_mode in [False, True]:
                results.append(run_case(args, case, field_name, list_mode))
    summary = {'cases': len(results), 'passed': sum(r['passed'] for r in results),
               'failed': [r['case'] for r in results if not r['passed']],
               'mihomo_tests': sum('mihomo_test_exit' in r for r in results),
               'runtime_reads': sum('runtime_members' in r for r in results),
               'all_processes_reaped': all(r.get('runtime_reaped', True) for r in results),
               'all_raw_outputs_unchanged': all(r['raw_output_unchanged'] for r in results),
               'results': results}
    (args.out / 'results.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2))
    print(json.dumps({k: v for k, v in summary.items() if k != 'results'}, indent=2))
    raise SystemExit(bool(summary['failed']))


if __name__ == '__main__':
    main()
