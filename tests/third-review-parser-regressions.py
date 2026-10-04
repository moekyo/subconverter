#!/usr/bin/env python3
"""Focused R3-2/R3-3 checks using an existing production protocol-convert.

Synthetic fixtures only. No builds, downloads, network or real subscriptions.
Run on both Release and Debug. Null/absent checks compare original output bytes.
"""
import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import yaml

UUID = '11111111-1111-4111-8111-111111111111'


def b64(s):
    return base64.b64encode(s.encode()).decode()


def require(ok, message):
    if not ok:
        raise AssertionError(message)


def uri(name):
    return 'ss://' + b64('aes-128-gcm:synthetic') + '@fixture.invalid:443#' + name


def ss(name):
    return dict(name=name, type='ss', server='fixture.invalid', port=443,
                cipher='aes-128-gcm', password='synthetic')


def v2ray(stream=None):
    o = dict(protocol='vmess', settings=dict(vnext=[dict(address='fixture.invalid', port=443,
             users=[dict(id=UUID, alterId=0, security='auto')])]))
    if stream is not None:
        o['streamSettings'] = stream
    return {'outbounds': [o]}


def cases():
    result = []
    def add(name, body, nodes=None, *, reject=False, equivalent=None):
        result.append(dict(name=name, body=body, nodes=nodes, reject=reject, equivalent=equivalent))
    def encoded(name, body, nodes=None, *, reject=False):
        for depth in range(3):
            add(name + '-b64-' + str(depth), body, nodes, reject=reject)
            body = b64(body)
    embedded = uri('Embedded')
    row = 'Container = ss, fixture.invalid, 443, encrypt-method=aes-128-gcm, password=synthetic'
    for ending, sep in [('lf', '\n'), ('crlf', '\r\n'), ('cr', '\r')]:
        for section, label in [('General', 'general'), ('WireGuard wg.example', 'dotted'),
                               ('WireGuard 日本', 'unicode'), ('9section', 'numeric')]:
            body = sep.join(['; comment', '# comment', '// comment', '[' + section + ']\t ',
                             'metadata = ' + embedded, '[Proxy]', row, ''])
            encoded('ini-' + ending + '-' + label, body, [ss('Container')])
        # Recognized containers own their URI-looking metadata, even when no
        # real node was accepted. CRLF input must remain CRLF at the process boundary.
        for label, rows in [('metadata', ['[General]', embedded, '[Proxy]', 'DIRECT = direct']),
                            ('proxy-only-uri', ['[Proxy]', embedded]),
                            ('rejected-row', ['[Proxy]', row.replace('443', '0'), embedded])]:
            encoded('ini-negative-' + ending + '-' + label, sep.join(rows), reject=True)
    for ending, sep in [('lf', '\n'), ('cr', '\r'), ('space', ' ')]:
        for where, rows in [('first', ['garbage', uri('Good'), uri('Second')]),
                            ('middle', [uri('Good'), 'garbage', uri('Second')]),
                            ('last', [uri('Good'), uri('Second'), 'garbage'])]:
            encoded('raw-' + ending + '-' + where, sep.join(rows), [ss('Good'), ss('Second')])
    for name, body in [('single-comment', '# comment ' + embedded),
                       ('single-semicolon', '; comment ' + embedded),
                       ('single-slash', '// comment ' + embedded),
                       ('single-indented-comment', '\t # ' + embedded),
                       ('yaml-block', 'notes: |\n  ' + embedded + '\n'),
                       ('yaml-flow-array', '["' + embedded + '"]'),
                       ('yaml-sequence', '- notes: |\n    ' + embedded + '\n'),
                       ('json-metadata', json.dumps({'notes': embedded})),
                       ('yaml-declared', '---\n|\n  ' + embedded + '\n')]:
        encoded('container-negative-' + name, body, reject=True)
    ws = dict(network='ws', security='tls', wsSettings=dict(path='/a%2Fb?q=one',
              headers={'Host': 'front.invalid', 'Edge': 'edge.invalid'}))
    tcp = dict(network='tcp', tcpSettings={})
    for name, absent, key in [('ws-unused-tcp', v2ray(ws), 'tcpSettings'),
                              ('tcp-unused-ws', v2ray(tcp), 'wsSettings'),
                              ('ws-selected', v2ray({'network': 'ws'}), 'wsSettings'),
                              ('tcp-selected', v2ray({'network': 'tcp'}), 'tcpSettings')]:
        nullable = copy.deepcopy(absent)
        nullable['outbounds'][0]['streamSettings'][key] = None
        add('nullable-' + name, nullable, equivalent=absent)
    nullable = v2ray(); nullable['outbounds'][0]['streamSettings'] = None
    add('nullable-stream', nullable, equivalent=v2ray())
    for label, bad in [('array', []), ('string', 'bad'), ('number', 3), ('bool', True)]:
        malformed = v2ray(); malformed['outbounds'][0]['streamSettings'] = bad
        add('shape-stream-' + label, malformed, reject=True)
        for network, key in [('ws', 'wsSettings'), ('ws', 'tcpSettings'), ('tcp', 'tcpSettings'), ('tcp', 'wsSettings')]:
            add('shape-' + network + '-' + key + '-' + label,
                v2ray({'network': network, key: bad}), reject=True)
    for label, body in [('outbounds-null', {'outbounds': [None]}),
                        ('settings-null', {'outbounds': [{'settings': None}]}),
                        ('vnext-null', {'outbounds': [{'settings': {'vnext': None}}]})]:
        add('required-' + label, body, reject=True)
    for label, users in [('null', None), ('empty', []), ('first-null', [None]),
                          ('first-empty', [{}]), ('id-null', [{'id': None}]),
                          ('id-empty', [{'id': ''}])]:
        body = v2ray(); body['outbounds'][0]['settings']['vnext'][0]['users'] = users
        add('required-users-' + label, body, reject=True)
    return result


def raw(body):
    return (body if isinstance(body, str) else json.dumps(body)).encode()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--driver', required=True, type=Path)
    p.add_argument('--out', required=True, type=Path)
    args = p.parse_args(); args.out.mkdir(parents=True, exist_ok=True)
    results = []
    for case in cases():
        body = raw(case['body']); stem = args.out / case['name']; stem.with_suffix('.input').write_bytes(body)
        item = dict(name=case['name'], input_sha256=hashlib.sha256(body).hexdigest())
        try:
            proc = subprocess.run([str(args.driver), 'clash', 'block', 'list'], input=body,
                                  capture_output=True, timeout=10)
            stem.with_suffix('.stdout').write_bytes(proc.stdout); stem.with_suffix('.stderr').write_bytes(proc.stderr)
            item.update(exit=proc.returncode, bytes=len(proc.stdout), output_sha256=hashlib.sha256(proc.stdout).hexdigest())
            require(proc.returncode == (2 if case['reject'] else 0), 'unexpected status ' + str(proc.returncode))
            if case['reject']:
                require(proc.stdout == b'', 'rejected input produced output')
            elif case['equivalent'] is not None:
                control_raw = raw(case['equivalent']); stem.with_suffix('.control.input').write_bytes(control_raw)
                control = subprocess.run([str(args.driver), 'clash', 'block', 'list'], input=control_raw,
                                         capture_output=True, timeout=10)
                stem.with_suffix('.control.stdout').write_bytes(control.stdout)
                stem.with_suffix('.control.stderr').write_bytes(control.stderr)
                require(control.returncode == 0 and control.stdout == proc.stdout, 'null differs from absent output bytes')
                proxies = yaml.safe_load(proc.stdout)['proxies']
                require(len(proxies) == 1 and proxies[0]['type'] == 'vmess' and proxies[0]['uuid'] == UUID,
                        'nullable positive control did not preserve VMess user')
                require(proxies[0]['server'] == 'fixture.invalid' and proxies[0]['port'] == 443, 'endpoint changed')
                if case['name'] == 'nullable-ws-unused-tcp':
                    require(proxies[0]['tls'] is True and proxies[0]['network'] == 'ws' and
                            proxies[0]['ws-opts'] == {'path': '/a%2Fb?q=one', 'headers': {'Host': 'front.invalid', 'Edge': 'edge.invalid'}},
                            'WS fields changed')
            else:
                require(yaml.safe_load(proc.stdout)['proxies'] == case['nodes'], 'node semantics differ')
            item['passed'] = True
        except (AssertionError, OSError, ValueError, KeyError, TypeError, yaml.YAMLError, subprocess.TimeoutExpired) as error:
            item.update(passed=False, error=str(error))
        results.append(item)
        print(('PASS ' if item['passed'] else 'FAIL ') + case['name'] + (': ' + item['error'] if 'error' in item else ''), flush=True)
    summary = dict(cases=len(results), passed=sum(x['passed'] for x in results),
                   driver_sha256=hashlib.sha256(args.driver.read_bytes()).hexdigest(), results=results)
    (args.out / 'results.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(str(summary['passed']) + '/' + str(summary['cases']) + ' passed')
    return int(summary['passed'] != summary['cases'])


if __name__ == '__main__':
    raise SystemExit(main())
