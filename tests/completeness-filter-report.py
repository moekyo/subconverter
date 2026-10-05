#!/usr/bin/env python3
"""Configured regex filter occurrences, using the real parser/filter/exporter."""
import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import unittest

ARGS = None
NONCE = '0123456789abcdef0123456789abcdef'


def node(name):
    return {'name': name, 'type': 'socks5', 'server': '192.0.2.1', 'port': 1080, 'udp': False}


def convert(body=None, mode=None, rule=None):
    if body is None: body = {'proxies': [node('keep'), node('drop')]}
    if not isinstance(body, str): body = json.dumps(body, ensure_ascii=False)
    command = [str(ARGS.driver), 'clash']
    if mode is not None: command.append(mode)
    if rule is not None: command.append(rule)
    result = subprocess.run(command, input=body.encode(), capture_output=True, timeout=10)
    report = json.loads(result.stdout)
    assert hashlib.sha256(report['output'].encode()).hexdigest() == report['output_sha256']
    return report


class ConfiguredFilters(unittest.TestCase):
    def test_exclude_preserves_occurrence_fields_and_exact_rule_authority(self):
        report = convert(mode='exclude', rule='^drop')
        self.assertEqual(report['schema'], 'subconverter.completeness/v2')
        self.assertEqual(report['report']['status'], 'PASS')
        self.assertEqual(report['report']['filter_policy'], {'engine': 'subconverter.regex/v1', 'include': [],
            'exclude': [hashlib.sha256((NONCE + '\0filter\0exclude\0^drop').encode()).hexdigest()]})
        records = report['report']['sources'][0]['input_nodes']
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]['status'], 'PASS')
        self.assertIsNone(records[0]['filter'])
        self.assertEqual(records[1]['status'], 'FILTERED')
        self.assertEqual(records[1]['reason'], 'CONFIG_EXCLUDE_MATCH')
        self.assertEqual(records[1]['filter'], {'kind': 'exclude', 'rule_ordinal': 0})
        self.assertIsNone(records[1]['output_ordinal'])
        self.assertEqual(records[1]['output_fields'], [])
        self.assertEqual(len(records[1]['fields']), 6)
        self.assertTrue(all(f['disposition'] == 'FILTERED' and f['reason'] == 'CONFIG_EXCLUDE_MATCH' for f in records[1]['fields']))

    def test_include_miss_is_distinct_explicit_reason(self):
        report = convert(mode='include', rule='^keep')
        self.assertEqual(report['report']['status'], 'PASS')
        record = report['report']['sources'][0]['input_nodes'][1]
        self.assertEqual(record['reason'], 'CONFIG_INCLUDE_MISS')
        self.assertEqual(record['filter'], {'kind': 'include', 'rule_ordinal': None})

    def test_248_to_220_counts_exact_occurrences(self):
        original = [node('drop-' + str(i)) for i in range(28)] + [node('keep-' + str(i)) for i in range(220)]
        report = convert({'proxies': original}, 'exclude', '^drop-')
        self.assertEqual(report['report']['status'], 'PASS')
        records = report['report']['sources'][0]['input_nodes']
        self.assertEqual(len(records), 248)
        self.assertEqual(sum(n['status'] == 'FILTERED' for n in records), 28)
        self.assertEqual([n['output_ordinal'] for n in records if n['status'] == 'PASS'], list(range(220)))
        import yaml
        self.assertEqual(yaml.safe_load(report['output'])['proxies'], original[28:])

    def test_unexplained_omission_or_plain_filtered_flag_fail(self):
        for mode in ['omitted', 'forged-filter', 'policy-mismatch']:
            with self.subTest(mode=mode):
                report = convert(mode=mode)
                self.assertEqual(report['report']['status'], 'FAIL')
                self.assertEqual(report['output'], '')

    def test_rejected_malformed_or_unknown_fields_cannot_hide_behind_filter(self):
        for key, value in [('type', 'unsupported'), ('port', 'not-a-port'), ('unknown-sensitive-option', 'synthetic')]:
            nodes = [node('keep'), {**node('drop'), key: value}]
            report = convert({'proxies': nodes}, 'exclude', '^drop')
            with self.subTest(key=key):
                self.assertEqual(report['report']['status'], 'FAIL')
                self.assertEqual(report['output'], '')

    def test_match_limit_is_unverified_instead_of_include_miss(self):
        # The second branch would match !, but the first exhausts PCRE2 first.
        body = {'proxies': [node('Good'), node('a' * 64 + '!')]}
        report = convert(body, 'include', '^(a+)+$|!$|^Good$')
        self.assertEqual(report['report']['status'], 'FAIL')
        self.assertEqual(report['report']['reason'], 'FILTER_UNVERIFIED')
        self.assertEqual(report['output'], '')

    def test_match_limit_in_exclude_is_unverified_even_without_drop(self):
        body = {'proxies': [node('Good'), node('a' * 64 + '!')]}
        report = convert(body, 'exclude', '^(a+)+$|!$')
        self.assertEqual(report['report']['status'], 'FAIL')
        self.assertEqual(report['report']['reason'], 'FILTER_UNVERIFIED')

    def test_duplicate_named_filtered_occurrences_remain_distinct(self):
        report = convert({'proxies': [node('keep'), node('drop'), node('drop')]}, 'exclude', '^drop')
        self.assertEqual(report['report']['status'], 'PASS')
        records = report['report']['sources'][0]['input_nodes']
        self.assertEqual([n['ordinal'] for n in records], [0, 1, 2])
        self.assertEqual([n['status'] for n in records], ['PASS', 'FILTERED', 'FILTERED'])

    def test_actual_exclusion_index_and_exclusion_precedence(self):
        report = convert(mode='exclude-second', rule='^drop')
        self.assertEqual(report['report']['status'], 'PASS')
        self.assertEqual(report['report']['sources'][0]['input_nodes'][1]['filter']['rule_ordinal'], 1)
        report = convert(mode='include-exclude')
        self.assertEqual(report['report']['status'], 'PASS')
        self.assertEqual(report['report']['sources'][0]['input_nodes'][1]['reason'], 'CONFIG_EXCLUDE_MATCH')

    def test_bad_port_values_cannot_gain_pass_from_filtering(self):
        for port in [-1, 0, 65537, 18446744073709551615]:
            report = convert({'proxies': [node('keep'), {**node('drop'), 'port': port}]}, 'exclude', '^drop')
            with self.subTest(port=port): self.assertEqual(report['report']['status'], 'FAIL')

    def test_empty_output_never_passes(self):
        self.assertEqual(convert(mode='exclude', rule='.*')['report']['status'], 'FAIL')

    def test_supported_input_alias_on_filtered_node_needs_no_output_mapping(self):
        report = convert({'proxies': [node('keep'), {**node('drop'), 'fast-open': False}]}, 'exclude', '^drop')
        self.assertEqual(report['report']['status'], 'PASS')
        self.assertEqual(report['report']['sources'][0]['input_nodes'][1]['status'], 'FILTERED')

    def test_no_match_preserves_all_originals(self):
        report = convert(mode='exclude', rule='^absent$')
        self.assertEqual(report['report']['status'], 'PASS')
        self.assertTrue(all(n['status'] == 'PASS' for n in report['report']['sources'][0]['input_nodes']))

    def test_unicode_regex_has_exact_utf8_hash_without_name_leak(self):
        report = convert({'proxies': [node('keep'), node('到期-私密')]}, 'exclude', '(到期|剩余流量)')
        self.assertEqual(report['report']['status'], 'PASS')
        witness = hashlib.sha256((NONCE + '\0filter\0exclude\0(到期|剩余流量)').encode()).hexdigest()
        self.assertEqual(report['report']['filter_policy']['exclude'], [witness])
        diagnostic = json.dumps(report['report'], ensure_ascii=False)
        self.assertNotIn('私密', diagnostic)
        self.assertNotIn('到期', diagnostic)

    def test_bad_regex_script_matcher_or_oversized_policy_refused(self):
        for rule in ['[', '!!TYPE=SOCKS5', '', 'x' * 4097]:
            with self.subTest(rule=rule[:20]):
                self.assertEqual(convert(mode='exclude', rule=rule)['report']['status'], 'FAIL')

    def test_filtered_native_and_base64_source_remain_accounted(self):
        raw = json.dumps({'proxies': [node('keep'), node('drop')]})
        report = convert(base64.b64encode(raw.encode()).decode(), 'exclude', 'drop')
        self.assertEqual(report['report']['status'], 'PASS')
        self.assertEqual(report['report']['sources'][0]['format'], 'base64-clash')

    def test_uri_original_components_remain_in_filtered_inventory(self):
        raw = 'trojan://synthetic@192.0.2.1:443#keep\ntrojan://synthetic@192.0.2.2:443#drop\n'
        report = convert(raw, 'exclude', '^drop')
        self.assertEqual(report['report']['status'], 'PASS')
        record = report['report']['sources'][0]['input_nodes'][1]
        self.assertEqual(record['status'], 'FILTERED')
        self.assertGreater(len(record['fields']), 3)
        self.assertTrue(all(f['reason'] == 'CONFIG_EXCLUDE_MATCH' for f in record['fields']))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--driver', type=Path, required=True)
    ARGS, remaining = parser.parse_known_args()
    unittest.main(argv=[__file__, *remaining])
