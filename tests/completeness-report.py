#!/usr/bin/env python3
"""Original-source field completeness and safe diagnostics; no network traffic."""
import argparse,base64,copy,hashlib,json,subprocess,unittest
from pathlib import Path
import yaml
ARGS=None

def node(kind='socks5',name='fixture',**fields):
    return dict(name=name,type=kind,server='192.0.2.10',port=1080,**fields)

def convert(body,target='clash'):
    raw=body if isinstance(body,str) else yaml.safe_dump(body,sort_keys=False)
    p=subprocess.run([str(ARGS.driver),target],input=raw.encode(),capture_output=True,timeout=10)
    r=json.loads(p.stdout)
    if hashlib.sha256(r['output'].encode()).hexdigest()!=r['output_sha256']:raise AssertionError('output witness mismatch')
    return r

class Completeness(unittest.TestCase):
    def test_socks_explicit_and_absent(self):
        for value in (True,False,None):
            for key in ('udp','tfo','skip-cert-verify'):
                n=node(**({key:value} if value is not None else {}))
                r=convert({'proxies':[n]})
                self.assertEqual(r['report']['status'],'PASS')
                self.assertEqual(yaml.safe_load(r['output'])['proxies'],[n])
    def test_original_full_field_fixture(self):
        n=node('anytls',password='003:@%中文',sni='tls.invalid',udp=False,tfo=True,
               **{'skip-cert-verify':False,'client-fingerprint':'chrome','fingerprint':'ab'*32,
                  'alpn':['h2','h3','private'],'min-idle-session':0})
        r=convert({'proxies':[n]});self.assertEqual(r['report']['status'],'PASS')
        self.assertEqual(yaml.safe_load(r['output'])['proxies'],[n])
    def test_json_base64_and_old_key(self):
        n=node(udp=True)
        for key in ('proxies','Proxy'):
            for raw in (json.dumps({key:[n]}),yaml.safe_dump({key:[n]})):
                for body in (raw,base64.b64encode(raw.encode()).decode()):
                    r=convert(body);self.assertEqual(r['report']['status'],'PASS')
                    self.assertEqual(yaml.safe_load(r['output'])['proxies'],[n])
    def test_unsupported_node_does_not_disappear(self):
        n=[node(name='one'),node(name='two'),node(name='three'),node('unknown-fixture','secret-node')]
        r=convert({'proxies':n});self.assertEqual(r['report']['status'],'FAIL');self.assertEqual(r['output'],'')
        records=r['report']['sources'][0]['input_nodes'];self.assertEqual(len(records),4)
        self.assertEqual(records[3]['status'],'FAIL');self.assertIsNone(records[3]['output_ordinal'])
    def test_unknown_fields_not_forwarded_or_approved(self):
        for extra in ({'unique-secret-key':{'token':'private-marker'}},{'unknown':False},{'ws-opts':{'unknown':3}}):
            r=convert({'proxies':[node(**extra)]});self.assertEqual(r['report']['status'],'FAIL');self.assertEqual(r['output'],'')
            report=json.dumps(r['report']);self.assertNotIn('unique-secret-key',report);self.assertNotIn('private-marker',report)
            self.assertTrue(any(f['disposition']=='REJECTED' for f in r['report']['sources'][0]['input_nodes'][0]['fields']))
    def test_malformed_name_retained(self):
        n=node();n['name']=['bad'];r=convert({'proxies':[n,node(name='ok')]})
        self.assertEqual(r['report']['status'],'FAIL');self.assertEqual(len(r['report']['sources'][0]['input_nodes']),2)
    def test_source_configuration_not_silently_ignored(self):
        r=convert({'proxies':[node()],'rules':['MATCH,DIRECT']})
        self.assertEqual(r['report']['status'],'FAIL');self.assertEqual(r['report']['sources'][0]['reason'],'SOURCE_CONFIGURATION_UNHANDLED')
    def test_target_without_verified_mapping(self):
        for target in ('surge','singbox','quanx','mixed'):
            r=convert({'proxies':[node()]},target);self.assertEqual(r['report']['status'],'FAIL');self.assertEqual(r['output'],'')
            self.assertEqual(r['report']['reason'],'TARGET_UNVERIFIED')
    def test_duplicate_source_fields_refused(self):
        r=convert('proxies:\n- {name: fixture, type: socks5, server: 192.0.2.10, port: 1080, udp: true, udp: false}\n')
        self.assertEqual(r['report']['status'],'FAIL');self.assertEqual(r['report']['sources'][0]['reason'],'DUPLICATE_FIELD')
    def test_yaml_multiple_documents_cannot_hide_nodes(self):
        raw=yaml.safe_dump({'proxies':[node()]})+'---\n'+yaml.safe_dump({'proxies':[node('unsupported','hidden')]})
        for body in (raw,base64.b64encode(raw.encode()).decode()):
            r=convert(body);self.assertEqual(r['report']['status'],'FAIL');self.assertEqual(r['output'],'')
            self.assertEqual(r['report']['sources'][0]['reason'],'MALFORMED_INPUT')

    def test_numeric_scalar_types_do_not_become_strings(self):
        for value in (1.5,1e100,1):
            for key in ('password','server'):
                n=node('anytls',password='synthetic');n[key]=value
                for raw in (json.dumps({'proxies':[n]}),yaml.safe_dump({'proxies':[n]})):
                    r=convert(raw);self.assertEqual(r['report']['status'],'FAIL');self.assertEqual(r['output'],'')
        n=node('anytls',password='1.5');r=convert({'proxies':[n]});self.assertEqual(r['report']['status'],'PASS')

    def test_nested_types_and_key_tags(self):
        for value in (True,1.5):
            n=node('vmess',uuid='00000000-0000-4000-8000-000000000001',cipher='auto',network='ws',**{'ws-opts':{'path':value}})
            r=convert({'proxies':[n]});self.assertEqual(r['report']['status'],'FAIL')
        r=convert('proxies:\n- { !private name: x, type: socks5, server: 192.0.2.1, port: 1080}\n')
        self.assertEqual(r['report']['status'],'FAIL')

    def test_plugin_tokens_preserve_tls_mux_and_delimiters(self):
        for path in ('/mux','/x?foo=1&tls','/a;tls','/a=b','/a\\b'):
            for tls,mux in ((None,None),(False,False),(True,True)):
                opts={'mode':'websocket','host':'tls.example','path':path}
                if tls is not None:opts.update(tls=tls,mux=mux)
                n=node('ss',password='p',cipher='aes-128-gcm',plugin='v2ray-plugin',**{'plugin-opts':opts})
                r=convert({'proxies':[n]});self.assertEqual(r['report']['status'],'PASS')
                actual=yaml.safe_load(r['output'])['proxies'][0]['plugin-opts']
                self.assertEqual(actual,{**opts,'tls':tls is True,'mux':mux is True})

    def test_uri_original_components_and_output_inventory(self):
        uri='anytls://p%40ss@[2001:db8::1]:443?sni=tls.invalid&peer=tls.invalid&udp=0#Any'
        for body in (uri,base64.b64encode(uri.encode()).decode()):
            r=convert(body);self.assertEqual(r['report']['status'],'PASS')
            record=r['report']['sources'][0]['input_nodes'][0]
            # root + scheme/authority/fragment + query + 3 query maps/key/value
            self.assertEqual(len(record['fields']),14)
            actual=yaml.safe_load(r['output'])['proxies'][0]
            self.assertEqual(actual,dict(name='Any',type='anytls',server='2001:db8::1',port=443,password='p@ss',sni='tls.invalid',udp=False))
            self.assertEqual(len(record['output_fields']),len(actual)+1)

    def test_uri_bounds_and_cyclic_document(self):
        cycle='v: 2\nps: &cycle {child: *cycle}\nadd: 192.0.2.1\nport: 443\nid: fixture\n'
        for body in ('vmess://'+base64.b64encode(cycle.encode()).decode(),'anytls://p@192.0.2.1:443?alpn='+','.join(['h3']*30000)):
            r=convert(body);self.assertEqual(r['report']['status'],'FAIL');self.assertEqual(r['output'],'')

    def test_ambiguous_valid_strings_stay_strings(self):
        for value in ('true','false','1.5','1e100','null','2026-10-04','1:20.5','1_000.0','1.2_3','1_2.3_4','1.0_0e+2','.5_0','1._0'):
            n=node(name=value,username=value,password=value,udp=False)
            r=convert(json.dumps({'proxies':[n]}));self.assertEqual(r['report']['status'],'PASS')
            self.assertEqual(yaml.safe_load(r['output'])['proxies'],[n])

    def test_uri_string_array_elements_are_not_inferred_types(self):
        uri='anytls://p@192.0.2.1:443?alpn=true%2C1.5#x'
        r=convert(uri);self.assertEqual(r['report']['status'],'PASS')
        self.assertEqual(yaml.safe_load(r['output'])['proxies'][0]['alpn'],['true','1.5'])
        uri='vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?security=tls&type=http&host=true#x'
        r=convert(uri);self.assertEqual(r['report']['status'],'PASS')
        self.assertEqual(yaml.safe_load(r['output'])['proxies'][0]['h2-opts']['host'],['true'])

    def test_existing_numeric_short_id_protection_is_a_declared_mapping(self):
        raw='proxies:\n- {name: Reality, type: vless, server: 192.0.2.1, port: 443, uuid: 00000000-0000-4000-8000-000000000001, tls: true, network: tcp, reality-opts: {public-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA, short-id: 00001234}}\n'
        r=convert(raw);self.assertEqual(r['report']['status'],'PASS')
        self.assertEqual(yaml.safe_load(r['output'])['proxies'][0]['reality-opts']['short-id'],'00001234')
        self.assertTrue(any(f['reason']=='REPRESENTATION_MAPPED' for f in r['report']['sources'][0]['input_nodes'][0]['fields']))

    def test_unquoted_yaml_float_credentials_are_not_strings(self):
        for value in ('1:20.5','1_000.0','1.2_3','1_2.3_4','1.0_0e+2','.5_0','1._0'):
            raw='proxies:\n- {name: x, type: socks5, server: 192.0.2.1, port: 1080, password: '+value+'}\n'
            r=convert(raw);self.assertEqual(r['report']['status'],'FAIL')

    def test_fields_do_not_leak_values(self):
        n=node('anytls','secret-label',password='private-password',**{'client-fingerprint':'private-fingerprint'})
        r=convert({'proxies':[n]});self.assertEqual(r['report']['status'],'PASS')
        text=json.dumps(r['report'])
        for value in ('secret-label','private-password','private-fingerprint','192.0.2.10'):
            self.assertNotIn(value,text)
    def test_empty_is_not_pass(self):
        for body in ('',{'proxies':[]},{'unrecognized':[]}):
            r=convert(body);self.assertEqual(r['report']['status'],'FAIL');self.assertEqual(r['output'],'')
    def test_legacy_unverified_is_not_empty_success(self):
        for body in ('vmess://e30=', '[Proxy]\nleaf = socks5, 192.0.2.10, 1080\n'):
            r=convert(body);self.assertEqual(r['report']['status'],'FAIL');self.assertEqual(r['output'],'')
            self.assertTrue(r['report']['sources'][0]['input_nodes'])

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--driver',type=Path,required=True);ARGS,other=p.parse_known_args()
    unittest.main(argv=['completeness-report']+other)
