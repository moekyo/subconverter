#!/usr/bin/env python3
"""Independent F1 boundary corpus. Runs only a caller-supplied production chain driver.
All files/endpoints are synthetic. Mihomo is optional and invoked with -t only.
This script does not modify the checkout or normalize converter output for -t.
"""
import argparse, hashlib, json, pathlib, subprocess
import yaml


def ss(name, dep=None):
    node = {'name': name, 'type': 'ss', 'server': '127.0.0.1', 'port': 18001, 'cipher': 'aes-128-gcm', 'password': 'synthetic-password'}
    if dep is not None: node['dialer-proxy'] = dep
    return node


def base_group(**kw):
    return {'name': 'Transit', 'type': 'select', **kw}


def request(group, *, nodes=None, generated=None, extra_base=None, **options):
    base = {'mode': 'rule', 'proxy-groups': [group], 'rules': ['MATCH,[SS] Leaf' if options.get('append') else 'MATCH,Leaf']}
    if extra_base: base.update(extra_base)
    return {'documents': [yaml.safe_dump({'proxies': nodes or [ss('Entry'), ss('Leaf', 'Transit')]}, sort_keys=False)], 'groups': generated or [], 'bases': {'clash': yaml.safe_dump(base, sort_keys=False)}, **options}


def cases():
    result=[]
    def add(name, group, expected, **opts):
        result.append({'name':name,'expected':expected,'request':request(group,**opts)})
    for flag in ('include-all-proxies','include-all'):
        for proxies in ('omit', 'empty'):
            g=base_group(**{flag:True,'filter':'^Entry$'})
            if proxies=='empty': g['proxies']=[]
            add(f'{flag}-{proxies}-valid',g,0)
            add(f'{flag}-{proxies}-no-chain',g,0,nodes=[ss('Entry'),ss('Leaf')])
        add(f'{flag}-zero-match',base_group(**{flag:True,'filter':'^Absent$'}),3)
        add(f'{flag}-self-match',base_group(**{flag:True,'filter':'^Leaf$'}),3)
        add(f'{flag}-entry-plus-self',base_group(**{flag:True,'filter':'^(Entry|Leaf)$'}),3)
        add(f'{flag}-false',base_group(**{flag:False,'filter':'^Entry$','proxies':[]}),3)
    add('explicit-direct',base_group(proxies=['DIRECT']),0)
    add('explicit-direct-plus-auto-empty',base_group(proxies=['DIRECT'],**{'include-all-proxies':True,'filter':'^Absent$'}),0)
    add('filter-does-not-drop-explicit-self',base_group(proxies=['Leaf'],**{'include-all-proxies':True,'filter':'^Entry$'}),3)
    add('explicit-and-auto-exclude-self',base_group(proxies=['Leaf'],**{'include-all-proxies':True,'filter':'^Entry$','exclude-filter':'^Leaf$'}),0)
    add('exclude-only-entry',base_group(**{'include-all-proxies':True,'filter':'^Entry$','exclude-filter':'^Entry$'}),3)
    add('exclude-only-self',base_group(**{'include-all-proxies':True,'exclude-filter':'^Leaf$'}),0)
    add('backtick-alternatives-cycle',base_group(**{'include-all-proxies':True,'filter':'^Entry$`^Leaf$'}),3)
    add('backtick-exclude-self',base_group(**{'include-all-proxies':True,'exclude-filter':'^Absent$`^Leaf$'}),0)
    add('trailing-empty-alternative-matches-all',base_group(**{'include-all-proxies':True,'filter':'^Entry$`'}),3)
    add('exclude-type-official-name',base_group(**{'include-all-proxies':True,'filter':'^Entry$','exclude-type':'ShAdOwSoCkS'}),3)
    add('exclude-type-yaml-alias-is-not-official-name',base_group(**{'include-all-proxies':True,'filter':'^Entry$','exclude-type':'ss'}),0)
    add('exclude-type-does-not-trim',base_group(**{'include-all-proxies':True,'filter':'^Entry$','exclude-type':' Shadowsocks'}),0)
    add('exclude-type-pipe-list',base_group(**{'include-all-proxies':True,'filter':'^Entry$','exclude-type':'Vmess|Shadowsocks'}),3)
    socks={'name':'Entry','type':'socks5','server':'127.0.0.1','port':18002}
    add('exclude-type-removes-self-node',base_group(**{'include-all-proxies':True,'exclude-type':'Shadowsocks'}),0,nodes=[socks,ss('Leaf','Transit')])
    add('exclude-type-removes-explicit-direct',base_group(proxies=['DIRECT'],**{'exclude-type':'Direct'}),3)
    add('use-empty-is-not-provider',base_group(proxies=[],use=[]),3)
    add('include-providers-with-none-is-empty',base_group(proxies=[],**{'include-all-providers':True}),3)
    add('filter-only-is-empty',base_group(filter='^Entry$'),3)
    add('unknown-group-type-is-not-provider',{'name':'Transit','type':'unrecognized','use':[]},3)
    add('missing-explicit-even-if-excluded',base_group(proxies=['Missing','Entry'],**{'exclude-filter':'^Missing$'}),3)
    cyc=[base_group(proxies=['Inner','Entry'],**{'exclude-type':'Selector'}),{'name':'Inner','type':'select','proxies':['Transit']}]
    add('raw-group-cycle-even-if-excluded',cyc[0],3,extra_base={'proxy-groups':cyc})
    add('raw-group-self-cycle-even-if-excluded',base_group(proxies=['Transit','Entry'],**{'exclude-filter':'^Transit$'}),3)
    add('generated-valid-overrides-broken-base',base_group(**{'include-all-proxies':True,'filter':'^Leaf$'}),0,generated=[{'name':'Transit','members':['[]Entry']}])
    add('generated-self-overrides-valid-base',base_group(**{'include-all-proxies':True,'filter':'^Entry$'}),3,generated=[{'name':'Transit','members':['[]Leaf']}])
    add('generated-empty-fallback-remains-empty',base_group(**{'include-all-proxies':True,'filter':'^Entry$'}),3,generated=[{'name':'Transit','members':['^Absent$']}])
    add('generated-explicit-direct-is-real',base_group(**{'include-all-proxies':True,'filter':'^Leaf$'}),0,generated=[{'name':'Transit','members':['[]DIRECT']}])
    add('filter-final-renamed-name',base_group(**{'include-all-proxies':True,'filter':'^Renamed$'}),0,rename=[['^Entry$','Renamed']])
    add('filter-original-name-after-rename-is-empty',base_group(**{'include-all-proxies':True,'filter':'^Entry$'}),3,rename=[['^Entry$','Renamed']])
    add('filter-final-appended-name',base_group(**{'include-all-proxies':True,'filter':r'^\[SS\] Entry$'}),0,append=True)
    add('filter-final-duplicate-suffix',base_group(**{'include-all-proxies':True,'filter':'^Entry 2$'}),0,nodes=[ss('Entry'),ss('Entry'),ss('Leaf','Transit')])
    add('filtered-source-is-not-auto-member',base_group(**{'include-all-proxies':True,'filter':'^Entry$'}),3,exclude=['^Entry$'])
    add('positive-lookahead-entry',base_group(**{'include-all-proxies':True,'filter':'^(?=Entry$).*$'}),0)
    add('negative-lookahead-entry',base_group(**{'include-all-proxies':True,'filter':'^(?!Leaf$).*$'}),0)
    add('ascii-casefold-entry',base_group(**{'include-all-proxies':True,'filter':'(?i)^entry$'}),0)
    add('unicode-literal-entry',base_group(**{'include-all-proxies':True,'filter':'^東京$'}),0,nodes=[ss('東京'),ss('Leaf','Transit')])
    # The chosen documented subset rejects these on reachable chains. No-chain
    # templates remain untouched; refusal is never described as a Mihomo error.
    for name,pattern in [('backreference',r'^(Entry)\1?$'),('unicode-class',r'^\p{L}+$'),('word-class',r'^\w+$'),('possessive','^Entry++$'),('vertical-whitespace',r'Entry\v?'),('engine-verbs','(*UTF)^Entry$')]:
        g=base_group(**{'include-all-proxies':True,'filter':pattern})
        add('unsupported-'+name,g,3)
        add('unsupported-'+name+'-no-chain',g,0,nodes=[ss('Entry'),ss('Leaf')])
    for name, pattern in [('quantifier-missing-lower','^Entry{,1}$'),('quantifier-inner-space','^Entry{1, 2}$'),('quantifier-edge-space','^Entry{ 1 }$')]:
        add('unsupported-'+name,base_group(**{'include-all-proxies':True,'filter':pattern}),3)
    add('unicode-exclude-type-must-not-be-ascii-folded',base_group(**{'include-all-proxies':True,'filter':'^Entry$','exclude-type':'SocKs5'}),3,nodes=[socks,ss('Leaf','Transit')])
    add('generated-builtin-name-collision',base_group(proxies=['Entry']),3,nodes=[ss('Entry'),ss('Leaf','DIRECT')],generated=[{'name':'DIRECT','members':['[]Entry']}])
    add('supported-ordinary-counted-quantifier',base_group(**{'include-all-proxies':True,'filter':'^Entr[y]{1}$'}),0)
    provider_base={'proxy-providers':{'P':{'type':'file','path':'./synthetic-provider.yaml'}}}
    add('provider-known-only-remains-unresolved',base_group(use=['P']),0,extra_base=provider_base)
    add('provider-missing-is-invalid',base_group(use=['Missing']),3)
    add('provider-all-replaces-missing-use',base_group(use=['Missing'],**{'include-all-providers':True}),0,extra_base=provider_base)
    add('provider-all-with-no-provider-does-not-use-missing',base_group(use=['Missing'],**{'include-all-providers':True}),3)
    add('provider-all-and-local-valid',base_group(**{'include-all':True,'filter':'^Entry$'}),0,extra_base=provider_base)
    add('provider-all-does-not-hide-local-self',base_group(**{'include-all':True,'filter':'^Leaf$'}),3,extra_base=provider_base)
    add('provider-does-not-hide-explicit-self',base_group(use=['P'],proxies=['Leaf']),3,extra_base=provider_base)
    add('provider-does-not-hide-excluded-missing',base_group(use=['P'],proxies=['Missing'],**{'exclude-filter':'^Missing$'}),3,extra_base=provider_base)
    add('provider-false-flag-does-not-fix-missing',base_group(use=['Missing'],**{'include-all-providers':False}),3,extra_base=provider_base)
    add('provider-present-with-local-excluded-stays-unresolved',base_group(use=['P'],proxies=['Entry'],**{'exclude-filter':'^Entry$'}),0,extra_base=provider_base)
    add('unknown-type-with-real-provider-is-invalid',{'name':'Transit','type':'unrecognized','use':['P']},3,extra_base=provider_base)
    same_provider={'proxy-providers':{'Transit':{'type':'file','path':'./synthetic-provider.yaml'}}}
    add('group-provider-collision-with-local-members',base_group(**{'include-all':True,'filter':'^Entry$'}),3,extra_base=same_provider)
    add('group-provider-same-name-with-provider-only',base_group(use=['Transit']),0,extra_base=same_provider)
    add('match-limit-is-unknown-not-nonmatch',base_group(**{'include-all-proxies':True,'filter':'^(a+)+$|^Entry$'}),3,nodes=[ss('Entry'),ss('a'*64+'!','Transit')])
    # Anchor and end-of-line semantics must use regexp2.None, not regFind's /m.
    add('anchor-does-not-match-interior-line',base_group(**{'include-all-proxies':True,'filter':'^Entry$'}),3,nodes=[ss('Prefix\nEntry'),ss('Leaf','Transit')])
    return result


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--driver',type=pathlib.Path);parser.add_argument('--out',required=True,type=pathlib.Path);parser.add_argument('--mihomo',type=pathlib.Path)
    args=parser.parse_args();args.out.mkdir(parents=True,exist_ok=True); corpus=cases()
    (args.out/'cases.json').write_text(json.dumps(corpus,ensure_ascii=False,indent=2))
    if not args.driver: print(f'Wrote {len(corpus)} cases');return
    provenance={'driver':str(args.driver),'driver_sha256':hashlib.sha256(args.driver.read_bytes()).hexdigest(),'script_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()}
    if args.mihomo:
        digest=hashlib.sha256(args.mihomo.read_bytes()).hexdigest()
        if digest!='9c397be7489538628fae781bc005e4c5b8cd7b0961b8bb2ca815c8150f193577':
            parser.error('Mihomo must be the pinned official v1.19.29 executable')
        provenance.update(mihomo=str(args.mihomo),mihomo_sha256=digest)
    (args.out/'provenance.json').write_text(json.dumps(provenance,indent=2))
    results=[]
    for case in corpus:
        name=case['name']; completed=subprocess.run([str(args.driver),'clash'],input=json.dumps(case['request']).encode(),capture_output=True,timeout=20)
        output=args.out/(name+'.yaml');output.write_bytes(completed.stdout);(args.out/(name+'.stderr')).write_bytes(completed.stderr)
        result={'name':name,'expected':case['expected'],'status':completed.returncode,'bytes':len(completed.stdout),'passed':completed.returncode==case['expected'],'output_sha256':hashlib.sha256(completed.stdout).hexdigest()}
        if completed.returncode==0:
            try:
                parsed=yaml.safe_load(completed.stdout); base=yaml.safe_load(case['request']['bases']['clash'])
                if not case['request']['groups']:
                    result['base_groups_preserved']=parsed['proxy-groups']==base['proxy-groups']
                    result['passed'] &= result['base_groups_preserved']
                if 'proxy-providers' in base:
                    result['providers_preserved']=parsed.get('proxy-providers')==base['proxy-providers']
                    result['passed'] &= result['providers_preserved']
            except Exception as e: result.update(passed=False,parse_error=str(e))
        elif completed.stdout: result.update(passed=False,error='Failed conversion emitted output')
        # Unsupported regex no-chain cases are intentionally not expected to
        # pass the core; converter preserves caller's requested source fields.
        if args.mihomo and result['passed'] and completed.returncode==0 and not name.startswith('unsupported-'):
            home=args.out/(name+'-home');home.mkdir(exist_ok=True)
            check=subprocess.run([str(args.mihomo),'-t','-d',str(home),'-f',str(output)],capture_output=True,timeout=20)
            (args.out/(name+'.mihomo.log')).write_bytes(check.stdout+check.stderr)
            result['mihomo_status']=check.returncode; result['passed'] &= check.returncode==0
            result['unchanged_after_test']=hashlib.sha256(output.read_bytes()).hexdigest()==result['output_sha256']
            result['passed'] &= result['unchanged_after_test']
        results.append(result)
    (args.out/'results.json').write_text(json.dumps(results,ensure_ascii=False,indent=2))
    failed=[x['name'] for x in results if not x['passed']]
    print(json.dumps({'cases':len(results),'passed':len(results)-len(failed),'failed':failed},ensure_ascii=False,indent=2))
    raise SystemExit(bool(failed))
if __name__=='__main__':main()
