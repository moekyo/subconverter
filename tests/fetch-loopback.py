#!/usr/bin/env python3
"""Synthetic 127.0.0.1-only regression evidence for production webget.cpp."""
import collections
import hashlib
import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlsplit

import argparse
parser = argparse.ArgumentParser()
parser.add_argument("--binary", type=Path, required=True)
args = parser.parse_args()
BINARY = args.binary.resolve()
temporary = tempfile.TemporaryDirectory(prefix="subconverter-fetch-")
ROOT = Path(temporary.name)

class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, label):
        super().__init__(('127.0.0.1', 0), Handler)
        self.label = label
        self.calls = []
        self.counts = collections.Counter()

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *args): pass
    def do_GET(self):
        path = urlsplit(self.path).path
        srv = self.server
        srv.calls.append({'path':self.path, 'auth':self.headers.get('Authorization','')})
        srv.counts[path] += 1
        n = srv.counts[path]
        if srv.label != 'origin':
            return self.respond(srv.label.upper().encode())
        if path == '/retry' and n == 1:
            return self.respond(b'PART-', declared=30)
        if path == '/retry':
            return self.respond(b'GOOD')
        if path == '/always-partial':
            return self.respond(b'PART-', declared=30)
        if path == '/cache-partial':
            return self.respond(b'KNOWN-GOOD' if n == 1 else b'PART-', declared=None if n == 1 else 30)
        if path == '/cache-503':
            return self.respond(b'KNOWN-GOOD' if n == 1 else b'UNAVAILABLE', code=200 if n == 1 else 503)
        if path == '/auth':
            return self.respond(('AUTH='+self.headers.get('Authorization','absent')).encode())
        return self.respond(b'ORIGIN')
    def respond(self, body, code=200, declared=None):
        self.send_response(code)
        self.send_header('Content-Length', str(len(body) if declared is None else declared))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
        self.close_connection = True

origin, proxy, cors = (Server(x) for x in ('origin','proxy','cors'))
servers = (origin,proxy,cors)
for srv in servers:
    threading.Thread(target=srv.serve_forever, daemon=True).start()

def url(srv, path='/'):
    return f'http://127.0.0.1:{srv.server_port}{path}'

def fresh(name):
    return Path(tempfile.mkdtemp(prefix=name+'-', dir=ROOT))

def call(path, *, cwd, mode='cache', ttl=0, api=True, force=False, auth='-', proxy_arg='', env_extra=None):
    target = url(origin,path)
    assert urlsplit(target).hostname == '127.0.0.1'
    if proxy_arg:
        normalized = proxy_arg.removeprefix('cors:')
        assert urlsplit(normalized).hostname == '127.0.0.1'
    env = {k:v for k,v in os.environ.items() if k.lower() not in ('http_proxy','https_proxy','all_proxy','no_proxy')}
    # Make all traffic explicitly local and eliminate inherited proxy endpoints.
    env.update({'http_proxy':'','https_proxy':'','all_proxy':'','no_proxy':'127.0.0.1'})
    if env_extra: env.update(env_extra)
    proc = subprocess.run([str(BINARY),mode,target,proxy_arg,str(ttl),str(int(api)),str(int(force)),auth,path],cwd=cwd,env=env,text=True,capture_output=True,timeout=20)
    assert proc.returncode == 0, (proc.returncode, proc.stderr)
    return json.loads(proc.stdout)

results=[]
def record(name, finding, **detail):
    results.append({'test':name,'finding':finding,**detail})

def age_cache(cwd):
    for path in (cwd/'cache').iterdir():
        os.utime(path,(time.time()-120,time.time()-120))

def cache_body(cwd):
    files = [p for p in (cwd/'cache').iterdir() if not p.name.endswith('_header')]
    assert len(files)==1,files
    return files[0].read_text(),str(files[0].relative_to(ROOT))

try:
    # Normal complete HTTP 200, and within-TTL cache control.
    cwd=fresh('normal')
    before=len(origin.calls)
    a=call('/normal',cwd=cwd,ttl=60)
    b=call('/normal',cwd=cwd,ttl=60)
    assert a['body']==b['body']=='ORIGIN' and len(origin.calls)-before==1
    record('normal_200_cache_control','PASS: complete response cached and reused',requests=1,body=b['body'])

    # Low-level result returns an HTTP status even when transfer is incomplete.
    a=call('/always-partial',cwd=fresh('raw-partial'),mode='raw')
    assert a['status']==0 and a['body']=='' and a['transport']==18 and a['upstream_status']==200
    record('raw_partial_200','FIXED: failed transport is separate from upstream 200',status=a['status'],body=a['body'],transport=a['transport'],upstream_status=a['upstream_status'])

    # Retries are enabled only with APIMode=false in this baseline.
    before=origin.counts['/retry']
    a=call('/retry',cwd=fresh('retry'),api=False)
    assert origin.counts['/retry']-before==2 and a['body']=='GOOD'
    assert a['headers'].count('HTTP/1.1 200')==1
    record('retry_buffer','FIXED: retry contains only complete last response',requests=2,body=a['body'],http_status_lines=1)

    # API mode has no automatic retry: its failed body is empty.
    before=origin.counts['/always-partial']
    a=call('/always-partial',cwd=fresh('api-no-retry'),api=True)
    assert origin.counts['/always-partial']-before==1 and a['body']==''
    record('api_mode_retry_control','PASS: API mode stops after one transfer',requests=1,body=a['body'])

    # After expiry, a truncated HTTP 200 overwrites known-good cache with empty body.
    cwd=fresh('partial-cache')
    a=call('/cache-partial',cwd=cwd,ttl=60)
    assert a['body']=='KNOWN-GOOD'
    age_cache(cwd)
    b=call('/cache-partial',cwd=cwd,ttl=60)
    disk,path=cache_body(cwd)
    c=call('/cache-partial',cwd=cwd,ttl=60)
    assert b['body']==disk==c['body']=='KNOWN-GOOD' and origin.counts['/cache-partial']==3
    record('partial_200_cache','FIXED: incomplete response preserves known-good cache and follows existing stale-on-failure policy',initial_body=a['body'],refresh_body=b['body'],disk_body=disk,next_body=c['body'],requests=3,cache_file=path)

    # Contrast: existing documented stale-on-error behavior for HTTP 503 is preserved.
    cwd=fresh('503-cache')
    a=call('/cache-503',cwd=cwd,ttl=60)
    age_cache(cwd)
    b=call('/cache-503',cwd=cwd,ttl=60)
    disk,path=cache_body(cwd)
    assert a['body']==b['body']==disk=='KNOWN-GOOD'
    record('http_503_stale_control','PASS: HTTP 503 retains known-good cached body',body=b['body'],disk_body=disk,requests=2)

    # Authorization changes are absent from cache identity.
    cwd=fresh('auth-cache')
    before=origin.counts['/auth']
    a=call('/auth',cwd=cwd,ttl=60,auth='fixture-A')
    b=call('/auth',cwd=cwd,ttl=60,auth='fixture-B')
    assert a['body']=='AUTH=fixture-A' and b['body']=='AUTH=fixture-B' and origin.counts['/auth']-before==2
    record('authorization_cache','FIXED: different authorization contexts fetch distinct responses',body_a=a['body'],body_b=b['body'],requests=2)
    a=call('/auth',cwd=fresh('auth-direct'),ttl=0,auth='fixture-B')
    assert a['body']=='AUTH=fixture-B'
    record('authorization_no_cache_control','PASS: uncached request forwards its own header',body=a['body'])

    # Ordinary explicit proxy honors force_proxy despite NO_PROXY.
    cwd=fresh('force-proxy')
    a=call('/route',cwd=cwd,proxy_arg=url(proxy),force=False)
    b=call('/route',cwd=cwd,proxy_arg=url(proxy),force=True)
    assert a['body']=='ORIGIN' and b['body']=='PROXY'
    record('normal_proxy_force_control','PASS: force_proxy disables NO_PROXY for ordinary explicit proxy',unforced_body=a['body'],forced_body=b['body'])

    # cors: takes a URL-prefix branch; force has no influence on proxy selection.
    before_proxy=len(proxy.calls)
    before_cors=len(cors.calls)
    before_origin=len(origin.calls)
    env={'http_proxy':url(proxy),'no_proxy':'127.0.0.1'}
    a=call('/cors-target',cwd=fresh('force-cors'),proxy_arg='cors:'+url(cors,'/fetch/'),force=True,env_extra=env)
    assert a['body']=='' and len(cors.calls)==before_cors and len(proxy.calls)==before_proxy and len(origin.calls)==before_origin
    record('forced_cors','FIXED: unsupported forced cors refuses before any network connection',body=a['body'],gateway_requests=0,proxy_requests=0,origin_requests=0)

    # Seed both the legacy and current namespaces. A rejected forced request
    # cannot return cached content, even if a matching entry already exists.
    cwd=fresh('cors-cached')
    prefix='cors:'+url(cors,'/fetch/')
    target=url(origin,'/cors-cached')
    context=hashlib.md5(b"headers-present\n").hexdigest()
    identities=[target, "fetch-cache-v2\n"+target+"\nrequest-context-md5:"+context]
    (cwd/'cache').mkdir()
    for identity in identities:
        identity += "\nproxy-md5:"+hashlib.md5(prefix.encode()).hexdigest()+"\nforce-proxy:1"
        key=hashlib.md5(identity.encode()).hexdigest()
        (cwd/'cache'/key).write_text('CACHED-CORS')
    before=[len(x.calls) for x in servers]
    a=call('/cors-cached',cwd=cwd,ttl=60,force=True,proxy_arg=prefix)
    assert a['body']=='' and before==[len(x.calls) for x in servers]
    record('forced_cors_cached','PASS: rejected forced request cannot use either cache namespace',new_requests=0)

    # Old entries without authorization context cannot be reused.
    cwd=fresh('old-auth-namespace'); (cwd/'cache').mkdir()
    key=hashlib.md5(url(origin,'/auth').encode()).hexdigest()
    (cwd/'cache'/key).write_text('AUTH=fixture-A')
    before=origin.counts['/auth']
    b=call('/auth',cwd=cwd,ttl=60,auth='fixture-B')
    assert b['body']=='AUTH=fixture-B' and origin.counts['/auth']-before==1
    record('auth_old_namespace','PASS: ignores old shared-auth cache',requests=1)
    c=call('/auth',cwd=cwd,ttl=60,auth='fixture-B')
    assert c['body']==b['body'] and origin.counts['/auth']-before==1
    record('auth_same_context_hit','PASS: same context reuses only its own cache',requests=1)

    before=[len(x.calls) for x in servers]
    a=call('/bad-force',cwd=fresh('empty-force'),force=True)
    b=call('/bad-force',cwd=fresh('unsupported-force'),force=True,proxy_arg='unsupported://127.0.0.1:1')
    assert a['body']==b['body']=='' and before==[len(x.calls) for x in servers]
    record('invalid_forced_descriptor','PASS: empty and unsupported force issue no requests',new_requests=0)
    a=call('/cors-legacy',cwd=fresh('cors-legacy'),proxy_arg='cors:'+url(cors,'/fetch/'))
    assert a['body']=='CORS'
    record('nonforced_cors_control','PASS: explicitly nonforced legacy cors behavior is unchanged')
    print(json.dumps({'curl_runtime':a['curl_runtime'],'curl_headers':a['curl_headers'],
                      'network':'127.0.0.1 synthetic services only; no TLS or real subscriptions',
                      'checks':len(results),'results':results},indent=2))

finally:
    for srv in servers:
        srv.shutdown()
        srv.server_close()
    temporary.cleanup()
