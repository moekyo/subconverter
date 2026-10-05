#!/usr/bin/env python3
"""Sequential synthetic loopback checks of real fetch provenance, no external URLs."""
import argparse,json,os,re,subprocess,tempfile,threading,time
from http.server import BaseHTTPRequestHandler,HTTPServer
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--binary',type=Path,required=True);args=p.parse_args()
class Origin(BaseHTTPRequestHandler):
    hits=0
    status=200
    def do_GET(self):
        Origin.hits+=1
        body=b'KNOWN-GOOD' if Origin.status==200 else b'unavailable'
        self.send_response(Origin.status);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def log_message(self,*_):pass
server=HTTPServer(('127.0.0.1',0),Origin);worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
checks=[]
def require(value,name):
    if not value:raise RuntimeError(name)
    checks.append(name)
try:
 with tempfile.TemporaryDirectory(prefix='fetch-provenance-') as folder:
    env=os.environ.copy()
    for key in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy'):env.pop(key,None)
    env['NO_PROXY']='127.0.0.1'
    def run(auth):
        result=subprocess.run([str(args.binary.resolve()),'wrapper',f'http://127.0.0.1:{server.server_port}/fixture','', '60','1','0',auth,'synthetic'],cwd=folder,env=env,capture_output=True,check=True,timeout=10)
        return json.loads(result.stdout)
    a=run('synthetic-A');require(a['provenance']=='network' and a['body']=='KNOWN-GOOD','network completion provenance')
    require(bool(re.fullmatch('[0-9a-f]{64}',a['fetch_context_sha256'])),'private context hash shape')
    hit=run('synthetic-A');require(hit['provenance']=='cache' and hit['fetch_context_sha256']==a['fetch_context_sha256'] and Origin.hits==1,'same context fresh cache')
    b=run('synthetic-B');require(b['provenance']=='network' and b['fetch_context_sha256']!=a['fetch_context_sha256'] and Origin.hits==2,'different auth isolated context')
    for file in (Path(folder)/'cache').iterdir():os.utime(file,(time.time()-3600,)*2)
    Origin.status=503
    stale=run('synthetic-A');require(stale['provenance']=='stale-cache' and stale['body']=='KNOWN-GOOD' and stale['fetch_context_sha256']==a['fetch_context_sha256'],'stale provenance does not become fresh')
 print(json.dumps({'checks':checks,'passed':len(checks),'origin_requests':Origin.hits}))
finally:
 server.shutdown();server.server_close();worker.join(timeout=2)
