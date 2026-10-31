"""Real n8n CLI checks against an explicitly synthetic local HTTP backend.

Requires the disposable winlog-n8n-verify container with /work read-only mount.
Never reads the application's token or logs. Outputs stay under ignored data/.
"""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess
import sys
import threading
from uuid import uuid4

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from build_workflow import build

OUT=ROOT/'data/n8n-verification'
CONTAINER='winlog-n8n-verify'
TOKEN='synthetic-n8n-verification-only'
jobs={}
polls={}


class Backend(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_POST(self):
        if self.headers.get('Authorization')!='Bearer '+TOKEN: return self.reply(401,{'error':'UNAUTHORIZED'})
        body=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        key=self.headers.get('Idempotency-Key')
        if key not in jobs: jobs[key]={'request_id':key,'result_id':str(uuid4()),'scenario':body['case_id']}
        self.respond(jobs[key],False)
    def do_GET(self):
        if self.headers.get('Authorization')!='Bearer '+TOKEN: return self.reply(401,{'error':'UNAUTHORIZED'})
        job=next((j for j in jobs.values() if self.path=='/results/'+j['result_id']),None)
        if not job: return self.reply(404,{'error':'NOT_FOUND'})
        polls[job['request_id']]=polls.get(job['request_id'],0)+1
        self.respond(job,True)
    def respond(self,job,is_poll):
        scenario=job['scenario']
        if scenario=='http-error': return self.reply(503,{'error':'TEST_UNAVAILABLE'})
        envelope={k:job[k] for k in ('request_id','result_id')}
        if scenario=='poll-limit' or (scenario=='pending' and not is_poll):
            return self.reply(200 if is_poll else 202,{**envelope,'state':'running'})
        label={'normal':'NORMAL','alert':'ALERT','pending':'ALERT'}.get(scenario,'UNKNOWN')
        result={'label':label,'reason':'Synthetic n8n test only','evidence_refs':['synthetic-ref'],
                'technical_error':'TIMEOUT' if scenario=='technical' else None}
        if scenario=='schema-error': del result['label']
        self.reply(200,{**envelope,'state':'completed','result':result})
    def reply(self,status,body):
        raw=json.dumps(body).encode()
        self.send_response(status); self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(raw))); self.end_headers(); self.wfile.write(raw)


def docker(*args):
    result=subprocess.run(['docker','exec',CONTAINER,*args],capture_output=True,text=True,encoding='utf-8',timeout=180)
    if result.returncode: raise RuntimeError(result.stdout[-3000:]+result.stderr[-3000:])
    return result.stdout


def execute(scenario,expected,key=None):
    workflow=build(); workflow['id']='winlog-test-'+scenario; workflow['name']='SYNTHETIC '+scenario
    key=key or str(uuid4())
    for node in workflow['nodes']:
        if node['name']=='Edit Fields':
            for field in node['parameters']['values']['string']:
                if field['name']=='case_id': field['value']=scenario
                if field['name']=='request_id': field['value']=key
                if field['name']=='base_url': field['value']='http://host.docker.internal:18082'
        if node['type']=='n8n-nodes-base.httpRequest':
            node['credentials']={'httpHeaderAuth':{'id':'winlog-synthetic-token','name':'Synthetic test only'}}
        if scenario=='poll-limit' and node['name']=='Prepare':
            node['parameters']['jsCode']=node['parameters']['jsCode'].replace('poll_count:0','poll_count:119')
    target=OUT/(scenario+'.json'); target.write_text(json.dumps(workflow),encoding='utf-8')
    imported=docker('n8n','import:workflow','--input=/work/data/n8n-verification/'+target.name)
    raw=docker('n8n','execute','--id='+workflow['id'],'--rawOutput')
    (OUT/(scenario+'-execution.txt')).write_text(raw,encoding='utf-8')
    # CLI emits startup lines before the JSON result.
    decoder=json.JSONDecoder(); document=None
    for index,char in enumerate(raw):
        if char=='{':
            try: candidate,_=decoder.raw_decode(raw[index:])
            except ValueError: continue
            if isinstance(candidate,dict) and 'data' in candidate:
                document=candidate; break
    if document is None: raise AssertionError('No execution JSON: '+raw[-2000:])
    run=document['data']['resultData']['runData']
    assert expected in run,(scenario,list(run))
    item=run[expected][-1]['data']['main'][0][0]['json']
    assert item['request_id']==key
    if scenario=='pending': assert polls.get(key)==1
    if scenario=='poll-limit': assert polls.get(key)==1 and item['error_kind']=='POLL_LIMIT'
    return {'scenario':scenario,'branch':expected,'request_id':key,'result_id':item.get('result_id'),
            'poll_count':polls.get(key,0),'synthetic':True,'imported':'Successfully imported' in imported}


if __name__=='__main__':
    OUT.mkdir(parents=True,exist_ok=True)
    credential=[{'id':'winlog-synthetic-token','name':'Synthetic test only','type':'httpHeaderAuth',
                 'data':{'name':'Authorization','value':'Bearer '+TOKEN}}]
    (OUT/'credential.json').write_text(json.dumps(credential),encoding='utf-8')
    docker('n8n','import:credentials','--input=/work/data/n8n-verification/credential.json')
    server=ThreadingHTTPServer(('127.0.0.1',18082),Backend)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    records=[]
    try:
        for scenario,branch in [('normal','NORMAL'),('alert','ALERT'),('unknown','UNKNOWN'),
                ('technical','UNKNOWN'),('pending','ALERT'),('schema-error','Schema Error'),
                ('http-error','HTTP Error'),('poll-limit','Polling Limit')]:
            record=execute(scenario,branch); records.append(record); print(json.dumps(record),flush=True)
        original=records[0]; count=len(jobs)
        repeated=execute('normal','NORMAL',original['request_id'])
        assert len(jobs)==count and repeated['result_id']==original['result_id']
        records.append(dict(repeated,retry_same_job=True))
        (OUT/'summary.json').write_text(json.dumps(records,indent=2),encoding='utf-8')
    finally: server.shutdown()
