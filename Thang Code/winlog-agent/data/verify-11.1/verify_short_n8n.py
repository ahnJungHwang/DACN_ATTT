"""Run handoff workflow on the short VM case using an isolated n8n container."""
import json
from pathlib import Path
import subprocess
import sys
from uuid import uuid4
import httpx

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
from build_workflow import build
OUT=Path(__file__).parent/'run-87dba4a5/n8n'
OUT.mkdir(exist_ok=True)
CASE=json.loads((OUT.parent/'cases.json').read_text(encoding='utf-8'))['case_ids'][0]
IMAGE='n8nio/n8n@sha256:d02752c6ab446ae9db8deec2f9cc887c378f77cdcad31650814df936b7386dfb'
def save(name,obj): (OUT/name).write_text(json.dumps(obj,ensure_ascii=False,indent=2),encoding='utf-8')
def docker(*args):
    r=subprocess.run(['docker',*args],capture_output=True,text=True,encoding='utf-8',timeout=720)
    if r.returncode: raise RuntimeError('Docker failed: '+r.stderr[-500:])
    return r.stdout
def decode(raw):
    for i,ch in enumerate(raw):
        if ch!='{': continue
        try: obj,_=json.JSONDecoder().raw_decode(raw[i:])
        except ValueError: continue
        if isinstance(obj,dict) and 'data' in obj: return obj
    raise RuntimeError('Execution JSON missing')
token=(ROOT/'data/secrets/api-token.txt').read_text().strip()
client=httpx.Client(base_url='http://127.0.0.1:8000',trust_env=False,timeout=30,
                  headers={'Authorization':'Bearer '+token})
name='winlog-short-'+uuid4().hex[:8]
created=False
credential=OUT/'credential.json'
summary={'case_id':CASE,'image':IMAGE,'runs':[],'complete':False}
try:
    save(credential.name,[{'id':'short-api','name':'Local short-case API','type':'httpHeaderAuth',
                         'data':{'name':'Authorization','value':'Bearer '+token}}])
    docker('run','-d','--name',name,'--mount',f'type=bind,source={OUT},target=/work,readonly',
           '-e','N8N_DIAGNOSTICS_ENABLED=false','-e','N8N_VERSION_NOTIFICATIONS_ENABLED=false',
           '-e','N8N_TEMPLATES_ENABLED=false','--entrypoint','/bin/sh',IMAGE,'-c','sleep infinity')
    created=True
    docker('exec',name,'n8n','import:credentials','--input=/work/credential.json')
    credential.unlink()
    for i,model in enumerate(('qwen2.5:3b-instruct-q4_K_M','llama3.2:3b-instruct-q4_K_M')):
        key=str(uuid4()); wf=build(); wf['id']='short'+str(i)
        for node in wf['nodes']:
            if node['name']=='Edit Fields':
                values={'base_url':'http://host.docker.internal:8000','case_id':CASE,'model':model,'request_id':key}
                for f in node['parameters']['values']['string']: f['value']=values[f['name']]
            if node['type']=='n8n-nodes-base.httpRequest':
                node['credentials']={'httpHeaderAuth':{'id':'short-api','name':'Local short-case API'}}
        save(f'workflow-{i}.json',wf)
        save(f'request-{i}.json',{'request_id':key,'model':model,'case_id':CASE})
        docker('exec',name,'n8n','import:workflow',f'--input=/work/workflow-{i}.json')
        raw=docker('exec',name,'n8n','execute','--id='+wf['id'],'--rawOutput')
        (OUT/f'execution-{i}.txt').write_text(raw,encoding='utf-8')
        nodes=decode(raw)['data']['resultData']['runData']
        branches=[b for b in ('NORMAL','ALERT','UNKNOWN') if b in nodes]
        assert len(branches)==1
        item=nodes[branches[0]][-1]['data']['main'][0][0]['json']
        r=client.get('/requests/'+key); r.raise_for_status(); envelope=r.json(); save(f'result-{i}.json',envelope)
        assert envelope['state']=='completed'
        result=envelope['result']
        assert item['result_id']==envelope['result_id'] and item['label']==result['label']
        assert item['evidence_refs']==result['evidence_refs']
        for ref in result['evidence_refs']:
            e=client.get('/events/'+ref); e.raise_for_status(); assert e.json()['raw_xml']
        export=client.get('/results/'+envelope['result_id']+'/export?format=jsonl')
        export.raise_for_status(); assert json.loads(export.text)==result
        record={'model':model,'request_id':key,'result_id':envelope['result_id'],'branch':branches[0],
                'technical_error':result['technical_error'],'preflight':result.get('preflight'),
                'reason':result['reason'],'polls':len(nodes.get('Poll',[])), 'refs_and_export_match':True}
        summary['runs'].append(record); save('summary.json',summary); print(json.dumps(record,ensure_ascii=False),flush=True)
    summary['complete']=True
finally:
    if credential.exists(): credential.unlink()
    if created: docker('rm','-f',name)
    client.close(); save('summary.json',summary)
