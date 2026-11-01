"""Local verification helper; credentials are never printed."""
import json
from pathlib import Path
import time
from uuid import uuid4
import httpx

ROOT = Path(__file__).resolve().parents[2]
RUN = ROOT.parent / 'log-test/20261028-123820-87dba4a5-f76b-4b9c-b107-9052b832fa83'
OUT = Path(__file__).parent / 'run-87dba4a5'
OUT.mkdir(exist_ok=True)
def save(name, value):
    (OUT / name).write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')

with httpx.Client(base_url='http://127.0.0.1:8000', trust_env=False, timeout=60,
                 headers={'Authorization':'Bearer '+(ROOT/'data/secrets/api-token.txt').read_text().strip()}) as c:
    c.get('/health').raise_for_status()
    with (RUN/'security.xml').open('rb') as s, (RUN/'powershell.xml').open('rb') as p:
        r=c.post('/imports', files={'security':('security.xml',s),'powershell':('powershell.xml',p)}, data={'synthetic':'false'})
    if r.status_code == 409:
        source=c.get('/sources/'+r.json()['source_id']); source.raise_for_status()
        r=c.get('/imports/'+source.json()['import_id'])
    r.raise_for_status(); imported=r.json(); save('import.json',imported)
    print('import',imported['import_id'], 'events',imported['event_count'],flush=True)
    casefile=OUT/'cases.json'
    if casefile.exists():
        cases=json.loads(casefile.read_text(encoding='utf-8'))
    else:
        r=c.post('/cases',json={'import_id':imported['import_id'],'user':'lab_demo'})
        r.raise_for_status(); cases=r.json(); save('cases.json',cases)
    print('groups',[(g['kind'],len(g['event_refs']),g.get('failure_count')) for g in cases['groups']],flush=True)
    assert len(cases['case_ids'])==1, 'Inspect unexpected case count before inference'
    caseid=cases['case_ids'][0]
    r=c.get('/cases/'+caseid); r.raise_for_status(); save('case.json',r.json())
    events=[]
    for ref in r.json()['snapshot']['event_refs']:
        e=c.get('/events/'+ref); e.raise_for_status(); events.append(e.json())
    save('events.json',events)
    for e in events:
        n=e['normalized']; n=json.loads(n) if isinstance(n,str) else n
        print('event',n['event_id'],n['event_record_id'],n['time'],'user',n['user'],'session',n['logon_id'],flush=True)
    for model in ('qwen2.5:3b-instruct-q4_K_M','llama3.2:3b-instruct-q4_K_M'):
        tag=model.split(':')[0]; keyfile=OUT/(tag+'-request.json')
        if keyfile.exists(): key=json.loads(keyfile.read_text())['request_id']
        else:
            key=str(uuid4()); save(keyfile.name,{'request_id':key,'case_id':caseid,'model':model})
        r=c.post('/analyze',json={'case_id':caseid,'model':model},headers={'Idempotency-Key':key})
        r.raise_for_status(); env=r.json(); save(tag+'-envelope.json',env)
        deadline=time.monotonic()+600
        while env['state']!='completed' and time.monotonic()<deadline:
            time.sleep(2); r=c.get('/requests/'+key); r.raise_for_status(); env=r.json()
        save(tag+'-envelope.json',env)
        if env['state']!='completed': raise RuntimeError('Pending request retained; do not create a new key')
        result=env['result']
        for ref in result['evidence_refs']:
            e=c.get('/events/'+ref); e.raise_for_status(); assert e.json()['raw_xml']
            assert ref in {ev['event_ref'] for ev in events}
        for fmt in ('jsonl','csv'):
            export=c.get('/results/'+env['result_id']+'/export',params={'format':fmt}); export.raise_for_status()
            (OUT/(tag+'.'+fmt)).write_bytes(export.content)
            if fmt=='jsonl': assert json.loads(export.text)==result
        print(json.dumps({'model':model,'case_id':caseid,'result_id':env['result_id'],
                         'label':result['label'],'technical_error':result['technical_error'],
                         'preflight':result.get('preflight'),'reason':result['reason']},ensure_ascii=False),flush=True)
