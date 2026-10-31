from pathlib import Path
import time
from uuid import uuid4
from fastapi.testclient import TestClient
from app.api import create_app
from app.config import Settings,MODELS
from app.service import Service
from app.storage import Store
from test_service import Runtime

TOKEN='synthetic-test-token-not-a-secret-0001'
HEADERS={'Authorization':'Bearer '+TOKEN}


def test_auth_csrf_and_routes(tmp_path):
    settings=Settings(data_root=str(tmp_path),response_wait_seconds=1)
    store=Store(tmp_path); runtime=Runtime(); runtime.release.set()
    service=Service(store,settings,runtime)
    with TestClient(create_app(settings,service,TOKEN)) as client:
        assert client.get('/health').json()=={'status':'ok'}
        assert client.get('/cases').status_code==401
        assert client.get('/cases',headers={'Authorization':'Bearer wrong'}).status_code==401
        login=client.post('/login',json={'token':TOKEN})
        assert login.status_code==200
        assert client.post('/cases',json={'import_id':'absent'}).status_code==403
        csrf={'X-CSRF-Token':login.json()['csrf_token']}
        assert client.post('/cases',json={'import_id':'absent'},headers=csrf).status_code==404
        xml=(Path(__file__).parent/'fixtures/synthetic-security.xml').read_bytes()
        response=client.post('/imports',files={'security':('../../original.xml',xml,'text/xml')},headers=HEADERS)
        assert response.status_code==200
        imp=response.json()['import_id']
        assert next(s for s in response.json()['sources'] if s['source_name']=='Security')['original_name']=='../../original.xml'
        response=client.post('/cases',json={'import_id':imp},headers=HEADERS)
        case=response.json()['case_ids'][0]
        assert client.get('/cases/'+case,headers=HEADERS).status_code==200
        assert client.get('/cases/absent',headers=HEADERS).status_code==404
        assert client.post('/analyze',json={'case_id':case,'model':'bad'},headers=HEADERS).status_code==422
        key=str(uuid4())
        response=client.post('/analyze',json={'case_id':case,'model':MODELS[0]},headers={**HEADERS,'Idempotency-Key':key})
        assert response.status_code==200
        result_id=response.json()['result_id']
        assert response.json()['result']['technical_error'] is None
        assert client.get('/requests/'+key,headers=HEADERS).json()['result_id']==result_id
        assert client.get('/results/'+result_id+'/export',headers=HEADERS).status_code==200
        assert client.get('/events/nonexistent',headers=HEADERS).status_code==404
        assert 'access-control-allow-origin' not in client.get('/cases',headers={**HEADERS,'Origin':'https://elsewhere.example'}).headers


def test_pending_response_and_unavailable(tmp_path):
    settings=Settings(data_root=str(tmp_path),response_wait_seconds=1)
    store=Store(tmp_path); case=store.create_case([]); runtime=Runtime()
    service=Service(store,settings,runtime)
    with TestClient(create_app(settings,service,TOKEN)) as client:
        response=client.post('/analyze',json={'case_id':case,'model':MODELS[0]},headers=HEADERS)
        assert response.status_code==202 and 'result' not in response.json()
        status=client.get(response.json()['status_url'],headers=HEADERS).json()
        assert status['state'] in ('queued','running') and 'label' not in status
        runtime.release.set()
        service.degraded=True
        assert client.post('/analyze',json={'case_id':case,'model':MODELS[0]},headers=HEADERS).status_code==503


def test_export_formula_and_traversal(tmp_path):
    from app.results import save_result
    settings=Settings(data_root=str(tmp_path))
    store=Store(tmp_path); case=store.create_case([]); runtime=Runtime()
    service=Service(store,settings,runtime)
    job=service.submit(case,MODELS[0])
    save_result(store,job['request_id'],{'label':'UNKNOWN','reason':'  =1+1','evidence_refs':[],
                'technical_error':None,'raw_output':'test'})
    with TestClient(create_app(settings,service,TOKEN)) as client:
        csv=client.get('/results/'+job['result_id']+'/export?format=csv',headers=HEADERS).text
        assert "'  =1+1" in csv
        jsonl=client.get('/results/'+job['result_id']+'/export?format=jsonl',headers=HEADERS).text
        assert '  =1+1' in jsonl
        assert client.get('/events/..%2F..%2Fsecret',headers=HEADERS).status_code==404
