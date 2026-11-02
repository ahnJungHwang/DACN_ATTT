from fastapi.testclient import TestClient
from app.api import create_app
from app.config import Settings, MODELS
from app.service import Service
from app.storage import Store
from test_service import Runtime


def test_activity_auth_and_real_queue(tmp_path):
    store=Store(tmp_path); runtime=Runtime()
    service=Service(store,Settings(),runtime)
    case=store.create_case([])
    token='test-activity-token-not-secret-000000'
    try:
        # No lifespan: keep submitted request queued deterministically.
        client=TestClient(create_app(Settings(),service,token))
        assert client.get('/activity').status_code==401
        job=service.submit(case,MODELS[0])
        data=client.get('/activity',headers={'Authorization':'Bearer '+token}).json()
        assert len(data['models'])==2
        task=data['models'][0]['tasks'][0]
        assert task['request_id']==job['request_id']
        assert task['case_id']==case and task['state']=='queued'
        assert task['sources']==[] and task['event_count']==0
    finally:
        service.close()
