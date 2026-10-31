from concurrent.futures import ThreadPoolExecutor
import threading
import time
from uuid import uuid4
import pytest
from app.service import Service,ServiceError
from app.storage import Store
from app.config import Settings,MODELS


class Runtime:
    degraded=False
    def __init__(self):
        self.client=self; self.calls=0; self.active=0; self.peak=0; self.release=threading.Event()
    def inspect(self,model): return {'model':model,'digest':'test','template_sha256':'test','ollama_version':'test'}
    def unload(self): pass
    def analyze(self,*args):
        self.calls+=1; self.active+=1; self.peak=max(self.peak,self.active)
        self.release.wait(4)
        self.active-=1
        return {'label':'UNKNOWN','technical_error':None,'raw_output':'{}','reason':'synthetic','evidence_refs':[]}


def setup(tmp_path,**kwargs):
    store=Store(tmp_path); case=store.create_case([]); runtime=Runtime()
    return Service(store,Settings(**kwargs),runtime),case,runtime


def wait_for(predicate):
    deadline=time.monotonic()+5
    while not predicate():
        assert time.monotonic()<deadline
        time.sleep(.01)


def test_singleton_concurrent_idempotency_and_queue(tmp_path):
    service,case,runtime=setup(tmp_path,queue_capacity=2)
    with pytest.raises(ServiceError): Service(service.store,Settings(),Runtime())
    key=str(uuid4())
    with ThreadPoolExecutor(max_workers=8) as pool:
        results=list(pool.map(lambda _:service.submit(case,MODELS[0],key),range(8)))
    assert len({r['result_id'] for r in results})==1
    with pytest.raises(ServiceError) as exc: service.submit(case,MODELS[1],key)
    assert exc.value.status==409
    service.submit(case,MODELS[0])
    with pytest.raises(ServiceError) as exc: service.submit(case,MODELS[0])
    assert exc.value.status==429
    assert 'result' not in results[0] and 'label' not in results[0]
    runtime.release.set(); service.start()
    wait_for(lambda:service.status(key)['state']=='completed')
    wait_for(lambda:runtime.calls==2)
    assert runtime.peak==1
    assert service.submit(case,MODELS[0],key)['state']=='completed'
    service.close()


def test_restart_does_not_replay_running(tmp_path):
    service,case,runtime=setup(tmp_path)
    req=service.submit(case,MODELS[0])
    with service.store.connect() as db: db.execute("UPDATE requests SET state='running'")
    service.close()
    restarted=Service(service.store,Settings(),Runtime())
    assert restarted.status(req['request_id'])['result']['technical_error']=='INTERRUPTED'
    restarted.close()


def test_timeout_keeps_next_request_waiting(tmp_path):
    service,case,runtime=setup(tmp_path,inference_timeout_seconds=1,response_wait_seconds=1)
    first=service.submit(case,MODELS[0]); second=service.submit(case,MODELS[1]); service.start()
    wait_for(lambda:service.status(first['request_id'])['state']=='completed')
    assert service.status(first['request_id'])['result']['technical_error']=='TIMEOUT'
    assert service.status(second['request_id'])['state']=='queued' and runtime.calls==1
    runtime.release.set()
    wait_for(lambda:service.status(second['request_id'])['state']=='completed')
    assert runtime.peak==1
    service.close()
