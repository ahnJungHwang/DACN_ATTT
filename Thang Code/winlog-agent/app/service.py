"""Single-owner SQLite queue with durable idempotency and bounded inference."""
import json
import os
import threading
import time
from uuid import UUID, uuid4
from .config import MODELS, Settings
from .payload import build_payload
from .results import save_result, read_result
from .storage import canonical, digest, now


class ServiceError(Exception):
    def __init__(self,status,code):
        self.status,self.code=status,code
        super().__init__(code)


class Singleton:
    def __init__(self,path):
        self.handle=path.open('a+b')
        try:
            self.handle.seek(0)
            if self.handle.read(1)==b'':
                self.handle.write(b'0'); self.handle.flush()
            self.handle.seek(0)
            if os.name=='nt':
                import msvcrt
                msvcrt.locking(self.handle.fileno(),msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                fcntl.flock(self.handle.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError:
            self.handle.close()
            raise ServiceError(503,'SERVICE_ALREADY_RUNNING')

    def close(self):
        self.handle.close()


class Service:
    def __init__(self,store,settings,runtime):
        self.store,self.settings,self.runtime=store,settings,runtime
        self.owner=Singleton(store.root/'service.lock')
        self.stop=threading.Event()
        self.wake=threading.Event()
        self.worker=None
        self.degraded=False
        with store.connect() as db:
            interrupted=db.execute("SELECT * FROM requests WHERE state='running'").fetchall()
        for request in interrupted:
            save_result(store,request['request_id'],self.error_document(json.loads(request['payload']),'INTERRUPTED'))

    def start(self):
        self.worker=threading.Thread(target=self.loop,daemon=True,name='winlog-inference')
        self.worker.start()

    @staticmethod
    def error_document(job,code):
        return {'label':'UNKNOWN','reason':code,'evidence_refs':[],'technical_error':code,
                'raw_output':None,'payload':job.get('payload'),'metadata':job.get('metadata'),
                'options':job.get('settings'),'wall_seconds':None}

    def submit(self,case_id,model,key=None):
        if model not in MODELS: raise ServiceError(422,'MODEL_NOT_ALLOWED')
        if key is not None:
            try: key=str(UUID(key))
            except (ValueError,TypeError): raise ServiceError(422,'INVALID_IDEMPOTENCY_KEY')
        with self.store.connect() as db:
            case=db.execute('SELECT * FROM cases WHERE case_id=?',(case_id,)).fetchone()
        if case is None: raise ServiceError(404,'CASE_NOT_FOUND')
        settings=self.settings.model_dump()
        signature=digest(canonical({'case_id':case_id,'case_hash':case['snapshot_hash'],
                                   'model':model,'settings':settings}).encode())
        # Existing requests remain recoverable even while Ollama is unavailable.
        with self.store.connect() as db:
            existing=db.execute('SELECT * FROM requests WHERE idempotency_key=?',(key,)).fetchone() if key else None
        if existing:
            if existing['payload_hash']!=signature: raise ServiceError(409,'IDEMPOTENCY_CONFLICT')
            return self.status(existing['request_id'])
        if self.degraded or self.runtime.degraded: raise ServiceError(503,'SERVICE_DEGRADED')
        try: metadata=self.runtime.client.inspect(model)
        except Exception as exc: raise ServiceError(503,'MODEL_UNAVAILABLE') from exc
        snapshot=json.loads(case['snapshot'])
        events=[]
        for ref in snapshot['event_refs']:
            row=self.store.event(ref)
            events.append(dict(json.loads(row['normalized']),event_ref=ref))
        groups=[link for link in snapshot['links'] if link.get('relation')=='group']
        payload=build_payload(events,groups)
        job={'metadata':metadata,'payload':payload,'settings':settings}
        request_id=key or str(uuid4()); result_id=str(uuid4())
        with self.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            existing=db.execute('SELECT * FROM requests WHERE idempotency_key=?',(key,)).fetchone() if key else None
            if existing:
                if existing['payload_hash']!=signature: raise ServiceError(409,'IDEMPOTENCY_CONFLICT')
                request_id=existing['request_id']
            else:
                queued=db.execute("SELECT count(*) FROM requests WHERE state='queued'").fetchone()[0]
                if queued>=self.settings.queue_capacity: raise ServiceError(429,'QUEUE_FULL')
                db.execute('INSERT INTO requests VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                           (request_id,key,case_id,model,signature,canonical(job),'queued',result_id,now(),None,None))
        self.wake.set()
        return self.status(request_id)

    def status(self,request_id):
        with self.store.connect() as db:
            row=db.execute('SELECT * FROM requests WHERE request_id=?',(request_id,)).fetchone()
        if row is None: raise ServiceError(404,'REQUEST_NOT_FOUND')
        envelope={k:row[k] for k in ('request_id','result_id','state')}
        envelope['status_url']='/results/'+row['result_id']
        if row['state']=='completed': envelope['result']=read_result(self.store,row['result_id'])
        return envelope

    def result_status(self,result_id):
        with self.store.connect() as db:
            row=db.execute('SELECT request_id FROM requests WHERE result_id=?',(result_id,)).fetchone()
        if row is None: raise ServiceError(404,'RESULT_NOT_FOUND')
        return self.status(row['request_id'])

    def execute(self,request):
        job=json.loads(request['payload'])
        settings=Settings.model_validate(job['settings'])
        output=[]
        def run():
            try:
                current=self.runtime.client.inspect(request['model'])
                if any(current.get(k)!=job['metadata'].get(k) for k in ('digest','template_sha256','ollama_version')):
                    output.append(self.error_document(job,'MODEL_CHANGED'))
                else: output.append(self.runtime.analyze(job['metadata'],job['payload'],settings))
            except Exception:
                self.runtime.degraded=True
                output.append(self.error_document(job,'INFERENCE_FAILED'))
        thread=threading.Thread(target=run,daemon=True,name='winlog-call')
        thread.start(); thread.join(settings.inference_timeout_seconds)
        if thread.is_alive():
            save_result(self.store,request['request_id'],self.error_document(job,'TIMEOUT'))
            # Do not start another inference while the underlying call may still run.
            self.degraded=True
            thread.join()
            try:
                self.runtime.unload()
                if not self.runtime.degraded: self.degraded=False
            except Exception: self.degraded=True
        else:
            save_result(self.store,request['request_id'],output[0])

    def loop(self):
        try:
            while not self.stop.is_set():
                if self.degraded or self.runtime.degraded:
                    self.wake.wait(.1); self.wake.clear(); continue
                with self.store.connect() as db:
                    db.execute('BEGIN IMMEDIATE')
                    request=db.execute("SELECT * FROM requests WHERE state='queued' ORDER BY created_at,request_id LIMIT 1").fetchone()
                    if request: db.execute("UPDATE requests SET state='running',started_at=? WHERE request_id=?",(now(),request['request_id']))
                if request:
                    self.execute(request)
                else:
                    self.wake.wait(.1); self.wake.clear()
        except Exception:
            self.degraded=True

    def close(self):
        self.stop.set(); self.wake.set()
        if self.worker:
            self.worker.join(timeout=2)
            if self.worker.is_alive():
                # Retain singleton ownership until process exit; never allow a second worker.
                return
        try: self.runtime.unload()
        finally: self.owner.close()
