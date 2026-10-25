"""Offline evaluation coordinator using the same singleton Service and queue.

Stop the HTTP server first; the shared service.lock refuses concurrent owners.
No labels, rubric, or provenance are added to model payloads.
"""
import json
import platform
import psutil
import time
from pathlib import Path
from uuid import uuid4
from .config import MODELS
from .evaluation_data import lock_dataset, verify_locked
from .evaluation_metrics import aggregate, comparison, timings, sum_measure
from .evaluation_resources import ResourceMonitor
from .payload import build_payload, PROMPT, SCHEMA
from .storage import canonical, digest, now

META=('model','digest','template_sha256','ollama_version')


class EvaluationRunner:
    def __init__(self,service,monitor=ResourceMonitor):
        self.service=service; self.store=service.store; self.monitor=monitor
    def payload(self,case_id):
        with self.store.connect() as db: row=db.execute('SELECT snapshot FROM cases WHERE case_id=?',(case_id,)).fetchone()
        snapshot=json.loads(row[0]); events=[]
        for ref in snapshot['event_refs']:
            events.append(dict(json.loads(self.store.event(ref)['normalized']),event_ref=ref))
        return build_payload(events,[g for g in snapshot['links'] if g.get('relation')=='group'])
    def check_lock(self):
        if self.service.settings.model_dump()!=self.lock['settings']: raise ValueError('EVALUATION_CONFIG_CHANGED')
        prompt_path=Path(__file__).resolve().parents[1]/'prompts/windows-log-v1.txt'
        if digest(prompt_path.read_text(encoding='utf-8').encode())!=self.lock['prompt_sha256']:
            raise ValueError('EVALUATION_PROMPT_CHANGED')
        if digest(canonical(SCHEMA).encode())!=self.lock['schema_sha256']: raise ValueError('EVALUATION_SCHEMA_CHANGED')
        for model in MODELS:
            current=self.service.runtime.client.inspect(model)
            if {k:current.get(k) for k in META}!=self.lock['models'][model]: raise ValueError('EVALUATION_MODEL_CHANGED')
    def run_case(self,case_id,model):
        self.check_lock()
        payload=self.payload(case_id)
        checks={m:self.service.runtime.guard.check(self.lock['models'][m],payload['messages'],self.service.settings) for m in MODELS}
        if not all(c['allowed'] for c in checks.values()):
            return {'label':'UNKNOWN','reason':'Both models must pass context preflight','technical_error':'COMPARISON_PREFLIGHT_FAILED',
                    'preflight_models':checks,'raw_output':None,'response':None,'wall_seconds':None,
                    'payload':payload,'metadata':self.lock['models'][model],'result_id':None}
        with self.monitor() as monitor:
            job=self.service.submit(case_id,model,str(uuid4()))
            deadline=time.monotonic()+self.service.settings.inference_timeout_seconds+30
            while job['state']!='completed':
                if time.monotonic()>deadline: raise RuntimeError('Evaluation wait expired; request retained: '+job['request_id'])
                time.sleep(.01); job=self.service.status(job['request_id'])
        result={**job['result'],'result_id':job['result_id'],'request_id':job['request_id'],'resources':monitor.report()}
        self.check_lock()
        if result.get('technical_error')=='MODEL_CHANGED': raise ValueError('EVALUATION_MODEL_CHANGED')
        if result.get('payload',{}).get('payload_sha256')!=payload['payload_sha256']:
            raise ValueError('EVALUATION_PAYLOAD_CHANGED')
        return result
    def persist(self):
        with self.store.connect() as db:
            db.execute('UPDATE evaluations SET report=? WHERE evaluation_id=?',(canonical(self.report),self.evaluation_id))
    def run(self,document):
        locked=lock_dataset(self.store,document); verify_locked(self.store,locked)
        warmups=[e for e in locked['entries'] if e['split']=='warmup']
        evaluation=[e for e in locked['entries'] if e['split']=='evaluation']
        if len(warmups)!=1 or not evaluation: raise ValueError('Require one independent neutral warmup and at least one evaluation case')
        with self.store.connect() as db:
            if db.execute("SELECT count(*) FROM requests WHERE state!='completed'").fetchone()[0]:
                raise ValueError('Finish existing jobs before evaluation')
        self.lock={'settings':self.service.settings.model_dump(),'prompt_sha256':digest(PROMPT.encode()),
                   'schema_sha256':digest(canonical(SCHEMA).encode()),'models':{}}
        for model in MODELS:
            metadata=self.service.runtime.client.inspect(model)
            self.lock['models'][model]={k:metadata.get(k) for k in META}
        self.evaluation_id=str(uuid4())
        self.report={'state':'running','synthetic':locked['synthetic'],'lock':self.lock,
                     'environment':{'python':platform.python_version(),'platform':platform.platform(),
                     'processor':platform.processor() or None,'logical_cpu_count':psutil.cpu_count(),
                     'machine_ram_bytes':psutil.virtual_memory().total,
                     'resource_scope':'Current singleton service process includes evaluation coordinator; Ollama process tree sampled separately'},
                     'started_at':now(),'rows':[],'warmup':[],'comparison':[],'timings':[],
                     'recommendation':None,'limitation':'No automatic best-model claim; inspect coverage, labels and manual session review.'}
        with self.store.connect() as db:
            db.execute('INSERT INTO evaluations VALUES(?,?,?,?,?)',(self.evaluation_id,now(),canonical(locked),locked['manifest_hash'],canonical(self.report)))
        try:
            single={}
            for entry in evaluation:
                single[entry['case_id']]=[self.store.create_case([ref],config={'evaluation_mode':'single','synthetic':locked['synthetic']}) for ref in entry['event_refs']]
            for model in MODELS:
                self.service.runtime.unload()
                warmup=self.run_case(warmups[0]['case_id'],model)
                self.report['warmup'].append({'model':model,'attempt':warmup}); self.persist()
                if warmup.get('technical_error'): raise RuntimeError('WARMUP_FAILED; no scored attempts for this model')
                for mode in ('single','grouped'):
                    for entry in evaluation:
                        for repeat in (1,2,3):
                            ids=single[entry['case_id']] if mode=='single' else [entry['case_id']]
                            attempts=[self.run_case(case_id,model) for case_id in ids]
                            row={'case_id':entry['case_id'],'model':model,'mode':mode,'repeat':repeat,
                                 'ground_truth':entry['label'],'label':aggregate(attempts),'attempts':attempts,'review':None,
                                 'wall_seconds':sum_measure(attempts,'wall_after_load_seconds'),
                                 'model_load_wall_seconds':sum_measure(attempts,'model_load_wall_seconds'),
                                 'durations_ns':{key:sum_measure([a.get('response') or {} for a in attempts],key)
                                    for key in ('load_duration','prompt_eval_duration','eval_duration')}}
                            self.report['rows'].append(row); self.persist()
            verify_locked(self.store,locked)
            self.report['state']='completed'
        except Exception as exc:
            self.report['state']='failed'; self.report['error']=str(exc)
            raise
        finally:
            self.report['finished_at']=now()
            self.report['comparison']=comparison(self.report['rows'])
            self.report['timings']=timings(self.report['rows'])
            self.persist()
        return self.evaluation_id


if __name__=='__main__':
    import argparse
    from .config import load_settings
    from .storage import Store
    from .context_tokens import ContextGuard
    from .ollama import Ollama
    from .inference import Inference
    from .service import Service
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest',type=Path); parser.add_argument('--config',type=Path,default=Path('config.local.toml'))
    args=parser.parse_args(); settings=load_settings(args.config); store=Store(settings.data_root)
    service=Service(store,settings,Inference(Ollama(),ContextGuard(store.root/'tokenizers')))
    service.start()
    try: print(EvaluationRunner(service).run(json.loads(args.manifest.read_text(encoding='utf-8'))))
    finally: service.close()
