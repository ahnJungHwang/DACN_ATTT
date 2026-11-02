import json
from copy import deepcopy
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from app.api import create_app
from app.config import Settings,MODELS
from app.storage import Store
from app.import_logs import import_files
from app.cases import create_cases
from app.evaluation_data import lock_dataset,verify_locked
from app.evaluation_metrics import aggregate,metrics,timings
from app.evaluation_resources import ResourceMonitor
from app.evaluation_runner import EvaluationRunner
from app.evaluation_reports import read_evaluation,record_review,export_evaluation
from app.service import Service


class Guard:
    def check(self,*args): return {'allowed':True,'error':None,'input_tokens':123}


class Runtime:
    degraded=False
    def __init__(self): self.client=self; self.guard=Guard(); self.calls=[]; self.changed=False
    def inspect(self,model): return {'model':model,'digest':'changed' if self.changed else 'synthetic','template_sha256':'synthetic','ollama_version':'mock'}
    def unload(self): pass
    def analyze(self,metadata,payload,settings):
        self.calls.append(payload)
        return {'label':'NORMAL','reason':'Synthetic test only','evidence_refs':list(payload['reference_map'].values()),
                'technical_error':None,'raw_output':'{"label":"NORMAL"}','response':{'load_duration':1,'prompt_eval_duration':2,'eval_duration':3},
                'payload':payload,'metadata':metadata,'wall_seconds':.04,'model_load_wall_seconds':.01,'wall_after_load_seconds':.03}


def make_dataset(store,tmp_path):
    entries=[]
    xml=(Path(__file__).parent/'fixtures/synthetic-security.xml').read_text(encoding='utf-8')
    for i,split in enumerate(('warmup','development','evaluation','evaluation')):
        path=tmp_path/f'synthetic-{i}.xml'
        path.write_text(xml.replace('synthetic-vm',f'synthetic-vm-{i}'),encoding='utf-8')
        report=import_files(store,{'Security':path},Settings(),synthetic=True)
        case=create_cases(store,report['import_id'],Settings())['case_ids'][0]
        with store.connect() as db: snapshot=json.loads(db.execute('SELECT snapshot FROM cases WHERE case_id=?',(case,)).fetchone()[0])
        entries.append({'case_id':case,'split':split,'group':'normal' if i!=3 else 'password_guessing',
                        'label':'NORMAL' if i!=3 else 'ALERT','run_ids':[f'run-{i}'],'session_keys':[f'host-{i}/boot-1/0x123'],
                        'annotator':'Synthetic fixture author','rationale':'Test only; not a real attack label',
                        'expected_accounts':['demo'],'expected_sessions':['0x123'],'evidence_refs':snapshot['event_refs']})
    return {'name':'SYNTHETIC pipeline verification','synthetic':True,'entries':entries}


def test_lock_hash_and_shortfall(tmp_path):
    store=Store(tmp_path/'store'); doc=make_dataset(store,tmp_path)
    locked=lock_dataset(store,doc); verify_locked(store,locked)
    assert locked['missing_targets']['development']==9 and locked['missing_targets']['evaluation']==38
    changed=deepcopy(locked); changed['entries'][0]['label']='ALERT'
    with pytest.raises(ValueError,match='Manifest hash'): verify_locked(store,changed)
    source=store.event(locked['entries'][0]['event_refs'][0])
    (store.root/source['relative_path']).write_bytes(b'tampered')
    with pytest.raises(ValueError,match='Raw evidence'): verify_locked(store,locked)


@pytest.mark.parametrize('field',['run_ids','session_keys'])
def test_provenance_leakage(tmp_path,field):
    store=Store(tmp_path/'store'); doc=make_dataset(store,tmp_path)
    doc['entries'][2][field]=doc['entries'][1][field]
    with pytest.raises(ValueError,match='Split leakage'): lock_dataset(store,doc)


def test_mixed_source_leaks_across_splits(tmp_path):
    store=Store(tmp_path/'store'); doc=make_dataset(store,tmp_path)
    refs=doc['entries'][1]['evidence_refs']+doc['entries'][2]['evidence_refs']
    doc['entries'][2]['case_id']=store.create_case(refs)
    with pytest.raises(ValueError,match='Split leakage'): lock_dataset(store,doc)


def test_synthetic_cannot_be_presented_as_real(tmp_path):
    store=Store(tmp_path/'store'); doc=make_dataset(store,tmp_path); doc['synthetic']=False
    with pytest.raises(ValueError,match='Synthetic/real'): lock_dataset(store,doc)


def test_aggregation_and_denominators():
    normal={'label':'NORMAL','technical_error':None,'response':{}}
    unknown={'label':'UNKNOWN','technical_error':'TIMEOUT','response':None}
    alert={'label':'ALERT','technical_error':None,'response':{}}
    assert aggregate([])=='UNKNOWN'
    assert aggregate([normal,unknown])=='UNKNOWN'
    assert aggregate([normal,unknown,alert])=='ALERT'
    rows=[{'label':'UNKNOWN','ground_truth':'ALERT','attempts':[unknown],'review':None},
          {'label':'UNKNOWN','ground_truth':'NORMAL','attempts':[unknown],'review':None}]
    report=metrics(rows)
    assert report['fn']==1 and report['tn']==0 and report['coverage']['value']==0
    assert report['precision']['value'] is None and report['f1']['value']==0
    assert report['json_valid_response']['value'] is None
    assert report['account_session_error']['value'] is None
    base={'case_id':'c','model':'m','mode':'single','wall_seconds':1,'attempts':[normal]}
    assert timings([{**base,'repeat':1},{**base,'repeat':2}])[0]['median_wall_seconds'] is None
    assert timings([{**base,'repeat':r} for r in (1,2,3)])[0]['median_wall_seconds']==1


def test_resource_missing_is_null_with_reason():
    monitor=ResourceMonitor(); monitor.samples=[{'service_rss_bytes':100,'ollama_rss_bytes':None,'ollama_vram_bytes':None,
                                                'reasons':{'ollama_vram_bytes':'WDDM unavailable'}}]
    result=monitor.report()['metrics']
    assert result['service_rss_bytes']['peak']==100
    assert result['ollama_vram_bytes']['peak'] is None and result['ollama_vram_bytes']['reasons']


def test_grouped_and_single_same_case_with_multiple_events(tmp_path):
    store=Store(tmp_path/'store'); doc=make_dataset(store,tmp_path)
    refs=doc['entries'][2]['evidence_refs']+doc['entries'][3]['evidence_refs']
    mixed=deepcopy(doc['entries'][2]); mixed.update(case_id=store.create_case(refs,config={'synthetic':True}),
        evidence_refs=refs,run_ids=['run-2','run-3'],session_keys=['host-2/boot-1/0x123','host-3/boot-1/0x123'],group='mixed_different_session')
    doc['entries']=doc['entries'][:2]+[mixed]
    service=Service(store,Settings(),Runtime()); service.start()
    try: eid=EvaluationRunner(service).run(doc)
    finally: service.close()
    rows=read_evaluation(store,eid)['report']['rows']
    assert all(len(r['attempts'])==2 and r['wall_seconds']==.06 for r in rows if r['mode']=='single')
    assert all(len(r['attempts'])==1 and r['wall_seconds']==.03 for r in rows if r['mode']=='grouped')


def test_options_drift_and_pair_preflight(tmp_path):
    store=Store(tmp_path/'store'); doc=make_dataset(store,tmp_path)
    runtime=Runtime(); service=Service(store,Settings(),runtime); service.start(); runner=EvaluationRunner(service)
    try:
        eid=runner.run(doc)
        service.settings.temperature=0.2
        with pytest.raises(ValueError,match='CONFIG_CHANGED'): runner.check_lock()
        service.settings.temperature=0.0
        runtime.guard.check=lambda metadata,*args: {'allowed':metadata['model']==MODELS[0],'error':'TEST_LIMIT'}
        count=len(runtime.calls)
        result=runner.run_case(doc['entries'][2]['case_id'],MODELS[0])
        assert result['technical_error']=='COMPARISON_PREFLIGHT_FAILED' and len(runtime.calls)==count
    finally: service.close()


def run_fixture(tmp_path):
    store=Store(tmp_path/'store'); doc=make_dataset(store,tmp_path)
    runtime=Runtime(); service=Service(store,Settings(),runtime); service.start()
    try:
        runner=EvaluationRunner(service)
        evaluation_id=runner.run(doc)
    finally: service.close()
    return store,doc,evaluation_id,runtime


def test_runner_repeats_reviews_export_and_local_report(tmp_path):
    store,doc,eid,runtime=run_fixture(tmp_path)
    result=read_evaluation(store,eid); report=result['report']
    assert report['state']=='completed' and len(report['rows'])==24 and len(report['warmup'])==2
    assert len(runtime.calls)==26
    assert all('ground_truth' not in str(p) and 'Synthetic fixture author' not in str(p) for p in runtime.calls)
    assert all(t['complete_three_repeats'] for t in report['timings'])
    assert len([c for c in report['comparison'] if c['primary']])==6
    row=report['rows'][0]; entry=next(e for e in doc['entries'] if e['case_id']==row['case_id'])
    review_args={k:row[k] for k in ('case_id','model','mode','repeat')}
    record_review(store,eid,**review_args,annotator='Reviewer',incorrect=False,rationale='Account and session match',evidence_refs=entry['evidence_refs'])
    result=read_evaluation(store,eid)
    assert result['report']['rows'][0]['review']['annotator']=='Reviewer'
    exported,_=export_evaluation(result,'jsonl')
    assert json.loads(exported.splitlines()[0])['synthetic'] is True
    csv,_=export_evaluation(result,'csv'); assert 'manifest_hash' in csv and 'primary' in csv
    service=Service(store,Settings(),Runtime())
    token='test-only-evaluation-token-000000000'
    with TestClient(create_app(Settings(),service,token)) as client:
        assert client.get('/reports').status_code==401
        headers={'Authorization':'Bearer '+token}
        page=client.get('/reports?evaluation_id='+eid,headers=headers)
        assert page.status_code==200 and 'MẪU TỔNG HỢP' in page.text
        assert client.get('/evaluations/'+eid+'/export?format=csv',headers=headers).status_code==200
        assert client.get('/evaluations/absent',headers=headers).status_code==404


def test_model_drift_stops_and_preserves_failed_report(tmp_path):
    store=Store(tmp_path/'store'); doc=make_dataset(store,tmp_path)
    runtime=Runtime(); original=runtime.analyze
    def changing(*args):
        response=original(*args); runtime.changed=True; return response
    runtime.analyze=changing
    service=Service(store,Settings(),runtime); service.start(); runner=EvaluationRunner(service)
    try:
        with pytest.raises(ValueError,match='EVALUATION_MODEL_CHANGED'): runner.run(doc)
        report=read_evaluation(store,runner.evaluation_id)['report']
        assert report['state']=='failed' and report['rows']==[] and len(runtime.calls)==1
    finally: service.close()


def test_baseline_integrated_same_cases_and_exports(tmp_path):
    store,doc,eid,runtime=run_fixture(tmp_path)
    result=read_evaluation(store,eid)
    baseline=result['report']['baseline_rows']
    scored={e['case_id'] for e in doc['entries'] if e['split']=='evaluation'}
    assert len(baseline)==4
    assert {r['case_id'] for r in baseline}==scored
    assert {r['mode'] for r in baseline}=={'single','grouped'}
    assert all(r['repeat']==1 and r['model']=='rules-only' for r in baseline)
    assert len(runtime.calls)==26  # Baseline introduces no inference requests.
    for row in baseline:
        refs=next(e['evidence_refs'] for e in doc['entries'] if e['case_id']==row['case_id'])
        assert all(set(a['evidence_refs'])<=set(refs) for a in row['attempts'])
    encoded,_=export_evaluation(result,'jsonl')
    records=[json.loads(line) for line in encoded.splitlines()]
    assert len([r for r in records if r['type']=='baseline_result'])==4
    csv,_=export_evaluation(result,'csv')
    assert 'rules-only' in csv
    comparisons=[r for r in result['report']['comparison'] if r['model']=='rules-only']
    assert len(comparisons)==2 and all(r['cases']==2 for r in comparisons)
    assert all(r['json_valid_response']['value'] is None for r in comparisons)
    assert result['report']['lock']['baseline_sha256']
