import csv
import io
import json
from pathlib import Path

import pytest
from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.evaluation_metrics import comparison, metrics
from app.evaluation_reports import export_evaluation, read_evaluation
from app.storage import Store, canonical


def row(truth, predicted, **extra):
    return dict(ground_truth=truth, label=predicted, attempts=[], review=None,
                model='qwen', mode='grouped', repeat=1, **extra)


def test_all_six_confusion_cells_and_abstention_penalty():
    rows=[row(truth, predicted) for truth in ('NORMAL','ALERT')
          for predicted in ('NORMAL','ALERT','UNKNOWN')]
    result=metrics(rows)
    assert result['accuracy']=={'numerator':2,'denominator':6,'value':1/3}
    assert result['precision']['value']==.5
    assert result['recall']['value']==1/3
    assert result['f1']['value']==.4
    assert result['coverage']['value']==2/3
    assert result['fn']==2
    assert result['confusion_matrix']=={t:{p:1 for p in ('NORMAL','ALERT','UNKNOWN')}
                                       for t in ('NORMAL','ALERT')}


def test_empty_and_no_positive_predictions_are_not_fabricated_scores():
    assert metrics([])['accuracy']['value'] is None
    result=metrics([row('NORMAL','NORMAL')])
    assert result['accuracy']['value']==1
    assert all(result[k]['value'] is None for k in ('precision','recall','f1'))
    result=metrics([row('NORMAL','UNKNOWN'),row('ALERT','UNKNOWN')])
    assert result['accuracy']['value']==0
    assert result['recall']['value']==0


def test_models_modes_and_repeats_are_separate():
    rows=[]
    for model in ('qwen','llama'):
        for mode in ('single','grouped'):
            for repeat in (1,2,3):
                rows.append({**row('ALERT','ALERT' if model=='qwen' else 'UNKNOWN'),
                             'model':model,'mode':mode,'repeat':repeat})
    result=comparison(rows)
    assert len(result)==12 and sum(r['primary'] for r in result)==4
    assert all(r['cases']==1 for r in result)
    assert all(r['accuracy']['value']==(1 if r['model']=='qwen' else 0) for r in result)


def test_reject_unsupported_labels():
    with pytest.raises(ValueError):
        metrics([row('UNKNOWN','NORMAL')])


def test_old_report_recomputed_for_ui_and_exports_without_db_mutation(tmp_path):
    store=Store(tmp_path/'store')
    manifest={'name':'Test <script>', 'synthetic':True,'counts':{},
              'missing_targets':{'development':10,'evaluation':40,'evaluation_groups':{}}}
    report={'state':'completed','rows':[row('ALERT','ALERT'),row('NORMAL','UNKNOWN')],
            'comparison':[{'stale':True}], 'timings':[]}
    original=canonical(report)
    with store.connect() as db:
        db.execute('INSERT INTO evaluations VALUES(?,?,?,?,?)',('test','today',canonical(manifest),'hash',original))
    document=read_evaluation(store,'test')
    assert document['report']['comparison'][0]['accuracy']['value']==.5
    with store.connect() as db:
        assert db.execute('SELECT report FROM evaluations').fetchone()[0]==original
    exported,_=export_evaluation(document,'jsonl')
    assert json.loads(exported.splitlines()[0])['comparison'][0]['accuracy']['value']==.5
    exported,_=export_evaluation(document,'csv')
    record=next(csv.DictReader(io.StringIO(exported)))
    assert json.loads(record['accuracy'])['denominator']==2
    assert json.loads(record['confusion_matrix'])['NORMAL']['UNKNOWN']==1
    env=Environment(loader=FileSystemLoader(Path(__file__).resolve().parents[1]/'templates'),
                    autoescape=select_autoescape())
    html=env.get_template('evaluation.html').render(evaluations=[],selected=document)
    assert '50.00%' in html and 'Accuracy' in html and 'mAP — chưa áp dụng' in html
    assert 'Test &lt;script&gt;' in html
