"""Local evaluation export and attributed manual review."""
import csv
import io
import json
from .evaluation_metrics import comparison
from .storage import canonical, now


def read_evaluation(store,evaluation_id):
    with store.connect() as db: row=db.execute('SELECT * FROM evaluations WHERE evaluation_id=?',(evaluation_id,)).fetchone()
    if row is None: raise KeyError(evaluation_id)
    return dict(row,manifest=json.loads(row['manifest']),report=json.loads(row['report']) if row['report'] else None)


def record_review(store,evaluation_id,*,case_id,model,mode,repeat,annotator,incorrect,rationale,evidence_refs):
    if not annotator.strip() or not rationale.strip() or type(incorrect) is not bool:
        raise ValueError('Manual review requires named reviewer, rationale and explicit judgement')
    with store.connect() as db:
        db.execute('BEGIN IMMEDIATE')
        row=db.execute('SELECT manifest,report FROM evaluations WHERE evaluation_id=?',(evaluation_id,)).fetchone()
        if row is None: raise KeyError(evaluation_id)
        report=json.loads(row['report']); manifest=json.loads(row['manifest'])
        if report['state']=='running': raise ValueError('Wait for evaluation to stop before manual review')
        entry=next((e for e in manifest['entries'] if e['case_id']==case_id),None)
        target=next((r for r in report['rows'] if (r['case_id'],r['model'],r['mode'],r['repeat'])==(case_id,model,mode,repeat)),None)
        if entry is None or target is None: raise KeyError('Evaluation row not found')
        if not evidence_refs or not set(evidence_refs)<=set(entry['event_refs']): raise ValueError('Review evidence must belong to the case')
        review={'annotator':annotator,'incorrect':incorrect,'rationale':rationale,'evidence_refs':evidence_refs,
                'reviewed_at':now(),'rubric_version':manifest['rubric_version']}
        target.setdefault('review_history',[]).append(review); target['review']=review
        report['comparison']=comparison(report['rows'])
        db.execute('UPDATE evaluations SET report=? WHERE evaluation_id=?',(canonical(report),evaluation_id))
    return review


def safe_cell(value):
    text=canonical(value) if isinstance(value,(dict,list)) else str(value if value is not None else '')
    return "'"+text if text.lstrip().startswith(('=','+','-','@')) else text


def export_evaluation(document,format):
    report=document['report'] or {}; manifest=document['manifest']
    common={'evaluation_id':document['evaluation_id'],'manifest_hash':document['manifest_hash'],'synthetic':manifest['synthetic']}
    if format=='jsonl':
        records=[{**common,'type':'manifest','manifest':manifest,'lock':report.get('lock'),'state':report.get('state'),
                  'environment':report.get('environment'),'error':report.get('error'),'warmup':report.get('warmup'),
                  'comparison':report.get('comparison'),'timings':report.get('timings')}]
        records += [{**common,'type':'case_result',**row} for row in report.get('rows',[])]
        return ''.join(canonical(row)+'\n' for row in records),'application/x-ndjson'
    if format!='csv': raise ValueError('Unsupported export format')
    buffer=io.StringIO(newline=''); writer=csv.writer(buffer)
    fields=['evaluation_id','manifest_hash','synthetic','model','mode','repeat','primary','cases','tp','fp','fn','tn','unknown',
            'technical_error_cases','precision','recall','f1','coverage','false_positive_rate','json_valid_response','response_attempt','account_session_error']
    writer.writerow(fields)
    for row in report.get('comparison',[]): writer.writerow([safe_cell({**common,**row}.get(field)) for field in fields])
    return buffer.getvalue(),'text/csv'
