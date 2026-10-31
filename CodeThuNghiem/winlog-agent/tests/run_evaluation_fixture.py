"""Save an explicitly SYNTHETIC evaluation for inspecting the report UI."""
import json
from pathlib import Path
import sys
from uuid import uuid4
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from test_evaluation import run_fixture
from app.evaluation_reports import read_evaluation,export_evaluation

if __name__=='__main__':
    root=Path('data/evaluation-mock')/str(uuid4())
    root.mkdir(parents=True,exist_ok=True)
    store,manifest,eid,_=run_fixture(root)
    (root/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
    document=read_evaluation(store,eid)
    for format,name in [('jsonl','results.jsonl'),('csv','comparison.csv')]:
        content,_=export_evaluation(document,format)
        (root/name).write_text(content,encoding='utf-8')
    (root/'verification.json').write_text(json.dumps({'evaluation_id':eid,'synthetic':True,
        'state':document['report']['state'],'rows':len(document['report']['rows']),
        'missing_targets':document['manifest']['missing_targets']},indent=2),encoding='utf-8')
    print(json.dumps({'evaluation_id':eid,'folder':str(root.resolve()),'data_root':str(store.root),'synthetic':True}))
