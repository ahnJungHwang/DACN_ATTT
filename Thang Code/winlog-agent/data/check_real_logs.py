"""One-off technical verification on existing copied logs, without ground truth."""
import json
import time
from pathlib import Path
from uuid import uuid4
from app.config import Settings, MODELS
from app.storage import Store, canonical, now, digest
from app.ollama import Ollama
from app.context_tokens import ContextGuard
from app.inference import Inference
from app.service import Service
from app.payload import build_payload

root = Path('data')
store = Store(root / 'verify-original')
settings = Settings(data_root=str(store.root))
client = Ollama()
runtime = Inference(client, ContextGuard(root / 'tokenizers'))
if runtime.loaded():
    raise RuntimeError('External model loaded')
metas = [client.inspect(m) for m in MODELS]
selected = {}
with store.connect() as db:
    cases = db.execute('SELECT * FROM cases ORDER BY created_at,case_id').fetchall()
    if db.execute("SELECT count(*) FROM requests WHERE state != 'completed'").fetchone()[0]:
        raise RuntimeError('Existing unfinished request')
for case in cases:
    snap = json.loads(case['snapshot'])
    groups = [g for g in snap['links'] if g.get('relation') == 'group']
    kinds = {g.get('kind') for g in groups}
    if len(kinds) != 1:
        continue
    kind = next(iter(kinds))
    if kind in selected:
        continue
    events = [dict(json.loads(store.event(r)['normalized']), event_ref=r) for r in snap['event_refs']]
    payload = build_payload(events, groups)
    checks = [runtime.guard.check(m, payload['messages'], settings) for m in metas]
    if all(c['allowed'] for c in checks):
        selected[kind] = {'case_id':case['case_id'], 'event_count':len(events)}
if not selected:
    raise RuntimeError('No whole case passes both context guards')
report = {'created_at':now(), 'purpose':'technical smoke, not accuracy evaluation',
          'ground_truth':None, 'collection_manifest_missing':True,
          'selection':'first whole case per group kind ordered by created_at,case_id passing both context guards',
          'cases':selected, 'sources':{}, 'results':[]}
for name in ('security.xml','powershell.xml'):
    report['sources'][name] = digest((Path('../log-test') / name).read_bytes())
out = root / ('real-log-verification-' + str(uuid4()) + '.json')
def save():
    out.write_text(canonical(report), encoding='utf-8')
save()
service = Service(store, settings, runtime)
service.start()
try:
    for model in MODELS:
        for kind, case in selected.items():
            status = service.submit(case['case_id'], model, str(uuid4()))
            deadline = time.monotonic() + 360
            while status['state'] != 'completed':
                if time.monotonic() > deadline:
                    raise RuntimeError('Verification deadline exceeded')
                time.sleep(.5)
                status = service.status(status['request_id'])
            result = status['result']
            for ref in result['evidence_refs']:
                assert store.event(ref)['raw_xml']
            report['results'].append({'model':model, 'kind':kind, **status})
            save()
            print(model, kind, result['label'], result['technical_error'], round(result['wall_seconds'] or 0,2), flush=True)
            if service.degraded or runtime.degraded:
                raise RuntimeError('Inference degraded')
finally:
    service.close()
    client.close()
    save()
print(str(out), flush=True)
