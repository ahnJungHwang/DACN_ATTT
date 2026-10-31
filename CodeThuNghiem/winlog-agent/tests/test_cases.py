import json
from app.cases import create_cases
from app.config import Settings
from app.storage import Store
from test_correlation import event


def test_normal_mixed_missing_snapshot_and_filter(tmp_path):
    store = Store(tmp_path)
    imp = store.create_import({'synthetic': True})
    src = store.add_source(imp, 'Security', 'synthetic.xml', b'<Events/>')
    rows = [event('s',4624,0),event('p',4688,1,pid=10),event('b',4625,2,user='b'),event('u',4688,3,user=None)]
    store.add_events(src, [(r,'<Event/>') for r in rows])
    result = create_cases(store, imp, Settings())
    assert len(result['case_ids']) == 3
    mixed = create_cases(store, imp, Settings(), mixed=True)
    with store.connect() as db:
        snap = json.loads(db.execute('SELECT snapshot FROM cases WHERE case_id=?', (mixed['case_ids'][0],)).fetchone()[0])
    assert len(snap['event_refs']) == 4
    assert len({g['group_id'] for g in snap['links']}) == 3
    assert snap['config']['synthetic'] is True
    assert all('label' not in g for g in snap['links'])
    assert len(create_cases(store,imp,Settings(),user='a')['case_ids']) == 1
    assert not create_cases(store,imp,Settings(),user='absent')['case_ids']
    changed = create_cases(store, imp, Settings(failure_window_seconds=30))
    assert set(result['case_ids']).isdisjoint(changed['case_ids'])
