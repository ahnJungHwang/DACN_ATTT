"""Synthetic evidence only; never uses the student's original logs."""
import json
import sqlite3
import pytest
from app.storage import Store, DuplicateSource, digest


def seed(store, content=b'<Events/>', host='vm-a'):
    import_id = store.create_import({'synthetic': True})
    source = store.add_source(import_id, 'Security', '../../original.xml', content)
    refs = store.add_events(source, [({'host': host, 'event_record_id': 1}, '<Event/>')])
    return source, refs


def test_schema_constraints_and_rollback(tmp_path):
    store = Store(tmp_path)
    with store.connect() as db:
        assert db.execute('PRAGMA user_version').fetchone()[0] == 1
        assert {'imports', 'events', 'cases', 'requests', 'results', 'evaluations'} <= {
            r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    with pytest.raises(sqlite3.IntegrityError):
        with store.connect() as db:
            db.execute("INSERT INTO imports VALUES('i','now','{}')")
            db.execute("INSERT INTO imports VALUES('i','now','{}')")
    with store.connect() as db:
        assert db.execute('SELECT count(*) FROM imports').fetchone()[0] == 0
    Store(tmp_path)  # restart is idempotent


def test_unknown_version_refused(tmp_path):
    store = Store(tmp_path)
    with store.connect() as db:
        db.execute('PRAGMA user_version=999')
    with pytest.raises(ValueError, match='version'):
        Store(tmp_path)


@pytest.mark.parametrize('point,field', [('staged', 'staging'), ('renamed', 'orphans')])
def test_crash_never_publishes(tmp_path, point, field):
    store = Store(tmp_path)
    def crash(step):
        if step == point:
            raise RuntimeError('simulated crash')
    with pytest.raises(RuntimeError):
        store.add_source(store.create_import(), 'Security', 'x.xml', b'<Events/>', checkpoint=crash)
    reopened = Store(tmp_path)
    assert len(reopened.recovery_report()[field]) == 1
    with reopened.connect() as db:
        assert db.execute('SELECT count(*) FROM sources').fetchone()[0] == 0
    assert reopened.recovery_report() == store.recovery_report()


def test_validation_failure_and_partial_sources(tmp_path):
    store = Store(tmp_path)
    imp = store.create_import()
    def reject(path):
        raise ValueError('invalid XML')
    with pytest.raises(ValueError):
        store.add_source(imp, 'Security', 'x', b'broken', validator=reject)
    store.add_source(imp, 'Security', 'x', state='error', metadata={'error': 'invalid XML'})
    store.add_source(imp, 'PowerShell', 'y', state='no_events')
    assert not list((tmp_path / 'raw').iterdir())


def test_refs_dedup_and_immutable_snapshots(tmp_path):
    store = Store(tmp_path)
    first, refs1 = seed(store)
    _, refs2 = seed(store, b'<Events> </Events>', 'vm-b')
    assert refs1 != refs2
    assert json.loads(store.event(refs2[0])['normalized'])['host'] == 'vm-b'
    with pytest.raises(DuplicateSource) as exc:
        seed(store)
    assert exc.value.source_id == first
    old = store.create_case(refs1 + refs2, config={'window': 60})
    new = store.create_case(refs1 + refs2, config={'window': 120})
    assert old != new
    with store.connect() as db:
        old_snapshot = db.execute('SELECT snapshot FROM cases WHERE case_id=?', (old,)).fetchone()[0]
        assert json.loads(old_snapshot)['config']['window'] == 60
    with pytest.raises(sqlite3.IntegrityError, match='immutable'):
        with store.connect() as db:
            db.execute("UPDATE cases SET snapshot='{}' WHERE case_id=?", (old,))
    with pytest.raises(ValueError, match='Duplicate'):
        store.create_case(refs1 * 2)
    with pytest.raises(sqlite3.IntegrityError):
        store.create_case(['nonexistent'])
    with store.connect() as db:
        assert db.execute('SELECT count(*) FROM cases').fetchone()[0] == 2


def test_hash_integrity_and_lookup(tmp_path):
    store = Store(tmp_path)
    _, refs = seed(store)
    evidence = store.event(refs[0])
    assert evidence['sha256'] == digest(b'<Events/>')
    assert not any(store.recovery_report().values())
    path = tmp_path / evidence['relative_path']
    path.write_bytes(b'changed')
    assert store.recovery_report()['hash_mismatch'] == [evidence['relative_path']]
    path.unlink()
    assert store.recovery_report()['missing'] == [evidence['relative_path']]
    with pytest.raises(KeyError):
        store.event('../../secret')
