import pytest
from app.backup import backup, restore
from app.storage import Store


def test_backup_restore_preserves_refs_and_hashes(tmp_path):
    store = Store(tmp_path / 'data')
    source = store.add_source(store.create_import(), 'Security', 'synthetic.xml', b'<Events/>')
    refs = store.add_events(source, [({'synthetic': True}, '<Event/>')])
    case = store.create_case(refs)
    manifest = backup(store.root, tmp_path / 'backup')
    assert manifest['schema_version'] == 1
    assert not any(restore(tmp_path / 'backup', tmp_path / 'restored').values())
    restored = Store(tmp_path / 'restored')
    assert restored.event(refs[0]) == store.event(refs[0])
    with restored.connect() as db, store.connect() as original:
        assert tuple(db.execute('SELECT * FROM cases WHERE case_id=?', (case,)).fetchone()) == tuple(
            original.execute('SELECT * FROM cases WHERE case_id=?', (case,)).fetchone())
    with pytest.raises(FileExistsError):
        restore(tmp_path / 'backup', tmp_path / 'restored')


def test_modified_backup_rejected_without_overwrite(tmp_path):
    store = Store(tmp_path / 'data')
    store.add_source(store.create_import(), 'Security', 'x', b'<Events/>')
    backup(store.root, tmp_path / 'backup')
    next((tmp_path / 'backup' / 'raw').iterdir()).write_bytes(b'changed')
    with pytest.raises(ValueError, match='changed'):
        restore(tmp_path / 'backup', tmp_path / 'restored')
    assert not (tmp_path / 'restored').exists()
