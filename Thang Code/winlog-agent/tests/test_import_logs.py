import json
from pathlib import Path
import pytest
from app.config import Settings
from app.import_logs import import_files, import_report, import_events, export_jsonl
from app.storage import Store, DuplicateSource, digest
from app.xml_logs import LogFormatError

FIXTURE = Path(__file__).parent / 'fixtures' / 'synthetic-security.xml'


def test_import_export_evidence_and_dedup(tmp_path):
    store = Store(tmp_path / 'data')
    report = import_files(store, {'Security': FIXTURE}, Settings(), synthetic=True)
    assert report['status'] == 'partial' and report['event_count'] == 1
    assert report['missing_event_ids'] == [4104, 4625, 4688]
    exported = json.loads(export_jsonl(store, report['import_id']).read_text(encoding='utf-8'))
    row = store.event(exported['event_ref'])
    assert row['ordinal'] == 1 and row['sha256'] == digest(FIXTURE.read_bytes())
    assert (store.root / row['relative_path']).read_bytes() == FIXTURE.read_bytes()
    assert 'demo' in row['raw_xml']
    with pytest.raises(DuplicateSource):
        import_files(store, {'Security': FIXTURE}, Settings())
    assert len(import_events(store, report['import_id'])) == 1


def test_partial_error_and_empty(tmp_path):
    broken = tmp_path / 'broken.xml'
    broken.write_text('<Events>')
    store = Store(tmp_path / 'data')
    report = import_files(store, {'Security': FIXTURE, 'PowerShell': broken}, Settings())
    assert report['status'] == 'partial' and report['event_count'] == 1
    assert any(s['state'] == 'error' for s in report['sources'])
    broken.write_text('<Events/>')
    empty = import_files(store, {'PowerShell': broken}, Settings())
    assert empty['event_count'] == 0 and empty['missing_event_ids'] == [4104, 4624, 4625, 4688]
    assert import_report(store, empty['import_id'])['status'] == 'partial'


def test_total_limit_does_not_publish(tmp_path):
    xml = FIXTURE.read_text(encoding='utf-8')
    second = tmp_path / 'ps.xml'
    second.write_text(xml.replace('4624', '4104').replace('<Channel>Security', '<Channel>Microsoft-Windows-PowerShell/Operational'), encoding='utf-8')
    store = Store(tmp_path / 'data')
    with pytest.raises(LogFormatError, match='TOO_MANY_EVENTS_IN_IMPORT'):
        import_files(store, {'Security': FIXTURE, 'PowerShell': second}, Settings(import_max_events=1))
    with store.connect() as db:
        assert db.execute('SELECT count(*) FROM imports').fetchone()[0] == 0
