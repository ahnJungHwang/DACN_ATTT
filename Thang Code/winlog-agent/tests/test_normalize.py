from xml.sax.saxutils import escape
from app.xml_logs import read_xml
from app.normalize import normalize
from app.config import Settings


def event(event_id=4624, fields=None, version=2, stamp='2026-10-24T10:00:00+07:00', message='hello'):
    data = ''.join(f'<Data Name="{name}">{escape(value)}</Data>' for name, value in (fields or {}).items())
    xml = f'<Event><System><EventID>{event_id}</EventID><Version>{version}</Version><TimeCreated SystemTime="{stamp}"/><Computer>vm</Computer><Channel>Security</Channel><EventRecordID>1</EventRecordID><Execution ProcessID="123"/></System><EventData>{data}</EventData><RenderingInfo><Message>{message}</Message></RenderingInfo></Event>'
    return normalize(read_xml(xml.encode(), Settings())[1][0])


def test_time_missing_fields_and_language():
    en = event(message='English')
    assert en == event(message='Tiếng Việt')
    assert en['time'] == '2026-10-24T03:00:00+00:00'
    assert en['command_line'] is None and en['user'] is None
    for stamp in ('', 'bad', '2026-10-24T10:00:00'):
        row = event(stamp=stamp)
        assert row['time'] is None and row['quality_errors']


def test_roles_and_process_ids():
    fields = {'SubjectUserName': 'creator', 'TargetUserName': 'runner', 'TargetLogonId': '0x30',
              'SubjectLogonId': '0x20', 'NewProcessId': '0x100', 'ProcessId': '64', 'CommandLine': 'notepad.exe'}
    row = event(4688, fields)
    assert row['user']['name'] == 'runner'
    assert row['subject']['name'] == 'creator'
    assert row['logon_id'] == 48 and row['process_id'] == 256 and row['creator_process_id'] == 64
    assert row['execution_process_id'] == 123
    assert event(4625, fields)['logon_id'] is None
    assert event(4624, fields)['user']['name'] == 'runner'
    assert event(4104, fields)['process_id'] == 123


def test_process_fallback_requires_evidence():
    fields = {'SubjectUserName': 'creator', 'SubjectLogonId': '32'}
    assert event(4688, fields)['user'] is None
    assert event(4688, fields, version=1)['user']['name'] == 'creator'
    fields.update(TargetUserSid='S-1-0-0', TargetUserName='-', TargetDomainName='-', TargetLogonId='0x0')
    assert event(4688, fields)['user_basis'] == 'same_context_subject'


def test_numeric_errors_keep_raw():
    row = event(4688, {'NewProcessId': 'not-a-number'})
    assert row['process_id'] is None
    assert row['event_data']['NewProcessId'] == 'not-a-number'
    assert 'invalid_number:NewProcessId' in row['quality_errors']
