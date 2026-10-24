"""Deterministic field extraction; rendered Message text is never parsed."""
from datetime import datetime, timezone
import re
from xml.etree import ElementTree as ET
from .xml_logs import NS


def clean(value):
    return None if value is None or value.strip() in ('', '-') else value


def number(value):
    if clean(value) is None:
        return None
    try:
        parsed = int(value, 16 if value.lower().startswith('0x') else 10)
        return parsed if parsed >= 0 else None
    except (ValueError, AttributeError):
        return None


def utc(value):
    if not value or not re.search(r'(Z|[+-]\d{2}:\d{2})$', value):
        return None
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone(timezone.utc).isoformat()
    except ValueError:
        return None


def normalize(element):
    prefix = f'{{{NS}}}' if element.tag.startswith('{') else ''
    def find(path):
        return element.find('/'.join(prefix + part for part in path.split('/')))
    def text(path):
        item = find(path)
        return clean(item.text) if item is not None else None
    def attr(path, name):
        item = find(path)
        return clean(item.get(name)) if item is not None else None
    data = {}
    errors = []
    event_data = find('EventData')
    if event_data is not None:
        for item in event_data.findall(prefix + 'Data'):
            name = item.get('Name')
            if name:
                if name in data:
                    errors.append('duplicate_field:' + name)
                    data[name] = None  # ambiguity must not silently overwrite a role
                else:
                    data[name] = item.text
    def account(role):
        sid = clean(data.get(role + 'UserSid'))
        return {'name': clean(data.get(role + 'UserName')), 'domain': clean(data.get(role + 'DomainName')),
                'sid': None if sid == 'S-1-0-0' else sid,
                'logon_id': number(data.get(role + 'LogonId'))}
    subject, target = account('Subject'), account('Target')
    event_id, version = number(text('System/EventID')), number(text('System/Version'))
    time_raw = attr('System/TimeCreated', 'SystemTime')
    result = dict.fromkeys(('event_ref', 'time', 'host', 'channel', 'event_id', 'event_record_id',
                           'user', 'logon_type', 'source_address', 'logon_id', 'process_id',
                           'command_line', 'script_text', 'creator_process_id'))
    result.update(time=utc(time_raw), time_raw=time_raw, host=text('System/Computer'),
                  channel=text('System/Channel'), event_id=event_id,
                  event_record_id=number(text('System/EventRecordID')), version=version,
                  subject=subject, target=target, event_data=data,
                  system_xml=ET.tostring(find('System'), encoding='unicode') if find('System') is not None else None,
                  quality_errors=errors, user_basis=None,
                  execution_process_id=number(attr('System/Execution', 'ProcessID')),
                  script_block_id=clean(data.get('ScriptBlockId')),
                  message_number=number(data.get('MessageNumber')), message_total=number(data.get('MessageTotal')))
    if result['time'] is None:
        errors.append('missing_or_invalid_timezone_timestamp')
    for field in ('host', 'channel', 'event_id', 'event_record_id'):
        if result[field] is None:
            errors.append('missing_or_invalid:' + field)
    if event_id in (4624, 4625):
        result.update(user=target if target['name'] or target['sid'] else None,
                      user_basis='target', logon_type=number(data.get('LogonType')),
                      source_address=clean(data.get('IpAddress')))
        # A failed login has no successful target session. SubjectLogonId is unrelated.
        result['logon_id'] = target['logon_id'] if event_id == 4624 else None
    elif event_id == 4688:
        if target['name'] or target['sid']:
            result.update(user=target, logon_id=target['logon_id'], user_basis='target')
        elif version in (0, 1):
            result.update(user=subject if subject['name'] or subject['sid'] else None,
                          logon_id=subject['logon_id'], user_basis='legacy_subject')
        elif (version == 2 and data.get('TargetUserSid') == 'S-1-0-0'
              and target['name'] is None and target['domain'] is None and target['logon_id'] == 0):
            result.update(user=subject if subject['name'] or subject['sid'] else None,
                          logon_id=subject['logon_id'], user_basis='same_context_subject')
        else:
            errors.append('unknown_process_account')
        result.update(process_id=number(data.get('NewProcessId')),
                      creator_process_id=number(data.get('ProcessId')), command_line=clean(data.get('CommandLine')))
    elif event_id == 4104:
        result.update(process_id=result['execution_process_id'], script_text=clean(data.get('ScriptBlockText')))
    for field in ('NewProcessId', 'ProcessId', 'SubjectLogonId', 'TargetLogonId', 'LogonType', 'MessageNumber', 'MessageTotal'):
        if clean(data.get(field)) is not None and number(data[field]) is None:
            errors.append('invalid_number:' + field)
    return result
