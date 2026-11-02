"""Rule-only baseline adapted from Lam-Code's detector, for comparison with the SLMs.

Rules run per correlation group, so one account's evidence is never attributed to another.
Output is never added to model payloads and no ground-truth label is read here.
"""
import argparse
import re
import ntpath
from pathlib import Path
from .config import Settings, load_settings
from .correlation import correlate
from .import_logs import import_events
from .storage import Store, canonical

def command_tokens(command):
    """Recognize direct net/net1 invocations and a single cmd /c wrapper.

    Token boundaries avoid matching echo text, internet.exe or /address.
    This is deliberately not a general shell interpreter.
    """
    command = command.strip()
    tokens = re.findall(r'"[^"]*"|[^\s]+', command)
    if not tokens:
        return []
    executable = ntpath.basename(tokens[0].strip('"')).casefold()
    if executable in ('cmd', 'cmd.exe'):
        tail = command[len(tokens[0]):].strip()
        match = re.match(r'(?i)(?:/d\s+)?/[ck]\s+(.+)$', tail)
        if not match:
            return []
        nested = match[1].strip()
        if nested.startswith('"') and nested.endswith('"'):
            nested = nested[1:-1]
        tokens = re.findall(r'"[^"]*"|[^\s]+', nested)
        if not tokens:
            return []
        executable = ntpath.basename(tokens[0].strip('"')).casefold()
    args = [t.strip('"').casefold() for t in tokens[1:]]
    return [executable, *args]


def account_command(command):
    tokens=command_tokens(command)
    if not tokens: return False
    executable,*args=tokens
    return executable in ('net', 'net.exe', 'net1', 'net1.exe') and bool(args) and args[0] in ('user', 'localgroup') and '/add' in args[1:]
RUN_KEY = 'currentversion\\run'
RECON_COMMANDS = ('whoami', 'nltest', 'net group', 'systeminfo')


def text(event, field):
    return (event.get(field) or '').casefold()


def event_stages(event):
    cmd, script = text(event, 'command_line'), text(event, 'script_text')
    tokens=command_tokens(cmd)
    powershell=bool(tokens) and tokens[0] in ('powershell','powershell.exe','pwsh','pwsh.exe')
    # Require combined behavior, not a keyword mentioned in text or a benign download.
    execution=bool(re.search(r'(?i)(?:^|[;|\s(])(?:iex|invoke-expression)\b',script))
    download=bool(re.search(r'\.(?:downloadstring|downloadfile)\s*\(',script))
    encoded=any(t in ('-enc','-encodedcommand','-e') for t in tokens[1:])
    concealed=any(tokens[i] in ('-w','-windowstyle') and tokens[i+1]=='hidden'
                  for i in range(1,len(tokens)-1))
    stages = []
    if event['event_id'] == 4688 and account_command(cmd):
        stages.append('T1136/T1098 Create Account / Account Manipulation')
    if ((event['event_id']==4104 and execution and download)
            or (event['event_id']==4688 and powershell and encoded and concealed)):
        stages.append('T1059.001 PowerShell')
    registry_write=(event['event_id']==4104 and RUN_KEY in script and
                    bool(re.search(r'(?i)(?:^|[;\s])(?:set-itemproperty|new-itemproperty)\b',script)))
    registry_command=(event['event_id']==4688 and RUN_KEY in cmd and len(tokens)>1
                      and tokens[0] in ('reg','reg.exe') and tokens[1]=='add')
    if registry_write or registry_command:
        stages.append('T1547.001 Registry Run Keys')
    return stages


def classify_group(group, by_ref):
    events = [by_ref[r] for r in group['event_refs']]
    stages, refs = [], []
    if group['kind'] == 'failed_logins' and group['threshold_reached']:
        stages.append('T1110 Brute Force')
        refs += [e['event_ref'] for e in events if e['event_id'] == 4625]
        success = [link['to'] for link in group['links'] if link.get('relation') == 'login_after_failures']
        if success:
            stages.append('T1078 Valid Accounts')
            refs += success
    for e in events:
        found = event_stages(e)
        if found:
            stages += found
            refs.append(e['event_ref'])
    # Discovery commands are routine admin work; count them only beside other evidence in the same group.
    recon = [e['event_ref'] for e in events if e['event_id'] == 4688
             and any(k in text(e, 'command_line') for k in RECON_COMMANDS)]
    if stages and recon:
        stages.append('T1033 System Owner/User Discovery')
        refs += recon
    return list(dict.fromkeys(stages)), list(dict.fromkeys(refs))


def classify(events, groups):
    by_ref = {e['event_ref']: e for e in events}
    results = []
    for group in groups:
        stages, refs = classify_group(group, by_ref)
        results.append({'group_id': group['group_id'], 'label': 'ALERT' if stages else 'NORMAL',
                        'detected_stages': stages, 'evidence_refs': refs})
    alerts = [r for r in results if r['label'] == 'ALERT']
    stages = list(dict.fromkeys(s for r in alerts for s in r['detected_stages']))
    if not results:
        label, reason = 'UNKNOWN', 'No events to evaluate.'
    elif alerts:
        label, reason = 'ALERT', 'Rule baseline matched: ' + '; '.join(stages)
    else:
        label, reason = 'NORMAL', 'No rule matched in the observed events.'
    return {'label': label, 'reason': reason, 'detected_stages': stages,
            'evidence_refs': list(dict.fromkeys(r for a in alerts for r in a['evidence_refs'])), 'groups': results}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('import_id')
    parser.add_argument('--data-root', type=Path, default=Path('data'))
    parser.add_argument('--config', type=Path)
    args = parser.parse_args()
    settings = load_settings(args.config) if args.config else Settings()
    events = import_events(Store(args.data_root), args.import_id)
    print(canonical(classify(events, correlate(events, settings))))
