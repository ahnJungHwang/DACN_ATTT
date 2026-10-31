"""Rule-only baseline adapted from Lam-Code's detector, for comparison with the SLMs.

Rules run per correlation group, so one account's evidence is never attributed to another.
Output is never added to model payloads and no ground-truth label is read here.
"""
import argparse
from pathlib import Path
from .config import Settings, load_settings
from .correlation import correlate
from .import_logs import import_events
from .storage import Store, canonical

ACCOUNT_COMMANDS = ('net user', 'net1 user', 'net localgroup', 'net1 localgroup')
DOWNLOAD_MARKERS = ('downloadstring', 'downloadfile', 'mimikatz')
ENCODED_FLAGS = ('-encodedcommand', ' -enc ')
RUN_KEY = 'currentversion\\run'
RECON_COMMANDS = ('whoami', 'nltest', 'net group', 'systeminfo')


def text(event, field):
    return (event.get(field) or '').casefold()


def event_stages(event):
    cmd, script = text(event, 'command_line'), text(event, 'script_text')
    stages = []
    if event['event_id'] == 4688 and '/add' in cmd and any(k in cmd for k in ACCOUNT_COMMANDS):
        stages.append('T1136/T1098 Create Account / Account Manipulation')
    if (any(k in script for k in DOWNLOAD_MARKERS) or ('iex' in script and 'http' in script)
            or any(k in cmd for k in ENCODED_FLAGS)):
        stages.append('T1059.001 PowerShell')
    if RUN_KEY in script or RUN_KEY in cmd:
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
