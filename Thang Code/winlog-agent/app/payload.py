"""Explicit projection prevents evaluation metadata leaking into model input."""
from pathlib import Path
from .storage import canonical, digest

PROMPT = (Path(__file__).resolve().parent.parent / 'prompts' / 'windows-log-v1.txt').read_text(encoding='utf-8')
SCHEMA = {'type': 'object', 'additionalProperties': False, 'required': ['label','reason','evidence_refs'],
          'properties': {'label': {'type':'string','enum':['NORMAL','ALERT','UNKNOWN']},
                         'reason': {'type':'string','minLength':1},
                         'evidence_refs': {'type':'array','items':{'type':'string'}}}}
FIELDS = ('time','host','channel','event_id','user','subject','target','logon_type','source_address',
          'logon_id','process_id','creator_process_id','command_line','script_text','quality_errors')


def build_payload(events, groups):
    refs = {e['event_ref']: f'E{i:03d}' for i, e in enumerate(events, 1)}
    if len(refs) != len(events):
        raise ValueError('Duplicate evidence')
    projected = []
    for e in events:
        row = {k: e.get(k) for k in FIELDS}
        for role in ('user','subject','target'):
            if row[role] is not None:
                row[role] = {k: row[role].get(k) for k in ('name','domain','sid','logon_id')}
        row['ref'] = refs[e['event_ref']]
        projected.append(row)
    projected_groups = []
    for i, group in enumerate(groups, 1):
        links = []
        for link in group.get('links', []):
            links.append({'relation': link['relation'], 'certainty': link['certainty'],
                          'from': refs.get(link.get('from')), 'to': refs.get(link.get('to')),
                          'candidate_refs': [refs[r] for r in link.get('candidate_refs', []) if r in refs]})
        projected_groups.append({'group': f'G{i:03d}', 'event_refs': [refs[r] for r in group['event_refs']], 'links': links})
    payload = {'events': projected, 'groups': projected_groups,
               'field_meanings': {'user':'account relevant to this event; null means unknown',
                                  'subject':'creator/requester context', 'target':'target context',
                                  'process_id':'new PID for 4688; execution PID for 4104',
                                  'logon_id':'successful target session or process account session; null if unknown'}}
    return {'messages': [{'role':'system','content':PROMPT}, {'role':'user','content':canonical(payload)}],
            'format': SCHEMA, 'reference_map': {v:k for k,v in refs.items()},
            'prompt_sha256': digest(PROMPT.encode()), 'payload_sha256': digest(canonical(payload).encode())}
