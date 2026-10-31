"""Ground truth stays outside model payloads. Lock provenance before evaluation."""
import json
from collections import Counter
from pathlib import Path
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator
from .storage import canonical, digest, now

GROUPS=('normal','password_guessing','mixed_same_session','mixed_different_session')


class Entry(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True)
    case_id:str
    split:Literal['development','evaluation','warmup']
    group:Literal['normal','password_guessing','mixed_same_session','mixed_different_session']
    label:Literal['NORMAL','ALERT']
    run_ids:list[str]=Field(min_length=1)
    session_keys:list[str]=Field(min_length=1)
    annotator:str=Field(min_length=1)
    rationale:str=Field(min_length=1)
    expected_accounts:list[str]
    expected_sessions:list[str]
    evidence_refs:list[str]

    @field_validator('run_ids','session_keys')
    @classmethod
    def nonempty_unique(cls,values):
        if any(not v.strip() for v in values) or len(set(values))!=len(values):
            raise ValueError('Provenance requires nonblank unique identifiers')
        return values


class Dataset(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True)
    version:Literal[1]=1
    name:str=Field(min_length=1)
    synthetic:bool
    rubric_version:Literal['account-session-v1']='account-session-v1'
    entries:list[Entry]=Field(min_length=1)


def lock_dataset(store,document):
    dataset=Dataset.model_validate(document)
    seen_cases=set(); membership={}; entries=[]
    # Known repository fixtures cannot silently become real data through a missing flag.
    fixture_dir=Path(__file__).resolve().parents[1]/'tests/fixtures'
    fixture_hashes={digest(p.read_bytes()) for p in fixture_dir.glob('*.xml')}
    for entry in dataset.entries:
        if entry.case_id in seen_cases: raise ValueError('Duplicate case in dataset')
        seen_cases.add(entry.case_id)
        with store.connect() as db:
            row=db.execute('SELECT * FROM cases WHERE case_id=?',(entry.case_id,)).fetchone()
        if row is None: raise ValueError('Unknown dataset case: '+entry.case_id)
        snapshot=json.loads(row['snapshot']); refs=snapshot['event_refs']
        if not refs: raise ValueError('Dataset case has no evidence')
        if not set(entry.evidence_refs)<=set(refs) or not entry.evidence_refs:
            raise ValueError('Ground truth needs evidence from its case')
        if entry.split=='warmup' and entry.label!='NORMAL': raise ValueError('Warmup must be neutral')
        hashes=set(); imports=set(); event_hashes=set(); source_samples=set()
        for ref in refs:
            event=store.event(ref); hashes.add(event['sha256']); imports.add(event['import_id'])
            event_hashes.add(digest(canonical(json.loads(event['normalized'])).encode()))
            with store.connect() as db:
                metadata=json.loads(db.execute('SELECT metadata FROM imports WHERE import_id=?',(event['import_id'],)).fetchone()[0])
            source_samples.add(bool(metadata.get('synthetic')) or event['sha256'] in fixture_hashes)
        if source_samples!={dataset.synthetic}:
            raise ValueError('Synthetic/real provenance mismatch; do not mix datasets')
        identities={'run':entry.run_ids,'session':entry.session_keys,'ref':refs,
                    'source_hash':hashes,'import':imports,'event_hash':event_hashes}
        for kind,values in identities.items():
            for value in values:
                key=(kind,value)
                if key in membership and membership[key]!=entry.split:
                    raise ValueError(f'Split leakage: {kind} shared by {membership[key]} and {entry.split}')
                membership[key]=entry.split
        entries.append({**entry.model_dump(),'case_hash':row['snapshot_hash'],
                        'event_refs':refs,'source_hashes':sorted(hashes),'import_ids':sorted(imports),
                        'event_hashes':sorted(event_hashes)})
    counts=Counter(e['split'] for e in entries)
    groups=Counter(e['group'] for e in entries if e['split']=='evaluation')
    missing={'development':max(0,10-counts['development']),
             'evaluation':max(0,40-counts['evaluation']),
             'evaluation_groups':{g:max(0,10-groups[g]) for g in GROUPS}}
    locked={**dataset.model_dump(exclude={'entries'}),'entries':entries,'locked_at':now(),
            'counts':dict(counts),'missing_targets':missing}
    locked['manifest_hash']=digest(canonical(locked).encode())
    return locked


def verify_locked(store,locked):
    body={k:v for k,v in locked.items() if k!='manifest_hash'}
    if digest(canonical(body).encode())!=locked['manifest_hash']: raise ValueError('Manifest hash changed')
    for entry in locked['entries']:
        with store.connect() as db:
            row=db.execute('SELECT snapshot_hash FROM cases WHERE case_id=?',(entry['case_id'],)).fetchone()
        if row is None or row[0]!=entry['case_hash']: raise ValueError('Case snapshot changed')
        for ref in entry['event_refs']:
            source=store.event(ref)
            if digest((store.root/source['relative_path']).read_bytes())!=source['sha256']:
                raise ValueError('Raw evidence hash changed')
