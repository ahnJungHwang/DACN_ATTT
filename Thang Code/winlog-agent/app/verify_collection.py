"""Read-only verification of a Windows collection folder against its manifest."""
import argparse
from collections import Counter
from datetime import datetime,timezone
from decimal import Decimal
import json
from pathlib import Path
import re
from uuid import UUID
from .config import Settings
from .normalize import normalize,utc
from .storage import digest,canonical
from .xml_logs import read_xml

SOURCES={'Security':('security.xml','Security',{4624,4625,4688}),
         'PowerShell':('powershell.xml','Microsoft-Windows-PowerShell/Operational',{4104})}


def instant(value):
    if not isinstance(value,str) or utc(value) is None: raise ValueError('Time requires ISO 8601 timezone')
    dt=datetime.fromisoformat(value.replace('Z','+00:00')).astimezone(timezone.utc)
    delta=dt.replace(microsecond=0)-datetime(1970,1,1,tzinfo=timezone.utc)
    fraction=re.search(r'\.(\d+)',value)
    return Decimal(delta.days*86400+delta.seconds)+(Decimal('0.'+fraction[1]) if fraction else 0)


def verify_collection(folder,settings=None):
    folder=Path(folder).resolve(); settings=settings or Settings()
    manifest_path=folder/'manifest.json'
    if not manifest_path.resolve().is_relative_to(folder): raise ValueError('Manifest escapes collection folder')
    if manifest_path.stat().st_size>1024*1024: raise ValueError('Manifest too large')
    manifest=json.loads(manifest_path.read_text(encoding='utf-8-sig'))
    errors=[]; warnings=[]; reports=[]
    if manifest.get('schema_version')!=1 or manifest.get('interval')!='inclusive': raise ValueError('Unsupported manifest schema/interval')
    UUID(manifest['run_id'])
    start,end=instant(manifest['start_utc']),instant(manifest['end_utc'])
    if start>end: raise ValueError('Invalid time interval')
    if instant(manifest['start_input'])!=start or instant(manifest['end_input'])!=end: errors.append('Input/UTC time mismatch')
    if not isinstance(manifest.get('computer'),str) or not manifest['computer'].strip(): errors.append('Missing computer')
    sources=manifest.get('sources',[])
    if not isinstance(sources,list) or len(sources)!=2 or {s.get('source') for s in sources}!=set(SOURCES):
        raise ValueError('Expected exactly Security and PowerShell source entries')
    complete=all(s.get('status') in ('success','no_events') for s in sources)
    if manifest.get('status')!=('complete' if complete else 'partial'): errors.append('Collection status mismatch')
    for source in sources:
        name=source['source']; filename,channel,ids=SOURCES[name]; problems=[]
        record={'source':name,'collection_status':source.get('status'),'verified':False,'errors':problems}
        reports.append(record)
        if source.get('channel')!=channel or set(source.get('event_ids',[]))!=ids: problems.append('Source definition mismatch')
        if source.get('status') not in ('success','no_events'):
            if source.get('status') not in ('permission_denied','read_error','write_error'): problems.append('Unknown source status')
            warnings.append(name+': collection not successful; preserve any partial files')
            continue
        if source.get('file')!=filename:
            problems.append('Unexpected filename'); continue
        path=folder/filename
        if not path.resolve().is_relative_to(folder): problems.append('File escapes collection folder'); continue
        try:
            with path.open('rb') as handle: content=handle.read(settings.upload_max_bytes+1)
            if digest(content).lower()!=str(source.get('sha256','')).lower(): problems.append('SHA256 mismatch')
            _,events=read_xml(content,settings)
            rows=[normalize(event) for event in events]
            counts=Counter(str(row['event_id']) for row in rows)
            record['count']=len(rows); record['counts_by_id']=dict(counts)
            if type(source.get('count')) is not int or source['count']!=len(rows): problems.append('Event count mismatch')
            if source.get('counts_by_id')!={str(i):counts[str(i)] for i in ids}: problems.append('Counts by Event ID mismatch')
            if (len(rows)==0)!=(source['status']=='no_events'): problems.append('no_events status mismatch')
            times=[]
            for element,row in zip(events,rows):
                raw_time=next((e.get('SystemTime') for e in element.iter() if e.tag.rsplit('}',1)[-1]=='TimeCreated'),None)
                timestamp=instant(raw_time); times.append(timestamp)
                if not start<=timestamp<=end: problems.append('Event outside collection interval')
                if row['channel']!=channel or row['event_id'] not in ids: problems.append('Unexpected channel/Event ID')
                if (row.get('host') or '').casefold()!=manifest.get('computer','').casefold(): problems.append('Computer mismatch')
            if times:
                if instant(source['first_event_utc'])!=min(times) or instant(source['last_event_utc'])!=max(times): problems.append('First/last event mismatch')
            elif source.get('first_event_utc') is not None or source.get('last_event_utc') is not None:
                problems.append('Empty source has nonempty event time')
            missing=sorted(ids-{row['event_id'] for row in rows})
            if missing: warnings.append(name+': Event IDs absent: '+','.join(map(str,missing)))
            record['verified']=not problems
        except (OSError,ValueError,KeyError,TypeError) as exc: problems.append(str(exc))
        record['errors']=sorted(set(problems))
    integrity_ok=not errors and all(not r['errors'] for r in reports)
    return {'run_id':manifest['run_id'],'computer':manifest.get('computer'),'integrity_ok':integrity_ok,
            'collection_complete':complete,'ready_for_manual_review':integrity_ok and complete,
            'sources':reports,'errors':errors,'warnings':warnings,
            'limitation':'File verification does not establish audit policy, scenario labels or VM provenance.'}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('folder',type=Path)
    args=parser.parse_args()
    try:
        report=verify_collection(args.folder); print(canonical(report))
        raise SystemExit(0 if report['ready_for_manual_review'] else 2)
    except (OSError,ValueError,KeyError,TypeError) as exc:
        print(canonical({'integrity_ok':False,'error':str(exc)})); raise SystemExit(2)
