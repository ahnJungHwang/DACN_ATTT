"""Local CLI and shared import service. Source XML is copied, never modified."""
import argparse
from collections import Counter
import json
from pathlib import Path
from xml.etree import ElementTree as ET
from .config import Settings, load_settings
from .normalize import normalize
from .script_blocks import assemble
from .storage import Store, DuplicateSource, canonical, digest
from .xml_logs import read_xml, LogFormatError

SOURCES = {'Security': ('Security', {4624, 4625, 4688}),
           'PowerShell': ('Microsoft-Windows-PowerShell/Operational', {4104})}


def import_files(store, files, settings, *, synthetic=False, original_names=None):
    """files maps source names to Paths; source failure never invents events."""
    if set(files) - SOURCES.keys():
        raise ValueError('Unknown source')
    prepared = {}
    total = 0
    hashes = set()
    for source_name, path in files.items():
        path = Path(path)
        original_name = (original_names or {}).get(source_name, path.name)
        try:
            with path.open('rb') as handle:
                content = handle.read(settings.upload_max_bytes + 1)
            sha = digest(content)
            with store.connect() as db:
                existing = db.execute('SELECT source_id FROM sources WHERE sha256=?', (sha,)).fetchone()
            if existing:
                raise DuplicateSource(existing['source_id'])
            if sha in hashes:
                raise ValueError('Same file supplied for multiple sources')
            hashes.add(sha)
            encoding, elements = read_xml(content, settings)
            events = [(normalize(e), ET.tostring(e, encoding='unicode')) for e in elements]
            channel, ids = SOURCES[source_name]
            if any(e['channel'] != channel or e['event_id'] not in ids for e, _ in events):
                raise LogFormatError('SOURCE_CHANNEL_OR_EVENT_ID_MISMATCH')
            total += len(events)
            prepared[source_name] = {'content': content, 'encoding': encoding, 'events': events,
                                     'original_name': original_name}
        except (OSError, LogFormatError) as exc:
            prepared[source_name] = {'error': str(exc), 'original_name': original_name}
    if total > settings.import_max_events:
        raise LogFormatError('TOO_MANY_EVENTS_IN_IMPORT')
    import_id = store.create_import({'synthetic': synthetic, 'normalizer_version': 1})
    for source_name in SOURCES:
        item = prepared.get(source_name)
        if item is None:
            store.add_source(import_id, source_name, '', state='missing')
        elif 'error' in item:
            store.add_source(import_id, source_name, item['original_name'], state='error', metadata={'error': item['error']})
        else:
            counts = Counter(str(event['event_id']) for event, _ in item['events'])
            store.add_source(import_id, source_name, item['original_name'], item['content'],
                             encoding=item['encoding'], events=item['events'],
                             metadata={'count': len(item['events']), 'counts_by_id': dict(counts),
                                       'collection_status': 'no_events' if not item['events'] else 'success'})
    return import_report(store, import_id)


def import_events(store, import_id):
    with store.connect() as db:
        rows = db.execute('SELECT e.*, s.import_id FROM events e JOIN sources s USING(source_id) '
                          'WHERE s.import_id=? ORDER BY s.source_name, e.ordinal', (import_id,)).fetchall()
    return [dict(json.loads(row['normalized']), event_ref=row['event_ref'], import_id=import_id) for row in rows]


def import_report(store, import_id):
    with store.connect() as db:
        imp = db.execute('SELECT * FROM imports WHERE import_id=?', (import_id,)).fetchone()
        if imp is None:
            raise KeyError(import_id)
        sources = [dict(row) for row in db.execute('SELECT * FROM sources WHERE import_id=?', (import_id,))]
    for source in sources:
        source['metadata'] = json.loads(source['metadata'])
    events = import_events(store, import_id)
    times = [e['time'] for e in events if e['time']]
    counts = dict(Counter(str(e['event_id']) for e in events))
    return {'import_id': import_id, 'metadata': json.loads(imp['metadata']), 'sources': sources,
            'status': 'complete' if len(sources) == 2 and all(s['state'] == 'ready' for s in sources) else 'partial',
            'event_count': len(events), 'counts_by_id': counts,
            'missing_event_ids': sorted({4624, 4625, 4688, 4104} - {e['event_id'] for e in events}),
            'first_time': min(times, default=None), 'last_time': max(times, default=None),
            'quality_errors': dict(Counter(error for e in events for error in e['quality_errors'])),
            'script_blocks': assemble(events)}


def export_jsonl(store, import_id):
    import_report(store, import_id)  # registered ID only
    path = store.root / 'normalized' / f'{import_id}.jsonl'
    temporary = path.with_suffix('.part')
    with temporary.open('w', encoding='utf-8', newline='\n') as handle:
        for event in import_events(store, import_id):
            handle.write(canonical(event) + '\n')
    temporary.replace(path)
    return path


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path)
    parser.add_argument('--data-root', type=Path)
    parser.add_argument('--security', type=Path)
    parser.add_argument('--powershell', type=Path)
    parser.add_argument('--synthetic', action='store_true')
    args = parser.parse_args()
    settings = load_settings(args.config) if args.config else Settings()
    if args.data_root:
        settings.data_root = str(args.data_root)
    files = {k: v for k, v in [('Security', args.security), ('PowerShell', args.powershell)] if v}
    if not files:
        parser.error('Provide --security and/or --powershell')
    store = Store(settings.data_root)
    try:
        report = import_files(store, files, settings, synthetic=args.synthetic)
        report['jsonl'] = str(export_jsonl(store, report['import_id']))
        print(canonical(report))
    except (ValueError, OSError) as exc:
        parser.exit(2, str(exc) + '\n')
