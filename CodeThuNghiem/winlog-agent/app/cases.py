"""Case snapshots and a local CLI. Filtering never modifies imported evidence."""
import argparse
import json
from pathlib import Path
from .config import Settings, load_settings
from .correlation import correlate, timestamp
from .import_logs import import_events, import_report
from .normalize import utc
from .storage import Store, canonical


def create_cases(store, import_id, settings, *, start=None, end=None, user=None, group_ids=None, mixed=False):
    report = import_report(store, import_id)
    filters = {'start': start, 'end': end, 'user': user}
    for value in (start, end):
        if value is not None and utc(value) is None:
            raise ValueError('Filter time requires an explicit timezone')
    start_time = timestamp({'time': utc(start)}) if start else None
    end_time = timestamp({'time': utc(end)}) if end else None
    if start_time is not None and end_time is not None and start_time > end_time:
        raise ValueError('Start must not follow end')
    # Correlate full import first so filtering cannot hide PID reuse evidence.
    all_events = import_events(store, import_id)
    groups = correlate(all_events, settings)
    lookup = {e['event_ref']: e for e in all_events}
    def selected(ref):
        e = lookup[ref]
        t = timestamp(e)
        if start_time is not None and (t is None or t < start_time):
            return False
        if end_time is not None and (t is None or t > end_time):
            return False
        account = e.get('user') or {}
        name = '\\'.join(v for v in (account.get('domain'), account.get('name')) if v)
        return user is None or user.casefold() in ((account.get('name') or '').casefold(), name.casefold())
    groups = [g for g in groups if any(selected(ref) for ref in g['event_refs'])]
    if group_ids is not None:
        if set(group_ids) - {g['group_id'] for g in groups}:
            raise ValueError('Unknown or filtered group ID')
        groups = [g for g in groups if g['group_id'] in group_ids]
    config = {k: getattr(settings, k) for k in ('failure_window_seconds', 'failure_threshold',
              'success_window_seconds', 'activity_window_seconds')}
    config.update(correlation_version=1, filters=filters, import_id=import_id,
                  selection='whole_groups_matching_filter', synthetic=report['metadata'].get('synthetic', False))
    ids = []
    batches = [groups] if mixed and groups else [[g] for g in groups]
    for batch in batches:
        refs = sorted({r for g in batch for r in g['event_refs']},
                      key=lambda r: (timestamp(lookup[r]) is None, timestamp(lookup[r]) or 0, r))
        links = [{'relation': 'group', **g} for g in batch]
        ids.append(store.create_case(refs, links=links, config=config))
    return {'case_ids': ids, 'groups': groups, 'config': config}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('import_id')
    parser.add_argument('--data-root', type=Path, default=Path('data'))
    parser.add_argument('--config', type=Path)
    parser.add_argument('--start')
    parser.add_argument('--end')
    parser.add_argument('--user')
    parser.add_argument('--group-id', action='append')
    parser.add_argument('--mixed', action='store_true')
    args = parser.parse_args()
    settings = load_settings(args.config) if args.config else Settings()
    store = Store(args.data_root)
    print(canonical(create_cases(store, args.import_id, settings, start=args.start, end=args.end,
                                 user=args.user, group_ids=args.group_id, mixed=args.mixed)))
