"""Assemble fragments only inside an observed process lifetime in one import."""
from collections import defaultdict


def assemble(events):
    processes = defaultdict(list)
    for event in events:
        if event['event_id'] == 4688 and event.get('time') and event.get('process_id') is not None:
            processes[(event.get('import_id'), event.get('host'), event['process_id'])].append(event)
    groups = defaultdict(list)
    for event in events:
        if event['event_id'] != 4104:
            continue
        key = (event.get('import_id'), event.get('host'), event.get('process_id'))
        candidates = [p for p in processes[key] if event.get('time') and p['time'] <= event['time']]
        latest = max((p['time'] for p in candidates), default=None)
        nearest = [p for p in candidates if p['time'] == latest]
        context = nearest[0]['event_ref'] if len(nearest) == 1 else None
        # With no known lifetime, preserve each fragment separately instead of joining reused PIDs.
        group = (*key, event.get('script_block_id'), context or event['event_ref'])
        groups[group].append(event)
    assembled = []
    for key, fragments in groups.items():
        fragments.sort(key=lambda e: (e.get('message_number') or 0, e['event_ref']))
        totals = {e.get('message_total') for e in fragments}
        parts = defaultdict(set)
        invalid = False
        for e in fragments:
            number, total = e.get('message_number'), e.get('message_total')
            if not number or not total or number > total or e.get('script_text') is None:
                invalid = True
            else:
                parts[number].add(e['script_text'])
        total = next(iter(totals)) if len(totals) == 1 else None
        # Bound metadata: hostile MessageTotal must not allocate an unbounded list.
        complete_numbers = total is not None and total > 0 and len(parts) == total and min(parts, default=0) == 1 and max(parts, default=0) == total
        conflict = len(totals) != 1 or any(len(values) != 1 for values in parts.values())
        missing = [n for n in range(1, total + 1) if n not in parts] if total and 0 < total <= 100000 else None
        complete = not invalid and not conflict and complete_numbers and bool(key[1]) and key[2] is not None and bool(key[3])
        assembled.append({'event_refs': [e['event_ref'] for e in fragments],
                          'script_block_id': key[3], 'process_context': key[4],
                          'status': 'conflict' if conflict else 'complete' if complete else 'incomplete',
                          'missing_numbers': missing,
                          'script_text': ''.join(next(iter(parts[n])) for n in sorted(parts)) if complete else None})
    return assembled
