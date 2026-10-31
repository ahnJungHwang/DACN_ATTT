"""Evidence-based grouping. No ground-truth or model label is assigned here."""
from datetime import datetime
from .storage import canonical, digest


def timestamp(event):
    value = event.get('time')
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
        return parsed.timestamp() if parsed.tzinfo else None
    except ValueError:
        return None


def identity(event):
    user = event.get('user') or {}
    if user.get('sid'):
        return ('sid', user['sid'].casefold())
    if user.get('name'):
        return ('name', (user.get('domain') or '').casefold(), user['name'].casefold())
    return None


def scope(event):
    return event.get('import_id'), (event.get('host') or '').casefold()


def same_user(left, right):
    a, b = left.get('user') or {}, right.get('user') or {}
    if a.get('sid') and b.get('sid'):
        return a['sid'].casefold() == b['sid'].casefold()
    return bool(a.get('name') and b.get('name') and
                a['name'].casefold() == b['name'].casefold() and
                (a.get('domain') or '').casefold() == (b.get('domain') or '').casefold())


def login_key(event):
    return (*scope(event), identity(event), event.get('logon_type'), event.get('source_address'))


def correlate(events, settings):
    rows = sorted(events, key=lambda e: (timestamp(e) is None, timestamp(e) or 0, e['event_ref']))
    if len({e['event_ref'] for e in rows}) != len(rows):
        raise ValueError('Duplicate event references')
    by_ref = {e['event_ref']: e for e in rows}
    groups, active, assigned, success_groups = [], {}, {}, {}

    def new_group(event, kind):
        group = {'kind': kind, 'event_refs': [], 'links': [], 'quality_warnings': [], 'failure_count': 0}
        groups.append(group)
        add(group, event)
        return group

    def add(group, event):
        group['event_refs'].append(event['event_ref'])
        assigned[event['event_ref']] = group
        group['quality_warnings'].extend(event.get('quality_errors', []))

    def warn(group, reason, candidates=()):
        group['quality_warnings'].append(reason)
        group['links'].append({'relation': reason, 'certainty': 'ambiguous', 'candidate_refs': list(candidates)})

    # Resolve successes while streaming: a successful login closes its failure group.
    for e in rows:
        if e['event_id'] not in (4624, 4625):
            continue
        time = timestamp(e)
        key = login_key(e)
        usable = time is not None and all(scope(e)) and identity(e) is not None and e.get('logon_type') is not None
        if e['event_id'] == 4625:
            group = active.get(key) if usable else None
            if group is None or time - timestamp(by_ref[group['event_refs'][0]]) > settings.failure_window_seconds:
                group = new_group(e, 'failed_logins')
                if usable:
                    active[key] = group
            else:
                add(group, e)
            group['failure_count'] += 1
            if not usable:
                warn(group, 'missing_login_identity_or_time')
            if e.get('source_address') is None:
                warn(group, 'missing_source_address')
        else:
            compatible = []
            if usable:
                for candidate_key, candidate in active.items():
                    previous = by_ref[candidate['event_refs'][-1]]
                    if scope(previous) != scope(e) or not same_user(previous, e) or previous.get('logon_type') != e.get('logon_type'):
                        continue
                    gap = time - timestamp(by_ref[candidate['event_refs'][-1]])
                    if 0 <= gap <= settings.success_window_seconds and (
                        candidate_key[4] == key[4] or candidate_key[4] is None or key[4] is None
                    ):
                        compatible.append((candidate_key, candidate))
            exact = [(k, g) for k, g in compatible if k[4] == key[4]]
            # Missing source amid several possibilities cannot prove which group succeeded.
            ambiguous = len(compatible) > 1 and (key[4] is None or any(k[4] is None for k, _ in compatible))
            tied_successes = [s for s in rows if s['event_id'] == 4624 and s['event_ref'] != e['event_ref']
                              and time is not None and timestamp(s) == time and scope(s) == scope(e)
                              and same_user(s, e) and s.get('logon_type') == e.get('logon_type')
                              and s.get('source_address') == e.get('source_address')]
            ambiguous = ambiguous or bool(tied_successes)
            if len(exact) == 1 and not ambiguous:
                candidate_key, group = exact[0]
                failure_ref = group['event_refs'][-1]
                add(group, e)
                group['links'].append({'relation': 'login_after_failures', 'certainty': 'supported',
                                       'from': failure_ref, 'to': e['event_ref']})
                active.pop(candidate_key)
            else:
                group = new_group(e, 'successful_login')
                if compatible:
                    warn(group, 'ambiguous_login_source', [r for _, g in compatible for r in g['event_refs']])
            success_groups[e['event_ref']] = group

    successes = [e for e in rows if e['event_id'] == 4624 and timestamp(e) is not None]
    processes = [e for e in rows if e['event_id'] == 4688]
    for e in processes:
        candidates = [s for s in successes if timestamp(e) is not None
                      and all(scope(e)) and scope(s) == scope(e)
                      and same_user(s, e)
                      and e.get('logon_id') not in (None, 0) and s.get('logon_id') == e['logon_id']
                      and 0 <= timestamp(e) - timestamp(s) <= settings.activity_window_seconds]
        if len(candidates) == 1:
            s = candidates[0]
            group = success_groups[s['event_ref']]
            add(group, e)
            group['links'].append({'relation': 'process_in_session', 'certainty': 'supported',
                                   'from': s['event_ref'], 'to': e['event_ref']})
        else:
            group = new_group(e, 'unassigned')
            warn(group, 'ambiguous_or_missing_session', [s['event_ref'] for s in candidates])

    for e in rows:
        if e['event_id'] != 4104:
            continue
        related = [p for p in processes if all(scope(e)) and scope(p) == scope(e)
                   and e.get('process_id') is not None and p.get('process_id') == e['process_id']]
        earlier = [p for p in related if timestamp(e) is not None and timestamp(p) is not None and timestamp(p) <= timestamp(e)]
        latest = max((timestamp(p) for p in earlier), default=None)
        nearest = [p for p in earlier if timestamp(p) == latest]
        target = None
        if len(nearest) == 1 and not any(timestamp(p) is None for p in related):
            p = nearest[0]
            group = assigned[p['event_ref']]
            session_links = [link for link in group['links'] if link.get('relation') == 'process_in_session'
                             and link.get('to') == p['event_ref']]
            if len(session_links) == 1:
                s = by_ref[session_links[0]['from']]
                if 0 <= timestamp(e) - timestamp(s) <= settings.activity_window_seconds:
                    target = (group, p)
        if target:
            group, p = target
            add(group, e)
            group['links'].append({'relation': 'script_in_observed_process', 'certainty': 'supported',
                                   'from': p['event_ref'], 'to': e['event_ref']})
        else:
            group = new_group(e, 'unassigned')
            warn(group, 'ambiguous_or_missing_process', [p['event_ref'] for p in nearest])

    for e in rows:
        if e['event_ref'] not in assigned:
            new_group(e, 'unassigned')
    order = {e['event_ref']: i for i, e in enumerate(rows)}
    for group in groups:
        group['event_refs'].sort(key=order.__getitem__)
        group['group_id'] = digest(canonical(group['event_refs']).encode())[:24]
        group['threshold_reached'] = group['failure_count'] >= settings.failure_threshold
        group['quality_warnings'] = sorted(set(group['quality_warnings']))
    return sorted(groups, key=lambda g: order[g['event_refs'][0]])
