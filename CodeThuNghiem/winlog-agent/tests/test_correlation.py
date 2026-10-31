from datetime import datetime, timedelta, timezone
from app.config import Settings
from app.correlation import correlate


def event(ref, eid, second, user='a', source='127.0.0.1', session=42, pid=None, imp='i'):
    return dict(event_ref=ref, event_id=eid, time=(datetime(2026, 1, 1, tzinfo=timezone.utc)+timedelta(seconds=second)).isoformat(),
                import_id=imp, host='vm', user={'name': user, 'domain': 'vm'} if user else None,
                source_address=source, logon_type=2, logon_id=session, process_id=pid, quality_errors=[])


def test_anchored_windows_threshold_and_sources():
    rows = [event(str(i), 4625, t) for i, t in enumerate([0, 10, 20, 40, 60, 61, 120, 121])]
    groups = correlate(rows, Settings())
    assert [g['failure_count'] for g in groups] == [5, 3]
    assert groups[0]['threshold_reached'] and not groups[1]['threshold_reached']
    groups = correlate([event('a',4625,0), event('b',4625,1,user='b'), event('c',4625,2,source=None), event('d',4625,3,source='other')], Settings())
    assert len(groups) == 4


def test_success_closes_group_and_boundary():
    groups = correlate([event('f',4625,0,session=999),event('s',4624,300),event('f2',4625,301)], Settings())
    assert groups[0]['event_refs'] == ['f','s']
    assert groups[1]['event_refs'] == ['f2']
    assert len(correlate([event('f',4625,0),event('s',4624,301)], Settings())) == 2
    groups = correlate([event('f',4625,0),event('s',4624,10),event('s2',4624,11)], Settings())
    assert groups[0]['event_refs'] == ['f','s'] and groups[1]['event_refs'] == ['s2']


def test_missing_source_does_not_match_multiple_groups():
    groups = correlate([event('f',4625,0),event('g',4625,1,source='other'),event('s',4624,2,source=None)], Settings())
    assert len(groups) == 3
    assert 'ambiguous_login_source' in groups[-1]['quality_warnings']


def test_session_and_pid_reuse():
    rows = [event('s',4624,0),event('p',4688,1,pid=10),event('x',4104,2,user=None,pid=10),
            event('other',4688,3,user='b',session=55,pid=10),event('y',4104,4,user=None,pid=10)]
    groups = correlate(rows, Settings())
    assert groups[0]['event_refs'] == ['s','p','x']
    assert any(g['event_refs'] == ['y'] for g in groups)
    rows = [event('s',4624,0),event('p',4688,300,pid=10),event('x',4104,301,user=None,pid=10)]
    assert correlate(rows, Settings())[0]['event_refs'] == ['s','p']


def test_missing_and_ambiguous_data_preserved_stably():
    rows = [event('s',4624,0),event('s2',4624,0),event('p',4688,1,pid=10)]
    groups = correlate(rows, Settings())
    assert len(groups) == 3
    assert groups == correlate(list(reversed(rows)), Settings())
    rows[0]['time'] = None
    rows[1]['import_id'] = 'other-run'
    assert len(correlate(rows, Settings())) == 3
    assert all('label' not in g for g in groups)


def test_sid_fallback_and_tied_successes():
    f, s = event('f',4625,0), event('s',4624,1)
    s['user']['sid'] = 'S-1-5-21-123'
    assert correlate([f,s], Settings())[0]['event_refs'] == ['f','s']
    s2 = dict(s, event_ref='s2')
    assert len(correlate([f,s,s2], Settings())) == 3
