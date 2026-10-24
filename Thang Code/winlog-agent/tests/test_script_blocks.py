from app.script_blocks import assemble


def process(ref='p', time='2026-01-01T00:00:00+00:00'):
    return dict(event_id=4688, import_id='i', host='vm', process_id=42, event_ref=ref, time=time)


def fragment(n, text, ref=None, total=3, time='2026-01-01T00:00:01+00:00'):
    return dict(event_id=4104, import_id='i', host='vm', process_id=42, event_ref=ref or str(n),
                time=time, script_block_id='s', message_number=n, message_total=total, script_text=text)


def test_complete_out_of_order_duplicate_refs_retained():
    result = assemble([process(), fragment(3, 'c'), fragment(1, 'a'), fragment(2, 'b'), fragment(2, 'b', 'dup')])[0]
    assert result['status'] == 'complete' and result['script_text'] == 'abc'
    assert set(result['event_refs']) == {'1', '2', '3', 'dup'}


def test_missing_conflicting_and_invalid():
    result = assemble([process(), fragment(1, 'a'), fragment(3, 'c')])[0]
    assert result['missing_numbers'] == [2] and result['script_text'] is None
    result = assemble([process(), fragment(1, 'a'), fragment(1, 'x', 'other')])[0]
    assert result['status'] == 'conflict' and result['script_text'] is None
    assert assemble([process(), fragment(0, 'a')])[0]['status'] == 'incomplete'
    assert assemble([process(), fragment(1, 'a', total=10**12)])[0]['script_text'] is None


def test_pid_reuse_and_unknown_context_do_not_join():
    rows = [process(), fragment(1, 'a'), process('p2', '2026-01-01T00:00:02+00:00'),
            fragment(2, 'b', time='2026-01-01T00:00:03+00:00')]
    assert len(assemble(rows)) == 2
    assert all(r['script_text'] is None for r in assemble(rows))
    assert len(assemble([fragment(1, 'a'), fragment(2, 'b')])) == 2
