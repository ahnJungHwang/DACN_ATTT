"""Persist completed immutable inference documents against registered requests."""
import json
from .storage import canonical, now


def save_result(store, request_id, document):
    # Serialize first: reject non-finite numbers or non-JSON values before writing.
    serialized = canonical(document)
    with store.connect() as db:
        request = db.execute('SELECT * FROM requests WHERE request_id=?',(request_id,)).fetchone()
        if request is None:
            raise KeyError(request_id)
        if request['state'] == 'completed':
            existing = db.execute('SELECT document FROM results WHERE request_id=?',(request_id,)).fetchone()
            if existing is None or existing['document'] != serialized:
                raise ValueError('Completed result cannot be replaced')
            return request['result_id']
        db.execute('INSERT INTO results VALUES(?,?,?,?,?,?,?)',
                   (request['result_id'],request_id,document['label'],document['technical_error'],
                    document.get('raw_output'),serialized,now()))
        db.execute("UPDATE requests SET state='completed', completed_at=? WHERE request_id=?",(now(),request_id))
    return request['result_id']


def read_result(store, result_id):
    with store.connect() as db:
        row=db.execute('SELECT document FROM results WHERE result_id=?',(result_id,)).fetchone()
    if row is None:
        raise KeyError(result_id)
    return json.loads(row['document'])
