"""Opt-in HTTP/process recovery checks with real local Ollama on a copied store.

Run from project root with PYTHONPATH=.; not collected by pytest. Requires idle
Ollama, free port 8000, verified tokenizers, and no other inference/writers.
Uses a one-second timeout only in its private config to exercise failure.
"""
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
from uuid import uuid4

import httpx

from app.backup import backup, restore
from app.config import MODELS
from app.storage import Store, canonical, digest, now

ROOT = Path(__file__).resolve().parents[1]


def main():
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 8000))
    ollama = httpx.Client(base_url='http://127.0.0.1:11434', trust_env=False, timeout=300)
    response = ollama.get('/api/ps'); response.raise_for_status()
    if response.json()['models']:
        raise RuntimeError('External model loaded; do not interrupt it')
    out = ROOT / 'data/real-recovery' / str(uuid4())
    out.mkdir(parents=True)
    source = Store(ROOT / 'data/verify-original')
    with source.connect() as db:
        assert db.execute("SELECT count(*) FROM requests WHERE state!='completed'").fetchone()[0] == 0
    backup(source.root, out / 'initial-backup')
    restore(out / 'initial-backup', out / 'store')
    shutil.copytree(ROOT / 'data/tokenizers', out / 'store/tokenizers')
    seed = json.loads((ROOT / 'data/real-log-verification-5cf144eb-ee96-49c3-ae93-7b183457eea3.json').read_text(encoding='utf-8'))
    case = seed['cases']['successful_login']['case_id']
    store = Store(out / 'store')
    process = None
    log = (out / 'api.log').open('a', encoding='utf-8')
    client = httpx.Client(base_url='http://127.0.0.1:8000', trust_env=False, timeout=30)
    report = {'created_at': now(), 'case_id': case, 'complete': False, 'checks': [],
              'ground_truth': None, 'scope': 'real HTTP/API/process/Ollama; n8n volume not tested'}

    def save():
        (out / 'summary.json').write_text(canonical(report), encoding='utf-8')

    def wait(predicate, timeout=60):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(.02)
        raise RuntimeError('Recovery verification deadline exceeded')

    def start(timeout=300):
        nonlocal process
        (out / 'config.toml').write_text('data_root="store"\nport=8000\nresponse_wait_seconds=1\ninference_timeout_seconds=' + str(timeout) + '\n', encoding='utf-8')
        process = subprocess.Popen([sys.executable, '-m', 'app.api', '--config', str(out / 'config.toml')],
                                   cwd=ROOT, stdout=log, stderr=log)
        def ready():
            if process.poll() is not None:
                raise RuntimeError('API exited; inspect api.log')
            try:
                return client.get('/health').status_code == 200
            except httpx.HTTPError:
                return False
        wait(ready, 30)
        client.headers['Authorization'] = 'Bearer ' + (out / 'store/secrets/api-token.txt').read_text().strip()

    def stop():
        nonlocal process
        if process is not None and process.poll() is None:
            process.terminate(); process.wait(timeout=20)
        process = None

    def unload_owned():
        # Initial ps was empty and this dedicated test only submitted Qwen.
        models = ollama.get('/api/ps').json()['models']
        if any(m['name'] != MODELS[0] for m in models):
            raise RuntimeError('Unexpected external model; do not unload')
        if models:
            r = ollama.post('/api/generate', json={'model': MODELS[0], 'stream': False, 'keep_alive': 0})
            r.raise_for_status()
        wait(lambda: not ollama.get('/api/ps').json()['models'], 30)

    def dropped_post(key):
        body = canonical({'case_id': case, 'model': MODELS[0]}).encode()
        headers = ('POST /analyze HTTP/1.1\r\nHost: 127.0.0.1:8000\r\nAuthorization: ' +
                   client.headers['Authorization'] + '\r\nIdempotency-Key: ' + key +
                   '\r\nContent-Type: application/json\r\nContent-Length: ' + str(len(body)) +
                   '\r\nConnection: close\r\n\r\n').encode()
        with socket.create_connection(('127.0.0.1', 8000), timeout=5) as sock:
            sock.sendall(headers + body)
            # Intentionally close without reading any response.

    def row(key):
        with store.connect() as db:
            value = db.execute('SELECT * FROM requests WHERE request_id=?', (key,)).fetchone()
            return dict(value) if value else None

    def completed(key):
        value = row(key)
        return value if value and value['state'] == 'completed' else None

    def result(key):
        response = client.get('/requests/' + key); response.raise_for_status()
        return response.json()

    def replay(key, original):
        response = client.post('/analyze', json={'case_id': case, 'model': MODELS[0]},
                               headers={'Idempotency-Key': key})
        response.raise_for_status()
        assert response.json() == original
        with store.connect() as db:
            assert db.execute('SELECT count(*) FROM requests WHERE idempotency_key=?', (key,)).fetchone()[0] == 1
            assert db.execute('SELECT count(*) FROM results WHERE request_id=?', (key,)).fetchone()[0] == 1

    def record(name, key, envelope):
        report['checks'].append({'scenario': name, 'request_id': key, 'result_id': envelope['result_id'],
                                 'label': envelope['result']['label'], 'technical_error': envelope['result']['technical_error'],
                                 'result_hash': digest(canonical(envelope['result']).encode())})
        save(); print(canonical(report['checks'][-1]), flush=True)

    try:
        start()
        key = str(uuid4()); dropped_post(key)
        wait(lambda: completed(key), 330)
        original = result(key)
        assert original['result'].get('response') is not None, original['result']['technical_error']
        replay(key, original)
        record('client_closed_before_response', key, original)
        unload_owned()

        key = str(uuid4()); dropped_post(key)
        wait(lambda: row(key) and row(key)['state'] == 'running')
        stop()
        assert row(key)['state'] == 'running', 'Job finished before process was stopped; rerun needed'
        start()
        interrupted = result(key)
        assert interrupted['result']['technical_error'] == 'INTERRUPTED'
        replay(key, interrupted)
        record('backend_stopped_while_running', key, interrupted)
        stop(); unload_owned()

        start(timeout=1)
        key = str(uuid4()); dropped_post(key)
        wait(lambda: completed(key), 330)
        timed_out = result(key)
        assert timed_out['result']['technical_error'] == 'TIMEOUT', timed_out['result']['technical_error']
        blocked_key = str(uuid4())
        blocked = client.post('/analyze', json={'case_id': case, 'model': MODELS[1]},
                              headers={'Idempotency-Key': blocked_key})
        assert blocked.status_code == 503 and blocked.json()['error'] == 'SERVICE_DEGRADED', 'Timeout gate not observed; preserve run for review'
        assert row(blocked_key) is None
        report['second_model_rejected_during_timeout_recovery'] = True
        replay(key, timed_out)
        record('one_second_real_inference_deadline', key, timed_out)
        # Allow the old call to finish; do not claim timeout cancels Ollama.
        time.sleep(2)
        stop(); unload_owned()
        start()
        assert result(key) == timed_out
        conflict = client.post('/analyze', json={'case_id': case, 'model': MODELS[0]},
                               headers={'Idempotency-Key': key})
        assert conflict.status_code == 409 and conflict.json()['error'] == 'IDEMPOTENCY_CONFLICT'
        report['changed_timeout_replay_rejected'] = True
        stop(); start(timeout=1)
        replay(key, timed_out)
        stop()

        backup(out / 'store', out / 'final-backup')
        restore(out / 'final-backup', out / 'restored')
        restored = Store(out / 'restored')
        with restored.connect() as db:
            for check in report['checks']:
                doc = db.execute('SELECT document FROM results WHERE request_id=?', (check['request_id'],)).fetchone()[0]
                assert digest(canonical(json.loads(doc)).encode()) == check['result_hash']
        integrity = restored.recovery_report()
        assert not integrity['missing'] and not integrity['hash_mismatch']
        report['backup_restore_raw_results_verified'] = True
        report['complete'] = True
    finally:
        stop(); client.close(); ollama.close(); log.close(); save()
    print(str(out / 'summary.json'), flush=True)


if __name__ == '__main__':
    main()
