"""Opt-in local integration with installed n8n/Ollama and copied real logs.

Run from the project root with PYTHONPATH=.; never collected by pytest.
Requires Docker/Ollama running, no other inference, and the prior real-log smoke.
Creates an isolated store/container; leaves evidence under ignored data/.
Does not modify the user's n8n volume or assign ground truth.
"""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
from uuid import uuid4

import httpx

from app.backup import backup, restore
from app.config import MODELS
from app.storage import Store, canonical, digest, now

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from build_workflow import build

IMAGE = 'n8nio/n8n@sha256:d02752c6ab446ae9db8deec2f9cc887c378f77cdcad31650814df936b7386dfb'


def execution_document(raw):
    decoder = json.JSONDecoder()
    for index, char in enumerate(raw):
        if char == '{':
            try:
                value, _ = decoder.raw_decode(raw[index:])
            except ValueError:
                continue
            if isinstance(value, dict) and 'data' in value:
                return value
    raise RuntimeError('No n8n execution JSON; inspect local execution file')


def main():
    source = ROOT / 'data/verify-original'
    with httpx.Client(trust_env=False, timeout=5) as client:
        response = client.get('http://127.0.0.1:11434/api/ps')
        response.raise_for_status()
        if response.json()['models']:
            raise RuntimeError('External model loaded; stop verification')
    with Store(source).connect() as db:
        if db.execute("SELECT count(*) FROM requests WHERE state != 'completed'").fetchone()[0]:
            raise RuntimeError('Source contains unfinished jobs')
    seed = json.loads((ROOT / 'data/real-log-verification-5cf144eb-ee96-49c3-ae93-7b183457eea3.json').read_text(encoding='utf-8'))
    case_id = seed['cases']['successful_login']['case_id']
    run_id = str(uuid4())
    out = ROOT / 'data/real-n8n' / run_id
    out.mkdir(parents=True)
    backup(source, out / 'source-backup')
    restore(out / 'source-backup', out / 'store')
    shutil.copytree(ROOT / 'data/tokenizers', out / 'store/tokenizers')
    (out / 'config.toml').write_text('data_root = "store"\nport = 8000\nresponse_wait_seconds = 1\n', encoding='utf-8')
    container = 'winlog-real-' + run_id[:8]
    process = None
    created = False
    logfile = (out / 'api.log').open('a', encoding='utf-8')
    report = {'created_at': now(), 'ground_truth': None, 'collection_manifest_missing': True,
              'case_id': case_id, 'image': IMAGE, 'runs': [], 'complete': False}

    def save():
        (out / 'summary.json').write_text(canonical(report), encoding='utf-8')

    def docker(*args):
        result = subprocess.run(['docker', *args], capture_output=True, text=True,
                                encoding='utf-8', timeout=720)
        if result.returncode:
            (out / 'docker-error.txt').write_text(result.stdout + result.stderr, encoding='utf-8')
            raise RuntimeError('Docker command failed; inspect local docker-error.txt')
        return result.stdout

    client = httpx.Client(base_url='http://127.0.0.1:8000', trust_env=False, timeout=30)

    def start_api():
        nonlocal process
        process = subprocess.Popen([sys.executable, '-m', 'app.api', '--config', str(out / 'config.toml')],
                                   cwd=ROOT, stdout=logfile, stderr=logfile)
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError('API exited; inspect api.log')
            try:
                if client.get('/health').status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(.2)
        raise RuntimeError('API startup timeout')

    def stop_api():
        nonlocal process
        if process is not None and process.poll() is None:
            process.terminate()
            process.wait(timeout=20)
        process = None

    def execute(model, key, suffix):
        workflow = build()
        workflow['id'] = 'real-' + suffix
        workflow['name'] = 'Local real-log verification ' + suffix
        for node in workflow['nodes']:
            if node['name'] == 'Edit Fields':
                values = {'base_url': 'http://host.docker.internal:8000', 'case_id': case_id,
                          'model': model, 'request_id': key}
                for field in node['parameters']['values']['string']:
                    field['value'] = values[field['name']]
            if node['type'] == 'n8n-nodes-base.httpRequest':
                node['credentials'] = {'httpHeaderAuth': {'id': 'isolated-api', 'name': 'Isolated local API'}}
        (out / (suffix + '.json')).write_text(canonical(workflow), encoding='utf-8')
        docker('exec', container, 'n8n', 'import:workflow', '--input=/work/' + suffix + '.json')
        raw = docker('exec', container, 'n8n', 'execute', '--id=' + workflow['id'], '--rawOutput')
        (out / (suffix + '-execution.txt')).write_text(raw, encoding='utf-8')
        run = execution_document(raw)['data']['resultData']['runData']
        branches = [label for label in ('NORMAL', 'ALERT', 'UNKNOWN') if label in run]
        assert len(branches) == 1, list(run)
        item = run[branches[0]][-1]['data']['main'][0][0]['json']
        response = client.get('/requests/' + key)
        response.raise_for_status()
        status = response.json()
        assert status['state'] == 'completed'
        assert item['request_id'] == key and item['result_id'] == status['result_id']
        assert item['label'] == status['result']['label']
        assert item['evidence_refs'] == status['result']['evidence_refs']
        for ref in item['evidence_refs']:
            evidence = client.get('/events/' + ref)
            evidence.raise_for_status()
            assert evidence.json()['raw_xml']
        exported = client.get('/results/' + item['result_id'] + '/export?format=jsonl')
        exported.raise_for_status()
        assert json.loads(exported.text) == status['result']
        record = {'model': model, 'request_id': key, 'result_id': item['result_id'],
                  'label': item['label'], 'technical_error': status['result']['technical_error'],
                  'model_response_received': status['result'].get('response') is not None,
                  'polls': len(run.get('Poll', [])), 'result_hash': digest(canonical(status['result']).encode())}
        report['runs'].append(record)
        save()
        print(canonical(record), flush=True)
        return record

    try:
        start_api()
        token = (out / 'store/secrets/api-token.txt').read_text().strip()
        client.headers['Authorization'] = 'Bearer ' + token
        credential = [{'id': 'isolated-api', 'name': 'Isolated local API', 'type': 'httpHeaderAuth',
                       'data': {'name': 'Authorization', 'value': 'Bearer ' + token}}]
        (out / 'credential.json').write_text(canonical(credential), encoding='utf-8')
        docker('run', '-d', '--name', container, '--mount', 'type=bind,source=' + str(out) + ',target=/work,readonly',
               '-e', 'N8N_DIAGNOSTICS_ENABLED=false', '-e', 'N8N_VERSION_NOTIFICATIONS_ENABLED=false',
               '-e', 'N8N_TEMPLATES_ENABLED=false', '--entrypoint', '/bin/sh', IMAGE, '-c', 'sleep infinity')
        created = True
        docker('exec', container, 'n8n', 'import:credentials', '--input=/work/credential.json')
        originals = [execute(model, str(uuid4()), 'model-' + str(i)) for i, model in enumerate(MODELS)]
        assert all(r['model_response_received'] for r in originals), 'No actual model response; see technical_error'
        stop_api()
        backup(out / 'store', out / 'completed-backup')
        restore(out / 'completed-backup', out / 'restored')
        restored = Store(out / 'restored')
        assert not any(restored.recovery_report()[k] for k in ('missing', 'hash_mismatch'))
        with restored.connect() as db:
            for record in originals:
                document = db.execute('SELECT document FROM results WHERE result_id=?', (record['result_id'],)).fetchone()[0]
                assert digest(canonical(json.loads(document)).encode()) == record['result_hash']
        report['backup_restore_results_and_raw_verified'] = True
        start_api()
        repeat = execute(MODELS[0], originals[0]['request_id'], 'retry-after-restart')
        assert repeat['result_id'] == originals[0]['result_id']
        assert repeat['result_hash'] == originals[0]['result_hash']
        with Store(out / 'store').connect() as db:
            assert db.execute('SELECT count(*) FROM requests WHERE idempotency_key=?', (repeat['request_id'],)).fetchone()[0] == 1
        report['completed_request_restart_replay_verified'] = True
        report['complete'] = True
    finally:
        stop_api()
        client.close()
        logfile.close()
        if created:
            docker('stop', container)
            docker('rm', container)
        save()
    print(str(out / 'summary.json'), flush=True)


if __name__ == '__main__':
    main()
