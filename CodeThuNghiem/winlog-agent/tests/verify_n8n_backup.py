"""Opt-in backup/restore verification of stopped local n8n_data.

Keeps the original volume read-only; leaves a separate restored volume and
archive for inspection. Archive contains secrets; all output is under data/.
"""
import json
from pathlib import Path
import subprocess
from uuid import uuid4

from app.storage import canonical, digest, now

ROOT = Path(__file__).resolve().parents[1]
IMAGE = 'n8nio/n8n@sha256:d02752c6ab446ae9db8deec2f9cc887c378f77cdcad31650814df936b7386dfb'
HASH_SCRIPT = """const fs=require('fs'),p=require('path'),crypto=require('crypto');
const rows=[];
function walk(dir,rel='') { for(const name of fs.readdirSync(dir).sort()) {
 const full=p.join(dir,name),key=rel?rel+'/'+name:name,s=fs.lstatSync(full);
 if(s.isSymbolicLink()) throw Error('Symlink requires manual backup review');
 if(s.isDirectory()) {rows.push({path:key,type:'directory',mode:s.mode&4095,uid:s.uid,gid:s.gid});walk(full,key);}
 else if(s.isFile()) rows.push({path:key,type:'file',size:s.size,mode:s.mode&4095,uid:s.uid,gid:s.gid,
 sha256:crypto.createHash('sha256').update(fs.readFileSync(full)).digest('hex')});
 else throw Error('Unsupported file type');
}}
walk('/source');process.stdout.write(JSON.stringify(rows));
"""


def main():
    def docker(*args):
        value = subprocess.run(['docker', *args], capture_output=True, text=True, encoding='utf-8', timeout=300)
        if value.returncode:
            raise RuntimeError('Docker backup operation failed: ' + value.stderr[-1000:])
        return value.stdout

    def stopped():
        if docker('ps', '--filter', 'volume=n8n_data', '--format', '{{.Names}}').strip():
            raise RuntimeError('n8n_data is in use; stop its writers before backup')

    stopped()
    docker('volume', 'inspect', 'n8n_data')
    run_id = str(uuid4())
    out = ROOT / 'data/n8n-backup-verification' / run_id
    out.mkdir(parents=True)
    (out / 'hash.cjs').write_text(HASH_SCRIPT, encoding='utf-8')
    target = 'winlog-n8n-restored-' + run_id
    report = {'created_at': now(), 'source_volume': 'n8n_data', 'restored_volume': target,
              'complete': False, 'scope': 'offline filesystem backup/restore; not application login'}

    def inventory(volume):
        return json.loads(docker('run', '--rm', '--user', '0', '--mount',
            'type=volume,source=' + volume + ',target=/source,readonly', '--mount',
            'type=bind,source=' + str(out) + ',target=/work,readonly',
            '--network', 'none', '--entrypoint', 'node', IMAGE, '/work/hash.cjs'))

    try:
        before = inventory('n8n_data')
        (out / 'source-inventory.json').write_text(canonical(before), encoding='utf-8')
        stopped()
        docker('run', '--rm', '--user', '0', '--network', 'none', '--mount',
               'type=volume,source=n8n_data,target=/source,readonly', '--mount',
               'type=bind,source=' + str(out) + ',target=/backup', '--entrypoint', '/bin/sh', IMAGE,
               '-c', 'tar -czf /backup/n8n-volume.tar.gz -C /source .')
        stopped()
        assert inventory('n8n_data') == before, 'Source changed during backup'
        docker('volume', 'create', '--label', 'winlog.verification=' + run_id, target)
        docker('run', '--rm', '--user', '0', '--network', 'none', '--mount',
               'type=volume,source=' + target + ',target=/restored', '--mount',
               'type=bind,source=' + str(out) + ',target=/backup,readonly', '--entrypoint', '/bin/sh', IMAGE,
               '-c', 'tar -xzf /backup/n8n-volume.tar.gz -C /restored')
        after = inventory(target)
        (out / 'restored-inventory.json').write_text(canonical(after), encoding='utf-8')
        assert after == before, 'Restored volume differs from source'
        assert inventory('n8n_data') == before, 'Original volume changed'
        report.update(complete=True, entries=len(before), files=sum(r['type'] == 'file' for r in before),
                      bytes=sum(r.get('size', 0) for r in before),
                      archive_sha256=digest((out / 'n8n-volume.tar.gz').read_bytes()),
                      inventory_sha256=digest(canonical(before).encode()))
    finally:
        (out / 'summary.json').write_text(canonical(report), encoding='utf-8')
    print(canonical(report), flush=True)
    print(str(out / 'summary.json'), flush=True)


if __name__ == '__main__':
    main()
