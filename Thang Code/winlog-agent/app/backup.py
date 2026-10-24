"""Offline backup/restore. Stop the service before invoking this module."""
import argparse
import json
from pathlib import Path
import shutil
import sqlite3
from .storage import Store, canonical, digest, SCHEMA_VERSION


def verify(root):
    root = Path(root)
    manifest = json.loads((root / 'backup-manifest.json').read_text(encoding='utf-8'))
    if manifest['schema_version'] != SCHEMA_VERSION:
        raise ValueError('Incompatible backup version')
    for relative, sha in manifest['files'].items():
        path = (root / relative).resolve()
        if not path.is_relative_to(root.resolve()) or not path.is_file() or digest(path.read_bytes()) != sha:
            raise ValueError(f'Backup file missing, unsafe or changed: {relative}')
    if 'database.sqlite3' not in manifest['files']:
        raise ValueError('Backup database missing')
    return manifest


def backup(source, destination):
    source, destination = Path(source).resolve(), Path(destination).resolve()
    if destination.is_relative_to(source):
        raise ValueError('Backup must be outside data root')
    if not (source / 'database.sqlite3').is_file():
        raise ValueError('Source database missing')
    store = Store(source)
    report = store.recovery_report()
    if report['missing'] or report['hash_mismatch']:
        raise ValueError('Repair missing/changed evidence before backup')
    destination.mkdir(parents=True, exist_ok=False)
    with store.connect() as db:
        target = sqlite3.connect(destination / 'database.sqlite3')
        try:
            db.backup(target)
        finally:
            target.close()
    for name in ('raw', 'staging', 'normalized', 'payloads', 'exports'):
        shutil.copytree(source / name, destination / name)
    manifest = {'schema_version': SCHEMA_VERSION, 'recovery_report': report, 'files': {
        p.relative_to(destination).as_posix(): digest(p.read_bytes())
        for p in destination.rglob('*') if p.is_file()
    }}
    (destination / 'backup-manifest.json').write_text(canonical(manifest), encoding='utf-8')
    verify(destination)
    return manifest


def restore(source, destination):
    source, destination = Path(source).resolve(), Path(destination).resolve()
    manifest = verify(source)
    if destination.is_relative_to(source):
        raise ValueError('Restore must be outside backup root')
    destination.mkdir(parents=True, exist_ok=False)
    for relative in manifest['files']:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / relative, target)
    store = Store(destination)
    report = store.recovery_report()
    if report['missing'] or report['hash_mismatch']:
        raise ValueError('Restored evidence failed verification; preserve directory for inspection')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['backup', 'restore'])
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    parser.add_argument('--service-stopped', action='store_true', required=True,
                        help='Confirm the service and other data writers are stopped')
    args = parser.parse_args()
    print(canonical((backup if args.operation == 'backup' else restore)(args.source, args.destination)))
