"""Versioned local evidence store. No user supplied paths are used for storage."""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from uuid import uuid4

SCHEMA_VERSION = 1
SCHEMA = """
CREATE TABLE imports (
 import_id TEXT PRIMARY KEY, created_at TEXT NOT NULL,
 metadata TEXT NOT NULL CHECK(json_valid(metadata)));
CREATE TABLE sources (
 source_id TEXT PRIMARY KEY, import_id TEXT NOT NULL REFERENCES imports,
 source_name TEXT NOT NULL, original_name TEXT NOT NULL,
 sha256 TEXT UNIQUE, relative_path TEXT UNIQUE, encoding TEXT,
 state TEXT NOT NULL CHECK(state IN ('ready','no_events','missing','error')),
 metadata TEXT NOT NULL CHECK(json_valid(metadata)),
 UNIQUE(import_id, source_name),
 CHECK((state = 'ready' AND sha256 IS NOT NULL AND relative_path IS NOT NULL)
       OR (state != 'ready' AND sha256 IS NULL AND relative_path IS NULL)));
CREATE TABLE events (
 event_ref TEXT PRIMARY KEY, source_id TEXT NOT NULL REFERENCES sources,
 ordinal INTEGER NOT NULL CHECK(ordinal > 0),
 normalized TEXT NOT NULL CHECK(json_valid(normalized)), raw_xml TEXT NOT NULL,
 UNIQUE(source_id, ordinal));
CREATE TABLE cases (
 case_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, version INTEGER NOT NULL,
 snapshot TEXT NOT NULL CHECK(json_valid(snapshot)), snapshot_hash TEXT NOT NULL);
CREATE TABLE case_events (
 case_id TEXT NOT NULL REFERENCES cases, event_ref TEXT NOT NULL REFERENCES events,
 position INTEGER NOT NULL CHECK(position >= 0),
 PRIMARY KEY(case_id, event_ref), UNIQUE(case_id, position));
CREATE TABLE requests (
 request_id TEXT PRIMARY KEY, idempotency_key TEXT UNIQUE,
 case_id TEXT NOT NULL REFERENCES cases, model TEXT NOT NULL,
 payload_hash TEXT NOT NULL, payload TEXT NOT NULL CHECK(json_valid(payload)),
 state TEXT NOT NULL CHECK(state IN ('queued','running','completed')),
 result_id TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL, started_at TEXT,
 completed_at TEXT);
CREATE TABLE results (
 result_id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE REFERENCES requests,
 label TEXT NOT NULL CHECK(label IN ('NORMAL','ALERT','UNKNOWN')),
 technical_error TEXT, raw_output TEXT,
 document TEXT NOT NULL CHECK(json_valid(document)), created_at TEXT NOT NULL);
CREATE TABLE evaluations (
 evaluation_id TEXT PRIMARY KEY, created_at TEXT NOT NULL,
 manifest TEXT NOT NULL CHECK(json_valid(manifest)), manifest_hash TEXT NOT NULL,
 report TEXT CHECK(report IS NULL OR json_valid(report)));
CREATE TRIGGER immutable_case_update BEFORE UPDATE ON cases
 BEGIN SELECT RAISE(ABORT, 'immutable case'); END;
CREATE TRIGGER immutable_case_delete BEFORE DELETE ON cases
 BEGIN SELECT RAISE(ABORT, 'immutable case'); END;
CREATE TRIGGER immutable_event_update BEFORE UPDATE ON events
 BEGIN SELECT RAISE(ABORT, 'immutable event'); END;
CREATE TRIGGER immutable_event_delete BEFORE DELETE ON events
 BEGIN SELECT RAISE(ABORT, 'immutable event'); END;
CREATE TRIGGER immutable_source_update BEFORE UPDATE ON sources
 BEGIN SELECT RAISE(ABORT, 'immutable source'); END;
CREATE TRIGGER immutable_source_delete BEFORE DELETE ON sources
 BEGIN SELECT RAISE(ABORT, 'immutable source'); END;
CREATE TRIGGER immutable_case_refs_update BEFORE UPDATE ON case_events
 BEGIN SELECT RAISE(ABORT, 'immutable case references'); END;
CREATE TRIGGER immutable_case_refs_delete BEFORE DELETE ON case_events
 BEGIN SELECT RAISE(ABORT, 'immutable case references'); END;
"""


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def now():
    return datetime.now(timezone.utc).isoformat()


class DuplicateSource(ValueError):
    def __init__(self, source_id):
        self.source_id = source_id
        super().__init__(f'Source already imported: {source_id}')


class Store:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        for name in ('raw', 'staging', 'normalized', 'payloads', 'exports'):
            (self.root / name).mkdir(exist_ok=True)
        with self.connect() as db:
            version = db.execute('PRAGMA user_version').fetchone()[0]
            if version not in (0, SCHEMA_VERSION):
                raise ValueError(f'Unsupported database version: {version}')
            if version == 0:
                db.executescript('BEGIN IMMEDIATE;\n' + SCHEMA + '\nPRAGMA user_version=1;\nCOMMIT;')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.root / 'database.sqlite3', timeout=30)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        db.execute('PRAGMA synchronous=FULL')
        try:
            with db:
                yield db
        finally:
            db.close()

    def create_import(self, metadata=None):
        import_id = str(uuid4())
        with self.connect() as db:
            db.execute('INSERT INTO imports VALUES(?,?,?)', (import_id, now(), canonical(metadata or {})))
        return import_id

    def add_source(self, import_id, source_name, original_name, content=None,
                   *, state='ready', metadata=None, encoding=None, validator=None, checkpoint=None, events=None):
        """Validate staged bytes, rename, then publish in a transaction.

        Exceptions leave files for recovery inspection, never delete evidence.
        checkpoint is a test hook for simulating process failure.
        """
        source_id = str(uuid4())
        sha = relative = None
        if state == 'ready':
            if not isinstance(content, bytes):
                raise TypeError('ready source requires bytes')
            sha = digest(content)
            with self.connect() as db:
                existing = db.execute('SELECT source_id FROM sources WHERE sha256=?', (sha,)).fetchone()
                if existing:
                    raise DuplicateSource(existing['source_id'])
            staged = self.root / 'staging' / f'{source_id}.part'
            with staged.open('xb') as output:
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
            if checkpoint:
                checkpoint('staged')
            if validator:
                validator(staged)
            if digest(staged.read_bytes()) != sha:
                raise ValueError('Staging hash mismatch')
            relative = f'raw/{source_id}.xml'
            staged.replace(self.root / relative)
            if checkpoint:
                checkpoint('renamed')
        elif content is not None:
            raise ValueError('Non-ready source cannot publish content')
        with self.connect() as db:
            db.execute('INSERT INTO sources VALUES(?,?,?,?,?,?,?,?,?)',
                       (source_id, import_id, source_name, original_name, sha, relative,
                        encoding, state, canonical(metadata or {})))
            if events is not None:
                if state != 'ready':
                    raise ValueError('Events require a ready source')
                for ordinal, (normalized, raw_xml) in enumerate(events, 1):
                    ref = f'{import_id}:{sha}:{ordinal}'
                    db.execute('INSERT INTO events VALUES(?,?,?,?,?)',
                               (ref, source_id, ordinal, canonical(normalized), raw_xml))
        return source_id

    def recovery_report(self):
        with self.connect() as db:
            sources = db.execute("SELECT relative_path, sha256 FROM sources WHERE state='ready'").fetchall()
        registered = {row['relative_path']: row['sha256'] for row in sources}
        return {
            'staging': sorted(p.relative_to(self.root).as_posix() for p in (self.root / 'staging').iterdir()),
            'orphans': sorted(p.relative_to(self.root).as_posix() for p in (self.root / 'raw').iterdir()
                              if p.relative_to(self.root).as_posix() not in registered),
            'missing': sorted(path for path in registered if not (self.root / path).is_file()),
            'hash_mismatch': sorted(path for path, sha in registered.items()
                                    if (self.root / path).is_file() and digest((self.root / path).read_bytes()) != sha),
        }

    def add_events(self, source_id, events):
        """events are (normalized dict, XML string) pairs in original file order."""
        refs = []
        with self.connect() as db:
            source = db.execute("SELECT * FROM sources WHERE source_id=? AND state='ready'", (source_id,)).fetchone()
            if source is None:
                raise ValueError('Source is not ready')
            for ordinal, (normalized, raw_xml) in enumerate(events, 1):
                ref = f"{source['import_id']}:{source['sha256']}:{ordinal}"
                db.execute('INSERT INTO events VALUES(?,?,?,?,?)',
                           (ref, source_id, ordinal, canonical(normalized), raw_xml))
                refs.append(ref)
        return refs

    def event(self, event_ref):
        with self.connect() as db:
            row = db.execute('SELECT e.*, s.import_id, s.sha256, s.relative_path FROM events e '
                             'JOIN sources s USING(source_id) WHERE event_ref=?', (event_ref,)).fetchone()
        if row is None:
            raise KeyError(event_ref)
        return dict(row)

    def create_case(self, refs, *, links=None, config=None, run_id=None):
        refs = list(refs)
        if len(set(refs)) != len(refs):
            raise ValueError('Duplicate evidence in case')
        snapshot = canonical({'event_refs': refs, 'links': links or [], 'config': config or {}, 'run_id': run_id})
        case_id = str(uuid4())
        with self.connect() as db:
            db.execute('INSERT INTO cases VALUES(?,?,?,?,?)', (case_id, now(), 1, snapshot, digest(snapshot.encode())))
            db.executemany('INSERT INTO case_events VALUES(?,?,?)', ((case_id, ref, i) for i, ref in enumerate(refs)))
        return case_id
