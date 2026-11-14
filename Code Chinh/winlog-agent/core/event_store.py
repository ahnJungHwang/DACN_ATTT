"""Cửa sổ sự kiện trượt lưu bằng SQLite cho luồng nhận log trực tiếp (gộp từ bản update 13/11/2026).

Mỗi lô client gửi được ghi vào DB (chống trùng theo Channel|Computer|EventRecordID), rồi xuất lại
toàn bộ sự kiện trong EVENT_WINDOW_SECONDS gần nhất ra security.xml / powershell.xml / system.xml
-> bộ luật tương quan được chuỗi tấn công trải qua nhiều lô gửi 3 giây (vd brute force chậm).
"""

from __future__ import annotations

import hashlib
import sqlite3
import threading
import time
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path


NS = {"w": "http://schemas.microsoft.com/win/2004/08/events/event"}
# system.xml (7045 cài service, 104 xoá log System) do client mới gửi thêm
CHANNEL_FILES = (("security", "security.xml"), ("powershell", "powershell.xml"), ("system", "system.xml"))


def _parse_time(value: str) -> float:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


class EventStore:
    """Persist, deduplicate and materialize a rolling window of Windows events."""

    def __init__(self, db_path: Path | str, window_seconds: int = 600):
        self.db_path = Path(db_path)
        self.window_seconds = window_seconds
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=15)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=15000")
        return conn

    @contextmanager
    def _connection(self):
        conn = self._connect()
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _initialize(self) -> None:
        with self._connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    client_id TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    event_key TEXT NOT NULL,
                    event_ts REAL NOT NULL,
                    xml_text TEXT NOT NULL,
                    received_at REAL NOT NULL,
                    PRIMARY KEY (client_id, channel, event_key)
                );
                CREATE INDEX IF NOT EXISTS idx_events_window
                    ON events(client_id, event_ts);

                CREATE TABLE IF NOT EXISTS alert_fingerprints (
                    client_id TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    PRIMARY KEY (client_id, fingerprint)
                );
                """
            )

    @staticmethod
    def _extract_events(xml_text: str) -> list[tuple[str, float, str]]:
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            raise ValueError(f"Invalid event XML: {exc}") from exc

        extracted = []
        for event in root.findall("w:Event", NS):
            system = event.find("w:System", NS)
            if system is None:
                continue
            created = system.find("w:TimeCreated", NS)
            timestamp = created.get("SystemTime", "") if created is not None else ""
            if not timestamp:
                continue
            try:
                event_ts = _parse_time(timestamp)
            except ValueError:
                continue
            record_id = system.findtext("w:EventRecordID", default="", namespaces=NS)
            computer = system.findtext("w:Computer", default="", namespaces=NS)
            source_channel = system.findtext("w:Channel", default="", namespaces=NS)
            serialized = ET.tostring(event, encoding="unicode")
            stable_part = f"{source_channel}|{computer}|{record_id}"
            event_key = stable_part if record_id else hashlib.sha256(serialized.encode()).hexdigest()
            extracted.append((event_key, event_ts, serialized))
        return extracted

    def ingest_xml(self, client_id: str, channel: str, xml_text: str) -> int:
        events = self._extract_events(xml_text)
        if not events:
            return 0
        now = time.time()
        with self._lock, self._connection() as conn:
            before = conn.total_changes
            conn.executemany(
                """
                INSERT OR IGNORE INTO events
                    (client_id, channel, event_key, event_ts, xml_text, received_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (client_id, channel, event_key, event_ts, serialized, now)
                    for event_key, event_ts, serialized in events
                ],
            )
            inserted = conn.total_changes - before
            self._prune_locked(conn, client_id)
            return inserted

    def _latest_timestamp_locked(self, conn: sqlite3.Connection, client_id: str) -> float | None:
        row = conn.execute(
            "SELECT MAX(event_ts) FROM events WHERE client_id = ?", (client_id,)
        ).fetchone()
        return row[0] if row and row[0] is not None else None

    def _prune_locked(self, conn: sqlite3.Connection, client_id: str) -> None:
        latest = self._latest_timestamp_locked(conn, client_id)
        if latest is None:
            return
        conn.execute(
            "DELETE FROM events WHERE client_id = ? AND event_ts < ?",
            (client_id, latest - self.window_seconds),
        )

    def materialize_case(self, client_id: str, case_dir: Path | str) -> dict[str, int]:
        case_dir = Path(case_dir)
        case_dir.mkdir(parents=True, exist_ok=True)
        counts = {}
        with self._lock, self._connection() as conn:
            latest = self._latest_timestamp_locked(conn, client_id)
            minimum = (latest - self.window_seconds) if latest is not None else float("inf")
            for channel, filename in CHANNEL_FILES:
                rows = conn.execute(
                    """
                    SELECT xml_text FROM events
                    WHERE client_id = ? AND channel = ? AND event_ts >= ?
                    ORDER BY event_ts, event_key
                    """,
                    (client_id, channel, minimum),
                ).fetchall()
                document = "<Events>" + "".join(row[0] for row in rows) + "</Events>"
                target = case_dir / filename
                temporary = target.with_suffix(target.suffix + ".tmp")
                temporary.write_text(document, encoding="utf-8")
                temporary.replace(target)
                counts[channel] = len(rows)
        return counts

    def register_alert(self, client_id: str, fingerprint: str, cooldown_seconds: int) -> bool:
        """Return True when the same alert was already seen inside the cooldown."""
        now = time.time()
        with self._lock, self._connection() as conn:
            row = conn.execute(
                """SELECT last_seen FROM alert_fingerprints
                   WHERE client_id = ? AND fingerprint = ?""",
                (client_id, fingerprint),
            ).fetchone()
            duplicate = bool(row and now - row[0] < cooldown_seconds)
            conn.execute(
                """
                INSERT INTO alert_fingerprints(client_id, fingerprint, first_seen, last_seen)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(client_id, fingerprint)
                DO UPDATE SET last_seen = excluded.last_seen
                """,
                (client_id, fingerprint, now, now),
            )
            conn.execute(
                "DELETE FROM alert_fingerprints WHERE last_seen < ?", (now - 86400,)
            )
            return duplicate

    def stats(self) -> dict[str, int]:
        with self._connection() as conn:
            events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            clients = conn.execute("SELECT COUNT(DISTINCT client_id) FROM events").fetchone()[0]
        return {"events": events, "clients": clients, "window_seconds": self.window_seconds}
