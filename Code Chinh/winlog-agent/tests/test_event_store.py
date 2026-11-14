"""Test cửa sổ sự kiện trượt (core/event_store.py). Chạy: .venv/Scripts/python.exe -m unittest discover -s tests"""
import sys
import tempfile
import unittest
from pathlib import Path


BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / "core"))

from analyze import correlate_security_events, read_events  # noqa: E402
from event_store import EventStore  # noqa: E402


def security_xml(record_id: int, second: int) -> str:
    return f"""<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID>
    <TimeCreated SystemTime="2026-10-26T08:00:{second:02d}.0000000Z"/>
    <EventRecordID>{record_id}</EventRecordID><Channel>Security</Channel><Computer>WINLAB</Computer></System>
    <EventData><Data Name="TargetUserName">admin</Data><Data Name="IpAddress">10.0.0.8</Data>
    <Data Name="LogonType">3</Data></EventData></Event></Events>"""


class EventStoreTests(unittest.TestCase):
    def test_events_across_batches_are_correlated_and_deduplicated(self):
        with tempfile.TemporaryDirectory() as temp:
            store = EventStore(Path(temp) / "events.db", window_seconds=300)
            self.assertEqual(1, store.ingest_xml("client-a", "security", security_xml(1, 0)))
            self.assertEqual(1, store.ingest_xml("client-a", "security", security_xml(2, 10)))
            self.assertEqual(0, store.ingest_xml("client-a", "security", security_xml(2, 10)))
            self.assertEqual(1, store.ingest_xml("client-a", "security", security_xml(3, 20)))

            case_dir = Path(temp) / "case"
            counts = store.materialize_case("client-a", case_dir)
            self.assertEqual(3, counts["security"])
            findings = correlate_security_events(read_events(case_dir))
            self.assertIn("Password Brute Force (MITRE T1110)", findings["stages"])
            self.assertGreaterEqual(findings["risk_score"], 70)

    def test_alert_cooldown_suppresses_only_repeats(self):
        with tempfile.TemporaryDirectory() as temp:
            store = EventStore(Path(temp) / "events.db")
            self.assertFalse(store.register_alert("client-a", "fingerprint-a", 300))
            self.assertTrue(store.register_alert("client-a", "fingerprint-a", 300))
            self.assertFalse(store.register_alert("client-a", "fingerprint-b", 300))


if __name__ == "__main__":
    unittest.main()
