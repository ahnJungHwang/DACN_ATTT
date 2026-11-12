"""Test chống trùng cảnh báo. Chạy: .venv\\Scripts\\python.exe -m unittest discover -s tests"""
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "core"))
import alerting

T0 = datetime(2026, 11, 11, 16, 43, 56, tzinfo=timezone.utc)


def alert(*stages):
    return {"label": "ALERT", "detected_stages": list(stages)}


class DedupTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        os.environ["WINLOG_RESULTS_DIR"] = self._tmp.name
        self.d = alerting.AlertDeduplicator(window_minutes=10)

    def tearDown(self):
        os.environ.pop("WINLOG_RESULTS_DIR", None)
        self._tmp.cleanup()

    def check(self, seconds, *stages):
        return self.d.check("vm1", "HOST", alert(*stages), now=T0 + timedelta(seconds=seconds))

    def test_ai_free_text_then_mitre_code_is_duplicate(self):
        # Tái hiện alerts_log.csv 11/11: AI ghi tên trần, lô sau luật ghi mã -> trước đây gửi 2 tin
        self.assertTrue(self.check(0, "PowerShell execution")["notify"])
        self.assertFalse(self.check(17, "Tạo tiến trình mới")["notify"])
        self.assertFalse(self.check(51, "Malware Execution / PowerShell Download Cradle (MITRE T1059.001)")["notify"])
        self.assertFalse(self.check(60, "PowerShell ScriptBlock execution")["notify"])

    def test_unknown_wordings_share_one_incident(self):
        self.assertTrue(self.check(0, "Hành vi lạ kiểu A")["notify"])
        self.assertFalse(self.check(10, "Một cách diễn đạt khác hẳn")["notify"])

    def test_new_technique_still_notifies(self):
        self.check(0, "Password Brute Force (MITRE T1110)")
        r = self.check(30, "Password Brute Force (MITRE T1110)", "System Reconnaissance (MITRE T1033)")
        self.assertTrue(r["notify"])
        self.assertEqual(r["status"], "NEW_TECHNIQUE")

    def test_realert_after_window(self):
        self.check(0, "Password Brute Force (MITRE T1110)")
        self.assertTrue(self.check(11 * 60, "Password Brute Force (MITRE T1110)")["notify"])

    def test_backdoor_rules_share_parent_technique(self):
        # 3 luật trong analyze.py cho cùng một đợt tạo tài khoản backdoor -> chỉ 1 tin
        self.assertTrue(self.check(0, "Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098)")["notify"])
        self.assertFalse(self.check(5, "Create Account: Local Account (MITRE T1136.001)")["notify"])
        self.assertFalse(self.check(9, "Account Manipulation: Add to Privileged Group (MITRE T1098)")["notify"])

    def test_password_spraying_stays_separate_from_brute_force(self):
        self.check(0, "Password Brute Force (MITRE T1110)")
        r = self.check(30, "Password Spraying (MITRE T1110.003)")
        self.assertTrue(r["notify"])
        self.assertFalse(self.check(60, "Password Spraying")["notify"])  # tên trần của AI -> cùng khóa

    def test_incident_ids_unique(self):
        ids = []
        for i, s in enumerate(["A (MITRE T1110)", "B (MITRE T1033)", "C (MITRE T1059.001)"]):
            ids += self.check(i, s)["incident_ids"]
        ids += self.check(11 * 60, "A (MITRE T1110)")["incident_ids"]  # mở lại sau cửa sổ
        self.assertEqual(len({i.rsplit("-", 1)[1] for i in ids}), 4)


if __name__ == "__main__":
    unittest.main()
