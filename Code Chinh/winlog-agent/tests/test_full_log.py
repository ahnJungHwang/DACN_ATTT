"""
Test cho thí nghiệm "toàn bộ log" (md/THIET_KE_TEST_TOAN_BO_LOG_25112026.md): đọc Event ID mới, lọc nhiễu mới.
Không gọi Ollama. Chạy: .venv\\Scripts\\python.exe -m unittest discover -s tests
"""
import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "core"))

import analyze as A  # noqa: E402
from analyze import is_benign_noise, read_events  # noqa: E402

XMLNS = "http://schemas.microsoft.com/win/2004/08/events/event"


def ev(event_id, ref="E0001", time="2026-11-22T08:00:00.0000000Z", **data):
    return {"event_id": event_id, "event_ref": ref, "time": time, "data": data}


def event_xml(event_id: int, channel: str, event_data: str, time="2026-11-22T08:00:00.0000000Z") -> str:
    return (f"<Event xmlns='{XMLNS}'><System><Provider Name='p'/><EventID>{event_id}</EventID>"
            f"<TimeCreated SystemTime='{time}'/><EventRecordID>1</EventRecordID><Channel>{channel}</Channel>"
            f"<Computer>LAB-PC02</Computer></System><EventData>{event_data}</EventData></Event>")


def case_with(filename: str, *events: str) -> tempfile.TemporaryDirectory:
    tmp = tempfile.TemporaryDirectory()
    Path(tmp.name, filename).write_text("<Events>" + "".join(events) + "</Events>", encoding="utf-8")
    return tmp


CLASSIC_400 = ("<Data>Available</Data><Data>None</Data>"
               "<Data>\tNewEngineState=Available\r\n\tPreviousEngineState=None\r\n\r\n"
               "\tHostApplication=powershell.exe -enc SQBFAFgA\r\n\tEngineVersion=5.1</Data>")


class FullLogReadTests(unittest.TestCase):
    def test_classic_powershell_400_host_application(self):
        with case_with("powershell.xml", event_xml(400, "Windows PowerShell", CLASSIC_400)) as d:
            events = read_events(Path(d))
        self.assertEqual("powershell.exe -enc SQBFAFgA", events[0]["data"]["HostApplication"])
        self.assertFalse(is_benign_noise(events[0]))

    def test_classic_400_without_host_application_is_read(self):
        body = "<Data>Available</Data><Data>None</Data><Data>\tNewEngineState=Available\r\n\tEngineVersion=5.1</Data>"
        with case_with("powershell.xml", event_xml(400, "Windows PowerShell", body)) as d:
            events = read_events(Path(d))
        self.assertEqual(1, len(events))
        self.assertNotIn("HostApplication", events[0]["data"])

    def test_new_ids_only_from_their_channel(self):
        """Kernel-PnP 400 (kênh System) trùng số với PowerShell 400 -> không được đọc thành 'PowerShell engine khởi động'."""
        pnp = event_xml(400, "Microsoft-Windows-Kernel-PnP/Configuration", "<Data Name='DeviceInstanceId'>USB\\1</Data>")
        group = "<Data Name='TargetUserName'>Administrators</Data>"
        with case_with("system.xml", pnp, event_xml(4799, "System", group), SYSTEM_LOGON) as d:
            self.assertEqual([4624], [e["event_id"] for e in read_events(Path(d))])  # ID cũ vẫn đọc như trước
        with case_with("security.xml", event_xml(4799, "Security", group)) as d:
            self.assertEqual(1, len(read_events(Path(d))))
        op = event_xml(4103, "Microsoft-Windows-PowerShell/Operational", "<Data Name='Payload'>x</Data>")
        with case_with("powershell.xml", op, event_xml(400, "Windows PowerShell", CLASSIC_400)) as d:
            self.assertEqual([4103, 400], [e["event_id"] for e in read_events(Path(d))])

    def test_classic_400_enc_reaches_ai(self):
        """Luật không đọc HostApplication của 400 -> -enc phải tới được AI (không bị lọc, có trong nội dung gửi mô hình)."""
        with case_with("powershell.xml", event_xml(400, "Windows PowerShell", CLASSIC_400)) as d:
            events = [e for e in read_events(Path(d)) if not is_benign_noise(e)]
        self.assertEqual(1, len(events))
        self.assertIn("powershell.exe -enc SQBFAFgA", A.build_batch_payload(events))
        self.assertEqual([], A.correlate_security_events(events)["strong_stages"])

    def test_classic_800_commandline_feeds_strong_rules(self):
        body = ("<Data>Get-Date</Data><Data>\tDetailSequence=1\r\n\tHostApplication=powershell.exe\r\n</Data>"
                "<Data>\tCommandLine=powershell.exe -nop -w hidden -enc SQBFAFgA\r\n</Data>")
        with case_with("powershell.xml", event_xml(800, "Windows PowerShell", body)) as d:
            events = read_events(Path(d))
        self.assertEqual("powershell.exe -nop -w hidden -enc SQBFAFgA", events[0]["data"]["CommandLine"])
        self.assertTrue(A.correlate_security_events(events)["strong_stages"])

    def test_noise_ids_are_not_read(self):
        body = "<Data Name='SubjectUserName'>nv01</Data><Data Name='TargetName'>x</Data>"
        with case_with("security.xml", event_xml(5379, "Security", body)) as d:
            with self.assertRaisesRegex(ValueError, "No supported events found"):
                read_events(Path(d))


class FullLogNoiseTests(unittest.TestCase):
    def test_4672_service_accounts_are_noise(self):
        self.assertTrue(is_benign_noise(ev(4672, SubjectUserName="SYSTEM", SubjectUserSid="S-1-5-18")))
        self.assertFalse(is_benign_noise(ev(4672, SubjectUserName="nv01", SubjectUserSid="S-1-5-21-1-2-3-1001")))

    def test_group_enumeration_by_lolbin_is_not_noise(self):
        for eid in (4798, 4799):
            for path in (r"C:\Windows\System32\net1.exe",
                         r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                         r"C:\Windows\System32\whoami.exe",
                         r"C:\Users\Public\svchost.exe"):
                self.assertFalse(is_benign_noise(ev(eid, CallerProcessName=path)), (eid, path))
            for path in (r"C:\Windows\System32\svchost.exe", r"C:\Windows\System32\LogonUI.exe",
                         r"C:\Windows\SysWOW64\dllhost.exe", r"C:\Windows\explorer.exe"):
                self.assertTrue(is_benign_noise(ev(eid, CallerProcessName=path)), (eid, path))

    def test_service_name_in_writable_windows_folder_is_not_noise(self):
        """Tên dịch vụ nhưng nằm trong thư mục người dùng ghi được (Temp, Tasks, Tracing...) -> không tin."""
        for path in (r"C:\Windows\Temp\svchost.exe", r"C:\Windows\Tasks\svchost.exe",
                     r"C:\Windows\Tracing\dllhost.exe", r"C:\Windows\System32\Tasks\svchost.exe",
                     r"C:\Windows\Temp\explorer.exe"):
            self.assertFalse(is_benign_noise(ev(4799, CallerProcessName=path)), path)


BASE_PROMPT_HASHES = {
    frozenset({4104, 4624, 4625, 4648, 4688}): "8fe535636b94ee6a958c074e99368748ef1bee638aec2e2280e6c3618f055ad8",
    frozenset({1102, 4104, 4624, 4688, 4698, 7045}): "5ffde5da487aa6b3fb56451ab3001f61fb5a2672a1153de795a96f526bf0fa60",
}


def prompt_for(ids) -> str:
    return A.build_system_prompt(A.BatchVerdict.model_json_schema(), "", set(ids))


def new_group(eid: int) -> tuple:
    return next(e for e in A.EXTENDED_SIGNS if eid in e[0] and e[0] <= A.NEW_EVENT_IDS)


class FullLogPromptTests(unittest.TestCase):
    def test_base_prompts_unchanged(self):
        for ids, digest in BASE_PROMPT_HASHES.items():
            self.assertEqual(digest, hashlib.sha256(prompt_for(ids).encode()).hexdigest(), sorted(ids))

    def test_new_group_guidance_in_prompt(self):
        _, sign, normal = new_group(4799)
        p = prompt_for({4624, 4799})
        self.assertIn("T1087", p)
        self.assertIn(sign, p)
        self.assertIn(normal, p)

    def test_noise_guidance_switch(self):
        _, sign, normal = new_group(4799)
        with mock.patch.dict(os.environ, {"NOISE_GUIDANCE": "0"}):
            p = prompt_for({4624, 4799})
            self.assertIn(sign, p)
            self.assertNotIn(normal, p)
            for ids, digest in BASE_PROMPT_HASHES.items():
                self.assertEqual(digest, hashlib.sha256(prompt_for(ids).encode()).hexdigest())

    def test_every_new_id_has_meaning_and_guidance(self):
        for eid in A.NEW_EVENT_IDS:
            self.assertIn(eid, A.EVENT_MEANING, eid)
            self.assertTrue(new_group(eid)[2], eid)

    def test_lone_lolbin_group_enumeration_is_recon(self):
        """net localgroup administrators đứng một mình vẫn là trinh sát; điều kiện 'đi cùng dấu hiệu khác' chỉ cho file lạ."""
        sign, normal = next((s, n) for ids, s, n in A.EXTENDED_SIGNS if ids == {4798, 4799})
        self.assertIn("kể cả khi đứng một mình", sign)
        self.assertIn("net localgroup administrators", sign)
        self.assertIn("chỉ do các tiến trình này gọi", normal)

    def test_guidance_has_no_app_names(self):
        text = " ".join(f"{s} {n}" for ids, s, n in A.EXTENDED_SIGNS if ids <= A.NEW_EVENT_IDS).lower()
        for name in ("claude", "wpsupdate", "zalo", "bash", "gamingservices"):
            self.assertNotIn(name, text)

    def test_prompt_fingerprint_is_sha256(self):
        self.assertRegex(A.prompt_fingerprint(), r"^[0-9a-f]{64}$")


sys.path.insert(0, str(ROOT / "eval_real"))
import run_combined_eval as RCE  # noqa: E402

SYSTEM_LOGON = event_xml(4624, "Security", "<Data Name='TargetUserName'>SYSTEM</Data><Data Name='LogonType'>5</Data>")
ODD_PROCESS = event_xml(4688, "Security", "<Data Name='NewProcessName'>C:\\Users\\Public\\x.exe</Data>"
                                          "<Data Name='CommandLine'>x.exe</Data>", time="2026-11-22T08:00:05.0000000Z")


class FullLogRunnerTests(unittest.TestCase):
    def test_noise_only_case_detected(self):
        with case_with("security.xml", SYSTEM_LOGON) as d:
            self.assertTrue(RCE.is_noise_only(Path(d)))
        with case_with("security.xml", SYSTEM_LOGON, ODD_PROCESS) as d:
            self.assertFalse(RCE.is_noise_only(Path(d)))

    def test_dev_split_has_no_attack_cases(self):
        if not any(RCE.CASES_DIR.glob("lam_full_*")):
            self.skipTest("Chưa dựng ca lam_full_* (build_normal_cases.ps1 -IdSet Full)")
        dev = RCE.load_cases("full", "dev")
        test = RCE.load_cases("full", "test")
        self.assertTrue(dev)
        self.assertEqual({"normal_full"}, {c["category"] for c in dev})
        self.assertTrue(any(c["case_id"].endswith("_full") for c in test))
        self.assertTrue(all(c["case_id"].startswith("lam_full_") or c["case_id"].endswith("_full") for c in test))

    def test_only_filter(self):
        if not any(RCE.CASES_DIR.glob("lam_full_*")):
            self.skipTest("Chưa dựng ca lam_full_*")
        first = RCE.load_cases("full", "dev")[0]["case_id"]
        self.assertEqual([first], [c["case_id"] for c in RCE.load_cases("full", "dev", only={first})])

    def test_resume_ignores_partial_row(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "r.csv")
            p.write_text(",".join(RCE.FIELDS) + "\n"
                         "qwen,lam_full_a,normal_full,NORMAL,NORMAL" + "," * (len(RCE.FIELDS) - 5) + "\n"
                         "qwen,lam_full_b,normal_full,NORMAL", encoding="utf-8")
            self.assertEqual({("qwen", "lam_full_a")}, RCE.load_done(p))

    def test_resume_ignores_truncated_label(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "r.csv")
            p.write_text(",".join(RCE.FIELDS) + "\n"
                         "qwen,lam_full_a,normal_full,NORMAL,NORMAL" + "," * (len(RCE.FIELDS) - 5) + "\n"
                         "qwen,lam_full_b,normal_full,NORMAL,ALE", encoding="utf-8")
            self.assertEqual({("qwen", "lam_full_a")}, RCE.load_done(p))

    def run_args(self, out):
        import argparse
        return argparse.Namespace(out=str(out), only="", set="full", split="test", tools="qwen", no_gpu_guard=True,
                                  tag="t", gpu_limit=58)

    def test_rows_record_noise_guidance_and_prompt(self):
        fake = {"verdict": {"label": "NORMAL"}, "batch_results": []}
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(RCE, "load_cases", lambda *a: [{"case_id": "c1", "category": "normal_full",
                                                                   "ground_truth": "NORMAL"}]), \
                mock.patch.object(RCE, "skip_as_noise", lambda *a: False), \
                mock.patch.object(RCE.A, "analyze_case", lambda *a, **k: fake), \
                mock.patch.dict(os.environ, {"NOISE_GUIDANCE": "0"}):
            RCE.run(self.run_args(Path(d, "r.csv")))
            expected = A.prompt_fingerprint()  # prompt đối chứng (NOISE_GUIDANCE=0 đang bật)
            import csv
            with open(Path(d, "r.csv"), encoding="utf-8") as f:
                row = next(csv.DictReader(f))
        self.assertEqual("0", row["noise_guidance"])
        self.assertEqual(expected, row["prompt_fingerprint"])

    def test_resume_refuses_old_header(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "r.csv")
            old = ",".join(f for f in RCE.FIELDS if f not in ("noise_guidance", "prompt_fingerprint"))
            p.write_text(old + "\n", encoding="utf-8")

            def no_model(*a, **k):
                raise AssertionError("không được gọi mô hình")

            with mock.patch.object(RCE, "load_cases", lambda *a: [{"case_id": "c1", "category": "normal_full",
                                                                   "ground_truth": "NORMAL"}]), \
                    mock.patch.object(RCE.A, "analyze_case", no_model), self.assertRaises(SystemExit):
                RCE.run(self.run_args(p))
            self.assertEqual(old + "\n", p.read_text(encoding="utf-8"))

    def test_events_after_noise_filter(self):
        with case_with("security.xml", SYSTEM_LOGON, ODD_PROCESS) as d:
            self.assertEqual(1, RCE.events_after_noise([Path(d)]))

    def test_report_lists_unscored_and_skips_truncated(self):
        import argparse
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "r.csv")
            pad = "," * (len(RCE.FIELDS) - 5)
            p.write_text(",".join(RCE.FIELDS) + "\n"
                         f"qwen,a1,scored,ALERT,ALERT{pad}\n"
                         f"qwen,n1,normal_session,NORMAL,NORMAL{pad}\n"
                         f"qwen,i1,insufficient_evidence,ALERT,NORMAL{pad}\n"
                         "qwen,n2,normal_session,NORMAL,ALE", encoding="utf-8")
            md = Path(d, "r.md")
            RCE.report(argparse.Namespace(out=str(p), baseline="", deepblue="", hayabusa="", set="legacy", tag="t",
                                          md=str(md)))
            text = md.read_text(encoding="utf-8")
        self.assertIn("(0/1;", text)  # n2 ghi dở không được tính
        self.assertIn("insufficient_evidence", text.split("## 3b.")[1])
        self.assertIn("`i1`", text.split("## 3b.")[1])

    def test_noise_only_skip_only_full_normal(self):
        with case_with("security.xml", SYSTEM_LOGON) as d:
            self.assertTrue(RCE.skip_as_noise("full", "normal_full", Path(d)))
            self.assertFalse(RCE.skip_as_noise("full", "scored", Path(d)))  # ca tấn công vẫn gửi mô hình
            self.assertFalse(RCE.skip_as_noise("legacy", "normal_session", Path(d)))  # lượt cũ giữ nguyên

    def test_report_keeps_attack_noise_only_as_miss(self):
        rows = [{"tool": "qwen", "case_id": "n1", "category": "normal_full", "pred": "NOISE_ONLY"},
                {"tool": "deepblue", "case_id": "n1", "category": "normal_full", "pred": "NORMAL"},
                {"tool": "qwen", "case_id": "a1", "category": "scored", "pred": "NOISE_ONLY"},
                {"tool": "qwen", "case_id": "a2", "category": "scored", "pred": "ALERT"}]
        kept, normal_noise, attack_noise = RCE.split_noise_only(rows)
        self.assertEqual(["n1"], normal_noise)
        self.assertEqual(["a1"], attack_noise)
        self.assertEqual(["a1", "a2"], [r["case_id"] for r in kept])


class CompareRunsTests(unittest.TestCase):
    def test_reports_only_changed_fields(self):
        import compare_runs as CR
        row = {"tool": "qwen", "case_id": "c1", "pred": "NORMAL", "ai_only": "NORMAL", "decision_source": "ai",
               "risk_score": "10", "stages": ""}
        ref = {("qwen", "c1"): row, ("llama", "c1"): {**row, "tool": "llama"}}
        new = {("qwen", "c1"): row, ("llama", "c1"): {**row, "tool": "llama", "pred": "ALERT"}}
        diffs = CR.compare(ref, new)
        self.assertEqual(1, len(diffs))
        self.assertIn("llama c1", diffs[0])
        self.assertIn("'NORMAL' -> 'ALERT'", diffs[0])

    def test_same_reasons_oldest_vs_newest_json(self):
        import compare_runs as CR

        def write(d, stamp, reason):
            batch = {"batch": 1, "verdict": {"label": "NORMAL", "reason": reason}}
            Path(d, "c1", f"qwen_{stamp}.json").write_text(
                json.dumps({"result": {"batch_results": [batch]}}), encoding="utf-8")

        with tempfile.TemporaryDirectory() as d:
            Path(d, "c1").mkdir()
            self.assertIsNone(CR.same_reasons(Path(d), "c1", "qwen"))
            write(d, "20261125T010000Z", "a")
            write(d, "20261125T020000Z", "khác")
            write(d, "20261125T030000Z", "a")
            self.assertTrue(CR.same_reasons(Path(d), "c1", "qwen"))
            write(d, "20261125T040000Z", "b")
            self.assertFalse(CR.same_reasons(Path(d), "c1", "qwen"))


import colab_pack as CP  # noqa: E402


def logon(user: str, sid: str = "S-1-5-21-111-222-333-1001") -> str:
    return event_xml(4624, "Security", f"<Data Name='TargetUserName'>{user}</Data><Data Name='TargetSid'>{sid}</Data>"
                                       "<Data Name='LogonType'>2</Data>")


class AnonymizeTests(unittest.TestCase):
    def test_name_map_skips_builtins(self):
        group = event_xml(4799, "Security", "<Data Name='TargetUserName'>Administrators</Data>"
                                            "<Data Name='TargetSid'>S-1-5-32-544</Data>")
        with case_with("security.xml", logon("nhanvien"), logon("SYSTEM", "S-1-5-18"), logon("LAB-PC02$"),
                       logon("Administrator", "S-1-5-21-111-222-333-500"), logon("DWM-1"), logon("-"), group) as d:
            self.assertEqual({"nhanvien": "USER01"}, CP.build_name_map([Path(d)]))

    def test_anonymize_everywhere_and_keep_rid(self):
        text = ("<Data Name='TargetUserName'>NhanVien</Data><Data Name='ScriptBlockText'>cd C:\\x\\nhanvien\\y</Data>"
                "<Data Name='TargetSid'>S-1-5-21-111-222-333-1001</Data><Data Name='GroupSid'>S-1-5-32-544</Data>")
        out = CP.anonymize_xml(text, {"nhanvien": "USER01"})
        self.assertNotIn("nhanvien", out.lower())
        self.assertIn("USER01", out)
        self.assertIn("S-1-5-21-0-0-0-1001", out)
        self.assertIn("S-1-5-32-544", out)

    def test_pack_keeps_only_fields_analyze_reads(self):
        vault = event_xml(5382, "Security", "<Data Name='SubjectUserName'>USER01</Data><Data Name='Resource'>r</Data>"
                                            "<Data Name='ProcessCreationTime'>bí mật</Data><Data Name='ReturnCode'>0</Data>")
        ps = event_xml(400, "Windows PowerShell", CLASSIC_400.replace("\tEngineVersion=5.1", "\tUserId=MAY\\bí mật"))
        for f, body, gone in (("security.xml", vault + ODD_PROCESS, "ProcessCreationTime"),
                              ("powershell.xml", ps, "UserId")):
            with case_with(f, body) as d:
                before = read_events(Path(d))
                raw = Path(d, f).read_text(encoding="utf-8")
                kept = CP.keep_read_fields(raw)
                self.assertIn(gone, raw)
                self.assertNotIn(gone, kept)
                self.assertNotIn("bí mật", kept)
                Path(d, f).write_text(kept, encoding="utf-8")
                self.assertEqual(before, read_events(Path(d)))  # mô hình / luật thấy y như cũ

    def test_anonymize_respects_word_boundary(self):
        out = CP.anonymize_xml("<Data>Administrators admin1 adminx</Data>", {"admin1": "USER01"})
        self.assertEqual("<Data>Administrators USER01 adminx</Data>", out)


if __name__ == "__main__":
    unittest.main()
