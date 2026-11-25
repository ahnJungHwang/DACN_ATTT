import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
import xml.etree.ElementTree as ET

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

import requests
from pydantic import BaseModel, ConfigDict, Field


BASE = Path(__file__).resolve().parent.parent  # thư mục gốc winlog-agent (file này ở core/)
NS = {
    "w": "http://schemas.microsoft.com/win/2004/08/events/event",
}

MODELS = {
    "qwen": "qwen2.5:3b-instruct-q4_K_M",
    "llama": "llama3.2:3b-instruct-q4_K_M",
}

# Có thể ghi đè bằng biến môi trường OLLAMA_URL.
OLLAMA_URL = os.getenv(
    "OLLAMA_URL",
    "http://127.0.0.1:11434/api/chat",
)

# Giới hạn theo số ký tự để giữ mỗi yêu cầu ở mức nhỏ.
MAX_BATCH_CHARS = int(os.getenv("MAX_BATCH_CHARS", "15000"))

# Mã sự kiện được phân tích. Nhóm mở rộng (07/11/2026): xoá nhật ký, cài service, tạo/nâng quyền tài khoản, scheduled task.
SUPPORTED_EVENT_IDS = {
    4624, 4625, 4648, 4688, 4104,      # đăng nhập, tạo tiến trình, PowerShell
    1102, 104,                          # xoá nhật ký Security / System
    7045,                               # cài service mới (System)
    4720, 4722, 4728, 4732, 4756,       # tạo / bật tài khoản, thêm vào nhóm global / local / universal
    4698,                               # tạo scheduled task
}
# Thí nghiệm "toàn bộ log" (md/THIET_KE_TEST_TOAN_BO_LOG_25112026.md): ID có giá trị ngoài 12 ID agent thu.
# Agent hiện chưa thu các ID này -> ca cũ không bị ảnh hưởng.
NEW_EVENT_IDS = {
    4798, 4799,         # dò tài khoản / nhóm (T1087 / T1069)
    4672,               # đặc quyền nhạy cảm khi đăng nhập
    5382,               # đọc vault (T1555)
    4797,               # dò tài khoản mật khẩu trống
    4738,               # sửa tài khoản (T1098)
    4647,               # người dùng chủ động đăng xuất
    4616,               # đổi giờ hệ thống (T1070.006)
    1100, 4719,         # dịch vụ log tắt / đổi chính sách audit (T1562.002)
    4103,               # PowerShell module logging
    400, 800,           # Windows PowerShell (cổ điển): engine bật (HostApplication), pipeline
}
SUPPORTED_EVENT_IDS |= NEW_EVENT_IDS
MAX_FIELD_CHARS = 2000  # cắt TaskContent (file XML định nghĩa task) để vừa context
# Trường chỉ lấy cho NEW_EVENT_IDS (4720 cũng có PrivilegeList / UAC... -> không đổi dữ liệu của ca cũ)
NEW_FIELDS = {
    "CallerProcessName", "PrivilegeList", "SchemaFriendlyName", "Resource", "Identity", "Workstation",
    "HostApplication", "Payload", "ContextInfo", "OldUacValue", "NewUacValue", "UserAccountControl",
    "SidHistory", "AllowedToDelegateTo", "PasswordLastSet", "PreviousTime", "NewTime",
    "CategoryId", "SubcategoryGuid", "AuditPolicyChanges",
}
LONG_FIELDS = ("TaskContent", "HostApplication", "Payload", "ContextInfo")
CLASSIC_PS_FIELD = re.compile(r"^\s*(HostApplication|CommandLine)=([^\r\n]*)", re.MULTILINE)

FIELDS = {
    "ServiceName", "ImagePath", "ServiceType", "StartType", "AccountName",   # 7045
    "MemberName", "MemberSid", "TargetSid", "SamAccountName", "GroupName",   # 4720 / 4722 / 4728 / 4732 / 4756
    "TaskName", "TaskContent",                                               # 4698
    "Channel", "BackupPath",                                                 # 104 / 1102 (UserData)
    "SubjectUserSid",
    "SubjectUserName",
    "SubjectDomainName",
    "SubjectLogonId",
    "TargetUserSid",
    "TargetUserName",
    "TargetDomainName",
    "TargetLogonId",
    "LogonType",
    "IpAddress",
    "WorkstationName",
    "Status",
    "SubStatus",
    "AuthenticationPackageName",
    "ProcessId",
    "ProcessName",
    "NewProcessId",
    "NewProcessName",
    "ParentProcessName",
    "CommandLine",
    "ScriptBlockText",
    "ScriptBlockId",
    "MessageNumber",
    "MessageTotal",
}

# Các tiến trình nền hệ thống lành tính trên Windows (Telemetry / Update)
NOISE_PROCESSES = {
    "microsoftedgeupdate.exe", "edgeupdate.exe", "compattelrunner.exe",
    "filecoauth.exe", "onedrivestandaloneupdater.exe", "devicecensus.exe",
    "sihclient.exe", "waasmedicagent.exe", "mousocoreworker.exe",
    "musnotification.exe", "musnotificationux.exe", "wsqmcons.exe",
    "sppsvc.exe", "sppextcomobj.exe", "slui.exe", "usoclient.exe",
    "upfc.exe", "hxtsr.exe", "runtimebroker.exe", "dllhost.exe",
    "wmiprvse.exe", "backgroundtaskhost.exe", "searchprotocolhost.exe",
    "searchfilterhost.exe", "searchapp.exe", "texthost.exe", "textinputhost.exe",
    "shellexperiencehost.exe", "startmenuexperiencehost.exe", "msedge.exe",
    "tiworker.exe", "trustedinstaller.exe", "wermgr.exe", "gamebar.exe",
    "winstore.app.exe", "mobsync.exe", "securityhealthhost.exe",
}

# Tiến trình dịch vụ Windows liệt kê thành viên nhóm (4798 / 4799) khi đăng nhập, sao lưu, tìm kiếm
GROUP_ENUM_SERVICES = {
    "svchost.exe", "vssvc.exe", "taskhostw.exe", "logonui.exe", "dllhost.exe", "explorer.exe", "searchindexer.exe",
}

# Ngưỡng tương quan brute force theo cửa sổ thời gian (gộp từ bản update 13/11/2026).
# Đăng nhập mạng (LogonType 3/10) sai liên tục nghi ngờ hơn gõ sai tại bàn phím nên ngưỡng thấp hơn.
CORRELATION_WINDOW_SECONDS = int(os.getenv("CORRELATION_WINDOW_SECONDS", "300"))
NETWORK_BRUTE_FORCE_THRESHOLD = int(os.getenv("NETWORK_BRUTE_FORCE_THRESHOLD", "3"))
INTERACTIVE_BRUTE_FORCE_THRESHOLD = int(os.getenv("INTERACTIVE_BRUTE_FORCE_THRESHOLD", "5"))
POST_BRUTE_SUCCESS_WINDOW_SECONDS = int(os.getenv("POST_BRUTE_SUCCESS_WINDOW_SECONDS", "600"))

# Trọng số rủi ro theo giai đoạn (điểm tham khảo 0-100, cộng dồn rồi chặn trên 100).
# Nhãn ALERT/NORMAL vẫn do cơ chế luật mạnh + AI quyết định; risk_score chỉ để xếp hạng / hiển thị.
STAGE_RISK_WEIGHTS = {
    "Password Brute Force (MITRE T1110)": 75,
    "Multiple Failed Logons (MITRE T1110)": 30,
    "Password Spraying (MITRE T1110.003)": 75,
    "Successful Logon Post-Brute Force (MITRE T1078)": 25,
    "Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098)": 90,
    "Account Creation Command (MITRE T1136)": 30,
    "PowerShell / Command and Scripting Interpreter (MITRE T1059.001)": 75,
    "OS Credential Dumping (MITRE T1003)": 100,
    "Impair Defenses (MITRE T1562.001)": 95,
    "Indicator Removal: Clear Windows Event Logs (MITRE T1070.001)": 95,
    "Persistence (MITRE T1547.001 / T1053.005)": 85,
    "System Reconnaissance (MITRE T1033)": 40,
    "Inhibit System Recovery (MITRE T1490)": 95,
    "Accessibility Features / Sticky Keys Backdoor (MITRE T1546.008)": 90,
    "In-Memory Assembly Execution (MITRE T1055)": 90,
    "Credential Access / Kerberoasting (MITRE T1558.003)": 85,
    "LOLBAS / Script Proxy Execution (MITRE T1218)": 90,
    "Deobfuscate/Decode Files (MITRE T1140)": 85,
    "Lateral Movement / Remote Execution (MITRE T1569 / T1047 / T1021)": 90,
    "Network Discovery / Port Scanning (MITRE T1046)": 80,
    "Ingress Tool Transfer (MITRE T1105 / T1197)": 85,
    "Data Collection & Exfiltration (MITRE T1560 / T1048)": 85,
    "Impact / Data Destruction & Ransomware (MITRE T1485 / T1486)": 95,
    "UAC Bypass (MITRE T1548.002)": 90,
    "Offensive Tooling: Discovery & Privilege Escalation Audit (MITRE T1087 / T1069 / T1482)": 85,
    "Exploitation for Privilege Escalation (MITRE T1068)": 95,
    "Indicator Removal / Hide Artifacts (MITRE T1070 / T1564.001)": 85,
    "File Permission Tampering (MITRE T1222.001)": 80,
    "Hijack Execution Flow (MITRE T1546 / T1574)": 90,
    "Reverse Shell / Protocol Tunneling (MITRE T1095 / T1572)": 90,
    "Create or Modify System Process: Malicious Service (MITRE T1543.003 / T1569.002)": 95,
    "New Service Installed (MITRE T1543.003)": 30,
    "Create Account: Local Account (MITRE T1136.001)": 30,
    "Account Manipulation: Add to Privileged Group (MITRE T1098)": 90,
    "Scheduled Task Persistence (MITRE T1053.005)": 85,
    "New Scheduled Task (MITRE T1053.005)": 25,
}
ALERT_RISK_THRESHOLD = int(os.getenv("ALERT_RISK_THRESHOLD", "70"))
REVIEW_RISK_THRESHOLD = int(os.getenv("REVIEW_RISK_THRESHOLD", "40"))


class BatchVerdict(BaseModel):
    """Schema Reasoning-First: Mô hình suy luận và liệt kê bằng chứng trước khi kết luận nhãn."""
    model_config = ConfigDict(extra="forbid")

    detected_stages: list[str] = Field(
        max_length=6,
        description="Danh sách các giai đoạn tấn công phát hiện được (ví dụ: Password Brute Force, Reconnaissance, Backdoor Creation, Privilege Escalation, OS Credential Dumping, Malware Execution, Persistence)"
    )
    evidence_refs: list[str] = Field(
        max_length=30,
        description="Danh sách các mã event_ref làm bằng chứng cho từng hành vi nghi ngờ"
    )
    reason: str = Field(
        min_length=1,
        description="Phân tích ngắn gọn 2-3 câu về chuỗi hành vi từ các bằng chứng tìm thấy"
    )
    label: Literal["ALERT", "NORMAL", "UNKNOWN"] = Field(
        description="Kết luận: ALERT nếu phát hiện bất kỳ dấu hiệu tấn công nào, NORMAL nếu hoàn toàn lành tính, UNKNOWN nếu thiếu dữ liệu"
    )
    limitations: list[str] = Field(
        max_length=2,
        description="Tối đa 1-2 giới hạn ngắn gọn, hoặc danh sách rỗng [] nếu không có giới hạn nào"
    )


class Verdict(BaseModel):
    """Schema tổng hợp cuối cùng trả về cho client / API."""
    model_config = ConfigDict(extra="ignore")

    # REVIEW: AI không kết luận được nhưng bộ luật có tín hiệu yếu đủ điểm rủi ro -> chuyển chuyên gia xem
    label: Literal["ALERT", "REVIEW", "NORMAL", "UNKNOWN"]
    reason: str = Field(min_length=1)
    evidence_refs: list[str]
    limitations: list[str]
    detected_stages: list[str] = Field(default_factory=list)
    decision_source: str = ""                         # rule+ai / ai / rule / error
    detection_source: str = ""                        # bí danh tương thích bản update (hybrid / rule / ai_model)
    risk_score: int = Field(default=0, ge=0, le=100)  # điểm rủi ro tham khảo
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


def is_benign_noise(event: dict) -> bool:
    """Lọc bỏ các tiến trình và dịch vụ hệ thống định kỳ không liên quan đến điều tra."""
    eid = event.get("event_id")
    data = event.get("data", {})

    if eid == 4688:
        proc = data.get("NewProcessName", "").lower()
        base_proc = proc.split("\\")[-1]
        cmd = data.get("CommandLine", "").strip()
        # Chỉ tin tên tiến trình khi file nằm trong thư mục hệ thống; mã độc đặt tên dllhost.exe /
        # svchost.exe ở C:\Users\... (T1036 Masquerading) không được coi là nhiễu.
        if not proc.startswith(("c:\\windows\\", "c:\\program files\\", "c:\\program files (x86)\\")):
            return False

        # Tiến trình telemetry / updater đã biết
        if base_proc in NOISE_PROCESSES:
            return True
        # taskhostw không có tham số
        if base_proc == "taskhostw.exe" and (not cmd or cmd == "taskhostw.exe"):
            return True
        # conhost hệ thống
        if base_proc == "conhost.exe":
            return True
        # Tiến trình hệ thống cốt lõi không có tham số
        if not cmd and any(p in proc for p in (
            "svchost.exe", "services.exe", "lsass.exe", "csrss.exe",
            "smss.exe", "winlogon.exe", "wininit.exe", "autochk.exe", "explorer.exe"
        )):
            return True

    elif eid == 4672:
        # Đặc quyền gán cho tài khoản dịch vụ hệ thống ở mỗi lần khởi động dịch vụ
        if data.get("SubjectUserSid") in ("S-1-5-18", "S-1-5-19", "S-1-5-20") or data.get("SubjectUserName") in (
            "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"
        ):
            return True

    elif eid in (4798, 4799):
        # Dịch vụ Windows kiểm tra nhóm khi đăng nhập / sao lưu. Chỉ tin khi file nằm trong C:\Windows\;
        # net.exe / net1.exe / whoami / powershell / cmd dò nhóm = trinh sát (T1087 / T1069), không bao giờ là nhiễu.
        caller = data.get("CallerProcessName", "").lower()
        if caller.startswith("c:\\windows\\") and caller.split("\\")[-1] in GROUP_ENUM_SERVICES:
            return True

    elif eid == 4624:
        # Lọc bỏ LogonType 5 (Dịch vụ nền khởi động dưới quyền SYSTEM/Service)
        if data.get("LogonType") == "5" and data.get("TargetUserName") in (
            "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"
        ):
            return True

    elif eid == 4104:
        # Lọc bỏ các đoạn script nội bộ của PowerShell engine (Prompt, formatter)
        txt = data.get("ScriptBlockText", "")
        # Module CDXML do PowerShell tự sinh (header "#requires -version 3.0" + Cmdletization).
        # Không lọc theo riêng chữ "Set-StrictMode": kẻ tấn công chỉ cần thêm dòng đó để giấu script.
        # Giả header vẫn bị giữ lại nếu luật thấy dấu hiệu tấn công trong khối.
        if (txt.lstrip().lower().startswith("#requires -version 3.0") and "Cmdletization" in txt
                and not correlate_security_events([event])["stages"]):
            return True
        if txt.strip() == "$global:?" or (
            "prompt" in txt.lower() and len(txt) < 50
        ):
            return True

    return False


def read_events(case_dir: Path) -> list[dict]:
    """Đọc các sự kiện được hỗ trợ từ security.xml, powershell.xml và system.xml.

    Mỗi file đều tuỳ chọn (một ca có thể chỉ có 1 kênh log, vd chỉ powershell.xml); phải có ít nhất 1 file.
    """
    events = []
    found_files = 0

    for filename in ("security.xml", "powershell.xml", "system.xml"):
        path = case_dir / filename

        if not path.is_file():
            continue  # ca / client cũ có thể không có kênh log này
        found_files += 1

        try:
            root = ET.parse(path).getroot()
        except ET.ParseError as exc:
            raise ValueError(f"Invalid XML in {filename}: {exc}") from exc

        for event in root.findall("w:Event", NS):
            system = event.find("w:System", NS)
            if system is None:
                raise ValueError(f"Event in {filename} has no System element")

            def system_text(name: str) -> str:
                return system.findtext(
                    f"w:{name}",
                    default="",
                    namespaces=NS,
                )

            event_id_text = system_text("EventID")
            try:
                event_id = int(event_id_text)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"Invalid EventID in {filename}: {event_id_text!r}"
                ) from exc

            if event_id not in SUPPORTED_EVENT_IDS:
                continue

            timestamp = system.find("w:TimeCreated", NS)
            provider = system.find("w:Provider", NS)
            execution = system.find("w:Execution", NS)

            allowed = FIELDS | NEW_FIELDS if event_id in NEW_EVENT_IDS else FIELDS
            data_items = event.findall("w:EventData/w:Data", NS)
            data = {
                item.get("Name"): item.text or ""
                for item in data_items
                if item.get("Name") in allowed
            }
            # Windows PowerShell cổ điển (400 / 800): <Data> không tên, chuỗi "HostApplication=..." nằm trong văn bản
            if event_id in (400, 800):
                text = "\n".join(item.text or "" for item in data_items if not item.get("Name"))
                for name, value in CLASSIC_PS_FIELD.findall(text):
                    if value.strip():
                        data.setdefault(name, value.strip())
            # 1102 / 104 lưu dữ liệu trong <UserData><LogFileCleared>...</LogFileCleared></UserData>
            user_data = event.find("w:UserData", NS)
            if user_data is not None:
                for block in user_data:
                    for item in block:
                        name = item.tag.split("}")[-1]
                        if name in FIELDS and item.text:
                            data.setdefault(name, item.text)
            # TaskContent là cả file XML định nghĩa task -> cắt bớt; ScriptBlockText giữ nguyên như trước
            for name in LONG_FIELDS:
                if len(data.get(name, "")) > MAX_FIELD_CHARS:
                    data[name] = data[name][:MAX_FIELD_CHARS] + "…[cắt bớt]"

            events.append({
                "time": (
                    timestamp.get("SystemTime")
                    if timestamp is not None
                    else ""
                ),
                "host": system_text("Computer"),
                "channel": system_text("Channel"),
                "provider": (
                    provider.get("Name")
                    if provider is not None
                    else ""
                ),
                "record_id": system_text("EventRecordID"),
                "event_id": event_id,
                "system_process_id": (
                    execution.get("ProcessID")
                    if execution is not None
                    else None
                ),
                "data": data,
            })

    if not found_files:
        raise ValueError("Missing file: security.xml / powershell.xml / system.xml")

    if not events:
        raise ValueError("No supported events found")

    if any(not event["time"] for event in events):
        raise ValueError("An event has no timestamp")

    try:
        events.sort(
            key=lambda event: datetime.fromisoformat(
                event["time"].replace("Z", "+00:00")
            )
        )
    except ValueError as exc:
        raise ValueError("An event has an invalid timestamp") from exc

    for index, event in enumerate(events, start=1):
        event["event_ref"] = f"E{index:04d}"

    return events


def _event_time(event: dict) -> datetime:
    """Mốc thời gian (aware) của một sự kiện đã chuẩn hoá."""
    return datetime.fromisoformat(event["time"].replace("Z", "+00:00"))


def _clean_identity(value: str | None) -> str:
    value = (value or "").strip().lower()
    return "" if value in {"", "-", "::1", "127.0.0.1"} else value


def _qualifying_clusters(grouped_events: dict[tuple[str, str], list[dict]]) -> list[dict]:
    """Tìm chuỗi đăng nhập sai lặp lại của cùng một danh tính (tài khoản hoặc IP) trong cửa sổ trượt."""
    clusters = []
    for (kind, value), group in grouped_events.items():
        ordered = sorted(group, key=_event_time)
        for start in range(len(ordered)):
            threshold = (
                NETWORK_BRUTE_FORCE_THRESHOLD
                if ordered[start]["data"].get("LogonType") in {"3", "10"}
                else INTERACTIVE_BRUTE_FORCE_THRESHOLD
            )
            window = []
            start_time = _event_time(ordered[start])
            for event in ordered[start:]:
                if (_event_time(event) - start_time).total_seconds() > CORRELATION_WINDOW_SECONDS:
                    break
                window.append(event)
            if len(window) >= threshold:
                clusters.append({"kind": kind, "value": value, "events": window})
                break
    return clusters


ADMIN_GROUP_WORDS = ("administrators", "administratoren", "administrateurs")
_EXE_SUFFIX_RE = re.compile(r"\.exe(?=[\s\"']|$)")


def _norm_cmd(raw: str | None) -> str:
    """Chuẩn hoá CommandLine cho luật: chữ thường, gộp khoảng trắng, bỏ đường dẫn + đuôi .exe của chương trình.
    '"C:\\Windows\\system32\\net.exe" user x /add' -> 'net user x /add' (log thật hay ghi đủ đường dẫn)."""
    cmd = " ".join((raw or "").lower().split())
    if cmd.startswith('"'):
        exe, _, rest = cmd[1:].partition('"')
    else:
        exe, _, rest = cmd.partition(" ")
    exe = exe.rsplit("\\", 1)[-1]
    return _EXE_SUFFIX_RE.sub("", f"{exe} {rest.strip()}".strip())


# Thư mục mọi người dùng đều ghi được: file thực thi chạy từ đây là dấu hiệu quen thuộc của mã độc
_WRITABLE_DIRS = ("\\users\\public\\", "\\windows\\temp\\", "\\appdata\\local\\temp\\", "c:\\temp\\", "\\downloads\\")
# Dịch vụ bảo mật / ghi log: tắt chúng là Impair Defenses
_SECURITY_SERVICES = ("windefend", "sense", "wdnissvc", "mpssvc", "wscsvc", "eventlog", "sysmon")

# Host nội bộ: IP private, localhost, tên miền .local/.lan/.corp/.internal
_URL_HOST_RE = re.compile(r"(?:https?|ftp)://([^/\s'\"\\:]+)", re.IGNORECASE)
_INTERNAL_HOST_RE = re.compile(
    r"^(?:localhost|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+"
    r"|[^/]*\.(?:local|lan|corp|internal|intranet)|[^/]*\.corp\.[a-z.]+)$"
)


def _url_hosts(text: str) -> list[str]:
    return [h.lower().rstrip(".") for h in _URL_HOST_RE.findall(text)]


def _has_external_url(text: str) -> bool:
    """True khi có ít nhất một URL trỏ ra ngoài mạng nội bộ."""
    return any(not _INTERNAL_HOST_RE.match(h) for h in _url_hosts(text))


def correlate_security_events(events: list[dict]) -> dict:
    """
    Bộ luật tương quan (Security Correlation Engine) theo MITRE ATT&CK.
    - strong_stages: tín hiệu chắc chắn -> hệ thống luôn ALERT (lưới an toàn).
    - các stage còn lại là tín hiệu YẾU: AI quyết định, luật chỉ gợi ý.
    - risk_score: điểm rủi ro tham khảo (cộng trọng số STAGE_RISK_WEIGHTS, chặn 100).
    Gộp 14/11/2026: brute force theo cửa sổ thời gian + đăng nhập sau brute force theo danh tính,
    17 nhóm chữ ký MITRE chi tiết (thay cho 1 stage "Malware Execution" cũ), nhóm universal 4756.
    """
    findings = {
        "stages": [],
        "strong_stages": [],
        "evidence_refs": [],
        "details": [],
        "risk_score": 0,
        "risk_factors": [],
    }

    def add(stage: str, evs: list[dict], detail: str, strong: bool) -> None:
        refs = list(dict.fromkeys(e["event_ref"] for e in evs))
        if stage not in findings["stages"]:
            findings["stages"].append(stage)
        if strong and stage not in findings["strong_stages"]:
            findings["strong_stages"].append(stage)
        findings["evidence_refs"].extend(refs)
        findings["details"].append(f"{detail} Bằng chứng: {', '.join(refs)}.")

    # 1. Dò mật khẩu (MITRE T1110): >= ngưỡng lần 4625 cùng tài khoản hoặc cùng IP trong cửa sổ thời gian
    failed_logons = [e for e in events if e.get("event_id") == 4625]
    grouped_failures: dict[tuple[str, str], list[dict]] = {}
    for event in failed_logons:
        data = event["data"]
        user = _clean_identity(data.get("TargetUserName"))
        source_ip = _clean_identity(data.get("IpAddress"))
        logon_type = data.get("LogonType", "")
        if user:
            grouped_failures.setdefault(("user", f"{user}|{logon_type}"), []).append(event)
        if source_ip:
            # nhóm theo IP bắt được cả password spraying nhiều tài khoản từ một nguồn
            grouped_failures.setdefault(("ip", f"{source_ip}|{logon_type}"), []).append(event)

    brute_clusters = _qualifying_clusters(grouped_failures)
    brute_events = sorted(
        {e["event_ref"]: e for c in brute_clusters for e in c["events"]}.values(), key=_event_time
    )
    if brute_events:
        target_users = list(dict.fromkeys(
            e["data"].get("TargetUserName") for e in brute_events if e["data"].get("TargetUserName")
        ))
        add("Password Brute Force (MITRE T1110)", brute_events,
            f"Phát hiện {len(brute_events)} lần đăng nhập thất bại có tương quan trong "
            f"{CORRELATION_WINDOW_SECONDS // 60} phút (Event 4625) nhằm vào tài khoản "
            f"'{', '.join(target_users) if target_users else 'unknown user'}'.", strong=True)
    elif len(failed_logons) >= 3:
        # Nhiều lần sai nhưng không dồn dập cùng tài khoản/IP trong cửa sổ -> tín hiệu yếu, để AI xét
        add("Multiple Failed Logons (MITRE T1110)", failed_logons,
            f"Có {len(failed_logons)} lần đăng nhập thất bại (Event 4625) nhưng không dồn dập cho cùng "
            f"tài khoản/IP trong {CORRELATION_WINDOW_SECONDS // 60} phút - cần xét ngữ cảnh.", strong=False)

    # 1b. Password Spraying (MITRE T1110.003): sai mật khẩu trên >= 3 tài khoản khác nhau
    sprayed_users = list(dict.fromkeys(
        (e["data"].get("TargetUserName") or "").lower() for e in failed_logons
        if (e["data"].get("TargetUserName") or "") not in ("", "-")
    ))
    if len(sprayed_users) >= 3:
        add("Password Spraying (MITRE T1110.003)", failed_logons,
            f"Phát hiện đăng nhập thất bại (Event 4625) trên {len(sprayed_users)} tài khoản khác nhau "
            f"({', '.join(sprayed_users[:8])}) -> dấu hiệu Password Spraying.", strong=True)

    # 2. Đăng nhập thành công ngay sau chuỗi brute force, khớp đúng tài khoản/IP và kiểu đăng nhập (MITRE T1078)
    if brute_clusters:
        success_logons = []
        for success in (e for e in events if e.get("event_id") == 4624):
            s_user = _clean_identity(success["data"].get("TargetUserName"))
            s_ip = _clean_identity(success["data"].get("IpAddress"))
            s_type = success["data"].get("LogonType", "")
            for cluster in brute_clusters:
                delay = (_event_time(success) - _event_time(cluster["events"][-1])).total_seconds()
                c_value, c_type = cluster["value"].rsplit("|", 1)
                same_identity = (cluster["kind"] == "user" and s_user == c_value) or (
                    cluster["kind"] == "ip" and s_ip == c_value)
                if same_identity and s_type == c_type and 0 <= delay <= POST_BRUTE_SUCCESS_WINDOW_SECONDS:
                    success_logons.append(success)
                    break
        if success_logons:
            add("Successful Logon Post-Brute Force (MITRE T1078)", success_logons,
                "Phát hiện đăng nhập thành công (Event 4624) ngay sau chuỗi đăng nhập thất bại.", strong=True)

    # 3. Tạo backdoor / leo thang (MITRE T1136 / T1098) qua dòng lệnh
    account_cmds = [
        e for e in events
        if e.get("event_id") == 4688
        and "/add" in _norm_cmd(e["data"].get("CommandLine"))
        and any(k in _norm_cmd(e["data"].get("CommandLine"))
                for k in ("net user", "net1 user", "net localgroup", "net1 localgroup"))
    ]
    if account_cmds:
        def _privileged(e: dict) -> bool:
            cmd = _norm_cmd(e["data"].get("CommandLine"))
            # thêm vào nhóm Administrators, hoặc tạo tài khoản qua thực thi từ xa (wmic process call create)
            return any(g in cmd for g in ADMIN_GROUP_WORDS) or ("wmic" in cmd and "process call create" in cmd)
        privileged = [e for e in account_cmds if _privileged(e)]
        if privileged:
            add("Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098)", account_cmds,
                "Phát hiện lệnh tạo tài khoản và/hoặc gán quyền quản trị cục bộ "
                "(net localgroup Administrators /add, hoặc net user /add qua wmic).", strong=True)
        else:
            # IT tạo tài khoản nhân viên trực tiếp là bình thường -> để AI xét ngữ cảnh
            add("Account Creation Command (MITRE T1136)", account_cmds,
                "Có lệnh tạo tài khoản (net user /add) không kèm nhóm đặc quyền - cần xét ngữ cảnh.", strong=False)

    # 4. Chữ ký kỹ thuật tấn công theo MITRE (đều là tín hiệu MẠNH)
    threat_events: dict[str, list[dict]] = {s: [] for s in (
        "PowerShell / Command and Scripting Interpreter (MITRE T1059.001)",
        "OS Credential Dumping (MITRE T1003)",
        "Impair Defenses (MITRE T1562.001)",
        "Persistence (MITRE T1547.001 / T1053.005)",
        "Inhibit System Recovery (MITRE T1490)",
        "Accessibility Features / Sticky Keys Backdoor (MITRE T1546.008)",
        "In-Memory Assembly Execution (MITRE T1055)",
        "Credential Access / Kerberoasting (MITRE T1558.003)",
        "LOLBAS / Script Proxy Execution (MITRE T1218)",
        "Deobfuscate/Decode Files (MITRE T1140)",
        "Lateral Movement / Remote Execution (MITRE T1569 / T1047 / T1021)",
        "Network Discovery / Port Scanning (MITRE T1046)",
        "Ingress Tool Transfer (MITRE T1105 / T1197)",
        "Data Collection & Exfiltration (MITRE T1560 / T1048)",
        "Impact / Data Destruction & Ransomware (MITRE T1485 / T1486)",
        "UAC Bypass (MITRE T1548.002)",
        "Offensive Tooling: Discovery & Privilege Escalation Audit (MITRE T1087 / T1069 / T1482)",
        "Exploitation for Privilege Escalation (MITRE T1068)",
        "Indicator Removal / Hide Artifacts (MITRE T1070 / T1564.001)",
        "File Permission Tampering (MITRE T1222.001)",
        "Hijack Execution Flow (MITRE T1546 / T1574)",
        "Reverse Shell / Protocol Tunneling (MITRE T1095 / T1572)",
    )}
    log_clear_cmds = []
    for e in events:
        raw_cmd = (e["data"].get("CommandLine") or "").lower()
        # Bỏ đường dẫn + đuôi .exe để khớp cả "C:\...\wevtutil.exe cl" lẫn "wevtutil cl" như log thật
        cmd = _norm_cmd(raw_cmd)
        script = (e["data"].get("ScriptBlockText") or "").lower()
        task = (e["data"].get("TaskContent") or "").lower()
        combined = " ".join((cmd, script, task))

        encoded_powershell = (
            any(flag in cmd for flag in ("-encodedcommand", " -enc "))
            and any(flag in cmd for flag in ("powershell", "-w hidden", "-windowstyle hidden", "-nop", "-noni", "bypass"))
        )
        # Tải từ URL ngoài mạng nội bộ (tải file cấu hình từ intranet *.local / 192.168.x là bình thường)
        download_cradle = _has_external_url(combined) and any(token in combined for token in (
            "downloadstring", "downloadfile", "net.webclient", "invoke-webrequest", "start-bitstransfer",
            "bitsadmin", "certutil", "mshta", "regsvr32",
        ))
        # DownloadString/DownloadFile mà không thấy URL nào (URL bị ghép chuỗi / biến) vẫn đáng ngờ
        hidden_cradle = not _url_hosts(combined) and any(t in script for t in ("downloadstring", "downloadfile"))
        remote_iex = "iex" in script and "http" in script and _has_external_url(script)
        credential_dump = (
            any(token in combined for token in ("mimikatz", "sekurlsa", "lsadump", "dcsync", "vaultcmd"))
            or ("procdump" in combined and "lsass" in combined)
            or ("comsvcs.dll" in combined and "minidump" in combined)
            or any(tool in combined for tool in ("lazagne", "pwdump", "secretsdump"))
            or ("reg" in cmd and " save " in f" {cmd} " and any(h in cmd for h in ("\\sam", "\\system", "\\security")))
        )
        impair_defenses = (
            ("set-mppreference" in combined and "disable" in combined)
            or "amsiinitfailed" in combined
            or ("net" in cmd and "stop" in cmd and any(s in cmd for s in ("eventlog", "windefend")))
            or ("sc" in cmd and "eventlog" in cmd and "disabled" in cmd)
            or ("schtasks" in cmd and "windows defender" in cmd and "disable" in cmd)
            or (cmd.startswith("netsh") and "firewall" in cmd
                and any(t in cmd for t in ("state off", "opmode mode=disable", "opmode disable")))
            or (cmd.startswith("fltmc") and " unload " in f" {cmd} ")
            or (cmd.startswith("sc ") and " config " in cmd and "disabled" in cmd
                and any(f" {svc} " in f" {cmd} " for svc in _SECURITY_SERVICES))
        )
        if "wevtutil cl" in combined or "clear-eventlog" in combined:
            log_clear_cmds.append(e)
        persistence = (
            ("currentversion\\run" in combined and any(t in combined for t in ("set-itemproperty", "new-itemproperty", "reg add")))
            or ("schtasks" in combined and "/create" in combined and any(t in combined for t in ("powershell", "http", "-enc", "hidden")))
            or "commandlineeventconsumer" in combined or "__eventfilter" in combined
            or ("version.dll" in combined and "copy" in combined)
            # task chạy file trong thư mục ai cũng ghi được, hoặc netcat (reverse shell định kỳ)
            or (cmd.startswith("schtasks") and "/create" in cmd
                and (any(d in raw_cmd for d in _WRITABLE_DIRS) or any(t in raw_cmd for t in ("nc.exe", "ncat", "netcat"))))
        )
        shadow_delete = (
            ("vssadmin" in combined and "delete" in combined)
            or ("shadowcopy" in combined and "delete" in combined)
            or ("wbadmin" in combined and "delete" in combined)
            or (cmd.startswith("bcdedit") and any(t in cmd for t in ("recoveryenabled no", "ignoreallfailures")))
        )
        sticky_keys = "image file execution options" in combined and any(t in combined for t in ("sethc", "utilman", "debugger"))
        in_memory = any(t in combined for t in ("[system.reflection.assembly]::load", "loadassembly", "virtualalloc"))
        kerberoast = (
            any(t in combined for t in ("invoke-kerberoast", "rubeus", "kerberosrequestorsecuritytoken", "get-domainspnticket"))
            or ("get-domainuser" in combined and "-spn" in combined)
        )
        lolbas_exec = (
            ("rundll32" in cmd and "advpack.dll" in cmd)
            or ("regsvr32" in cmd and "scrobj.dll" in cmd)
            or ("mshta" in cmd and "vbscript" in cmd)
            or (cmd.startswith("rundll32") and any(d in raw_cmd for d in _WRITABLE_DIRS))
        )
        certutil_decode = "certutil" in cmd and "-decode" in cmd
        lateral_remote = (
            "psexec" in cmd
            or ("wmic" in cmd and "process call create" in cmd and "node" in cmd)
            or ("net" in cmd and " use " in f" {cmd} " and any(s in cmd for s in ("c$", "admin$")))
        )
        port_scan = ("tcpclient" in script and "connect" in script and "1..254" in script) or "invoke-portscan" in combined
        ingress_transfer = (
            ("bitsadmin" in cmd and "/transfer" in cmd and _has_external_url(cmd))
            or ("curl" in cmd and _has_external_url(raw_cmd)
                and any(p in raw_cmd for p in (".exe", ".dll", "c:\\users\\public", "c:\\temp")))
        )
        data_exfil = (
            ("tar" in cmd and any(ext in cmd for ext in (".docx", ".xlsx", ".pdf", "confidential")))
            or ("resolve-dnsname" in script and "type txt" in script and any(k in script for k in ("base64", "tobase64string")))
        )
        impact_ransomware = (
            ("cipher" in cmd and "/w:" in cmd)
            or ("rename-item" in script and any(ext in script for ext in (".locked", ".crypted", ".crypto")))
        )
        uac_bypass = (
            "fodhelper" in cmd or "ms-settings\\shell\\open\\command" in cmd or "cmstp" in cmd  # cmd đã bỏ đuôi .exe
            or "mscfile\\shell\\open\\command" in combined  # eventvwr.msc hijack
        )
        offensive_tooling = any(t in combined for t in (
            "sharphound", "bloodhound", "powerview", "get-netdomaintrust", "get-domaintrust", "get-netforest",
            "seatbelt", "winpeas", "sharpup", "powerup.ps1", "invoke-allchecks", "privesccheck",
        ))
        privesc_exploit = any(t in combined for t in (
            "invoke-nightmare", "printnightmare", "cve-2021-1675", "cve-2021-34527",
            "juicypotato", "printspoofer", "godpotato", "sweetpotato",
        ))
        hide_artifacts = (
            (cmd.startswith("fsutil") and "usn" in cmd and "deletejournal" in cmd)
            or (cmd.startswith("attrib ") and "+h" in cmd
                and any(ext in raw_cmd for ext in (".exe", ".dll", ".ps1", ".bat", ".vbs")))
        )
        perm_tamper = (
            (cmd.startswith("icacls ") and "/deny" in cmd
             and any(p in cmd for p in ("system", "administrators", "everyone", "*s-1-5-18", "*s-1-5-32-544")))
            or (cmd.startswith("takeown ") and "\\windows\\system32\\" in cmd)
        )
        registry_write = cmd.startswith("reg add") or any(t in script for t in ("set-itemproperty", "new-itemproperty", "new-item "))
        hijack = (
            (registry_write and any(k in combined for k in ("appcertdlls", "appinit_dlls")))
            or (registry_write and "hkcu" in combined and "\\classes\\clsid\\" in combined and "inprocserver32" in combined)
            or cmd.startswith("sdbinst")
        )
        reverse_shell = (
            ("net.sockets.tcpclient" in combined and "getstream" in combined
             and any(t in combined for t in ("iex", "invoke-expression", "out-string")))
            or (cmd.startswith(("plink", "ssh ")) and " -r " in f" {cmd} ")
            or cmd.startswith("chisel") or any(f"\\{t}" in raw_cmd for t in ("chisel.exe", "ngrok.exe"))
        )

        checks = (
            ("PowerShell / Command and Scripting Interpreter (MITRE T1059.001)",
             encoded_powershell or download_cradle or hidden_cradle or remote_iex),
            ("OS Credential Dumping (MITRE T1003)", credential_dump),
            ("Impair Defenses (MITRE T1562.001)", impair_defenses),
            ("Persistence (MITRE T1547.001 / T1053.005)", persistence),
            ("Inhibit System Recovery (MITRE T1490)", shadow_delete),
            ("Accessibility Features / Sticky Keys Backdoor (MITRE T1546.008)", sticky_keys),
            ("In-Memory Assembly Execution (MITRE T1055)", in_memory),
            ("Credential Access / Kerberoasting (MITRE T1558.003)", kerberoast),
            ("LOLBAS / Script Proxy Execution (MITRE T1218)", lolbas_exec),
            ("Deobfuscate/Decode Files (MITRE T1140)", certutil_decode),
            ("Lateral Movement / Remote Execution (MITRE T1569 / T1047 / T1021)", lateral_remote),
            ("Network Discovery / Port Scanning (MITRE T1046)", port_scan),
            ("Ingress Tool Transfer (MITRE T1105 / T1197)", ingress_transfer),
            ("Data Collection & Exfiltration (MITRE T1560 / T1048)", data_exfil),
            ("Impact / Data Destruction & Ransomware (MITRE T1485 / T1486)", impact_ransomware),
            ("UAC Bypass (MITRE T1548.002)", uac_bypass),
            ("Offensive Tooling: Discovery & Privilege Escalation Audit (MITRE T1087 / T1069 / T1482)", offensive_tooling),
            ("Exploitation for Privilege Escalation (MITRE T1068)", privesc_exploit),
            ("Indicator Removal / Hide Artifacts (MITRE T1070 / T1564.001)", hide_artifacts),
            ("File Permission Tampering (MITRE T1222.001)", perm_tamper),
            ("Hijack Execution Flow (MITRE T1546 / T1574)", hijack),
            ("Reverse Shell / Protocol Tunneling (MITRE T1095 / T1572)", reverse_shell),
        )
        for stage, hit in checks:
            if hit:
                threat_events[stage].append(e)

    malware_events = []
    for stage, stage_events in threat_events.items():
        if stage_events:
            malware_events.extend(stage_events)
            add(stage, stage_events, f"Phát hiện {stage} từ chữ ký có độ tin cậy cao.", strong=True)

    # 5. Trinh sát (MITRE T1033) - tín hiệu YẾU: whoami/net user đơn lẻ là lệnh quản trị bình thường.
    #    Chỉ ghi nhận khi đi kèm chuỗi tấn công khác hoặc >= 3 lệnh trinh sát trong cùng lô.
    recon_events = [
        e for e in events
        if e.get("event_id") == 4688 and any(
            k in _norm_cmd(e["data"].get("CommandLine")) or k in (e["data"].get("NewProcessName") or "").lower()
            for k in ("whoami", "nltest", "net group", "net user", "systeminfo")
        )
    ]
    if recon_events and (brute_events or account_cmds or malware_events or len(recon_events) >= 3):
        add("System Reconnaissance (MITRE T1033)", recon_events,
            "Phát hiện chuỗi lệnh khám phá và trinh sát hệ thống (whoami, net user/group, nltest, systeminfo).",
            strong=False)

    # 6. Xoá nhật ký (MITRE T1070.001): 1102 (Security) / 104 (System) hoặc lệnh wevtutil cl / Clear-EventLog
    cleared = [e for e in events if e.get("event_id") in (1102, 104)] + log_clear_cmds
    if cleared:
        logs = sorted({
            e["data"].get("Channel") or {1102: "Security", 104: "System"}.get(e["event_id"], "lệnh wevtutil/Clear-EventLog")
            for e in cleared
        })
        add("Indicator Removal: Clear Windows Event Logs (MITRE T1070.001)", cleared,
            f"Phát hiện nhật ký Windows bị xoá ({', '.join(logs)}) - Event 1102/104 hoặc lệnh xoá log.", strong=True)

    # 7. Cài service mới (MITRE T1543.003 / T1569.002): 7045; chắc chắn khi service chạy shell/script/file từ thư mục ghi được
    services = [e for e in events if e.get("event_id") == 7045]
    if services:
        def suspicious_service(e: dict) -> bool:
            p = (e["data"].get("ImagePath") or "").lower()
            return any(k in p for k in SUSPICIOUS_SERVICE_PATH) or bool(RANDOM_WINDOWS_EXE.search(p))
        bad = [e for e in services if suspicious_service(e)]
        if bad:
            add("Create or Modify System Process: Malicious Service (MITRE T1543.003 / T1569.002)", bad,
                "Phát hiện service mới chạy lệnh shell/PowerShell hoặc file thực thi đáng ngờ (Event 7045, kiểu PsExec/Metasploit).",
                strong=True)
        others = [e for e in services if e not in bad]
        if others:
            add("New Service Installed (MITRE T1543.003)", others,
                "Có service mới được cài (Event 7045) - cần xét ngữ cảnh (có thể là phần mềm/driver hợp lệ).", strong=False)

    # 8. Tạo tài khoản (MITRE T1136.001): 4720 -> tín hiệu yếu
    created = [e for e in events if e.get("event_id") == 4720]
    if created:
        users = ", ".join(dict.fromkeys(e["data"].get("TargetUserName", "?") for e in created))
        add("Create Account: Local Account (MITRE T1136.001)", created,
            f"Tài khoản mới được tạo (Event 4720): {users}.", strong=False)

    # 9. Thêm vào nhóm đặc quyền (MITRE T1098): 4728/4732/4756 với Administrators / Domain Admins...
    group_adds = [e for e in events if e.get("event_id") in (4728, 4732, 4756)]
    priv_adds = [
        e for e in group_adds
        if (e["data"].get("TargetSid") or "").upper() in PRIVILEGED_GROUP_SIDS
        or (e["data"].get("TargetUserName") or "").lower() in PRIVILEGED_GROUP_NAMES
        or (e["data"].get("GroupName") or "").lower() in PRIVILEGED_GROUP_NAMES
    ]
    if priv_adds:
        groups = ", ".join(dict.fromkeys(
            e["data"].get("TargetUserName") or e["data"].get("GroupName") or "?" for e in priv_adds))
        add("Account Manipulation: Add to Privileged Group (MITRE T1098)", priv_adds,
            f"Tài khoản được thêm vào nhóm đặc quyền {groups} (Event 4728/4732/4756).", strong=True)

    # 10. Scheduled task (MITRE T1053.005): 4698; chắc chắn khi task chạy script mã hoá / tải từ mạng / file trong thư mục ghi được
    tasks = [e for e in events if e.get("event_id") == 4698]
    if tasks:
        bad_tasks = [e for e in tasks
                     if any(k in (e["data"].get("TaskContent") or "").lower() for k in SUSPICIOUS_TASK_CONTENT)]
        if bad_tasks:
            add("Scheduled Task Persistence (MITRE T1053.005)", bad_tasks,
                "Scheduled task mới chạy PowerShell mã hoá / tải từ mạng / file trong thư mục tạm (Event 4698).", strong=True)
        normal_tasks = [e for e in tasks if e not in bad_tasks]
        if normal_tasks:
            add("New Scheduled Task (MITRE T1053.005)", normal_tasks,
                "Có scheduled task mới (Event 4698) - cần xét ngữ cảnh.", strong=False)

    findings["evidence_refs"] = list(dict.fromkeys(findings["evidence_refs"]))
    findings["risk_factors"] = [
        {"stage": s, "score": STAGE_RISK_WEIGHTS.get(s, 50), "strong": s in findings["strong_stages"]}
        for s in findings["stages"]
    ]
    findings["risk_score"] = min(100, sum(f["score"] for f in findings["risk_factors"]))
    return findings


SUSPICIOUS_SERVICE_PATH = (
    "cmd.exe /c", "cmd /c", "%comspec%", "powershell", "pwsh", "-enc", "frombase64", "rundll32",
    "\\admin$", "\\\\127.0.0.1", "\\temp\\", "\\appdata\\", "\\users\\public\\", "\\programdata\\",
)
# File .exe tên ngẫu nhiên đặt thẳng trong C:\Windows (kiểu PsExec của Metasploit)
RANDOM_WINDOWS_EXE = re.compile(r"(?:\\windows|%systemroot%|%windir%)\\[a-z0-9]{6,12}\.exe\b")
PRIVILEGED_GROUP_SIDS = {"S-1-5-32-544", "S-1-5-32-555", "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-551"}
PRIVILEGED_GROUP_NAMES = {
    "administrators", "domain admins", "enterprise admins", "schema admins",
    "remote desktop users", "account operators", "backup operators", "server operators",
}
SUSPICIOUS_TASK_CONTENT = ("-enc", "frombase64", "downloadstring", "http://", "https://", "\\temp\\",
                           "\\appdata\\", "\\users\\public\\", "iex", "bypass")


def split_event_batches(
    events: list[dict],
    max_chars: int = MAX_BATCH_CHARS,
) -> list[list[dict]]:
    """Chia sự kiện thành các lô mà không làm mất sự kiện."""
    if max_chars <= 0:
        raise ValueError("max_chars must be greater than zero")

    batches = []
    current_batch = []
    current_size = 2  # ký tự cho dấu ngoặc JSON []

    for event in events:
        event_size = len(json.dumps(event, ensure_ascii=False)) + 1

        if event_size > max_chars:
            if current_batch:
                batches.append(current_batch)
                current_batch = []
                current_size = 2
            batches.append([event])
            continue

        if current_batch and current_size + event_size > max_chars:
            batches.append(current_batch)
            current_batch = []
            current_size = 2

        current_batch.append(event)
        current_size += event_size

    if current_batch:
        batches.append(current_batch)

    return batches


EVENT_MEANING = {
    4624: "Đăng nhập THÀNH CÔNG",
    4625: "Đăng nhập THẤT BẠI (sai mật khẩu)",
    4648: "Đăng nhập bằng thông tin xác thực tường minh (runas / explicit credentials)",
    4688: "Tạo tiến trình mới (xem NewProcessName, CommandLine)",
    4104: "PowerShell ScriptBlock (xem ScriptBlockText)",
    1102: "Nhật ký Security BỊ XOÁ",
    104: "Nhật ký System/ứng dụng BỊ XOÁ (xem Channel)",
    7045: "Service mới được cài (xem ServiceName, ImagePath)",
    4720: "Tài khoản người dùng mới được tạo (TargetUserName)",
    4722: "Tài khoản người dùng được BẬT (enable) (TargetUserName)",
    4728: "Thành viên được thêm vào nhóm bảo mật global (TargetUserName = tên nhóm, MemberName/MemberSid = người được thêm)",
    4732: "Thành viên được thêm vào nhóm bảo mật local (TargetUserName = tên nhóm, MemberSid = người được thêm)",
    4756: "Thành viên được thêm vào nhóm bảo mật universal (TargetUserName = tên nhóm, MemberName = người được thêm)",
    4698: "Scheduled task mới được tạo (TaskName, TaskContent)",
    # Nhóm ID mới (thí nghiệm toàn bộ log, 25/11/2026)
    4798: "Danh sách nhóm của một TÀI KHOẢN bị liệt kê (TargetUserName = tài khoản, CallerProcessName = tiến trình gọi)",
    4799: "Thành viên của một NHÓM bị liệt kê (TargetUserName = nhóm, CallerProcessName = tiến trình gọi)",
    4672: "Đặc quyền đặc biệt được gán khi đăng nhập (SubjectUserName, PrivilegeList)",
    5382: "Thông tin đăng nhập trong Windows Vault bị đọc (SchemaFriendlyName, Resource, Identity)",
    4797: "Có truy vấn kiểm tra tài khoản có mật khẩu trống hay không (TargetUserName, Workstation)",
    4738: "Tài khoản người dùng bị sửa thuộc tính (TargetUserName, UserAccountControl, SidHistory, AllowedToDelegateTo)",
    4647: "Người dùng chủ động đăng xuất",
    4616: "Giờ hệ thống bị thay đổi (PreviousTime, NewTime, ProcessName)",
    1100: "Dịch vụ ghi nhật ký sự kiện bị tắt",
    4719: "Chính sách audit của hệ thống bị thay đổi (SubcategoryGuid, AuditPolicyChanges)",
    4103: "PowerShell module logging: lệnh đã chạy (Payload, ContextInfo)",
    400: "PowerShell engine khởi động (HostApplication = dòng lệnh mở PowerShell)",
    800: "PowerShell pipeline chạy lệnh (HostApplication, CommandLine)",
}


BASE_EVENT_IDS = (4624, 4625, 4648, 4688, 4104)

# Mô tả dấu hiệu tấn công / hoạt động bình thường cho các loại sự kiện mở rộng.
# Chỉ đưa vào prompt khi lô có loại sự kiện tương ứng (prompt động) - mô hình 3B rất nhạy với độ dài prompt.
EXTENDED_SIGNS = [
    ({1102, 104}, "Xoá dấu vết: sự kiện 1102 hoặc 104 (nhật ký bị xoá).", None),
    ({7045},
     "Service đáng ngờ (7045): ImagePath chạy cmd /c, powershell, %COMSPEC%, rundll32, file trong Temp/AppData/ADMIN$, "
     "hoặc file .exe tên ngẫu nhiên đặt thẳng trong C:\\Windows (dấu hiệu PsExec/Metasploit).",
     "Service/driver của phần mềm hợp lệ cài vào Program Files hoặc System32 (vd Windows Update, driver, phần mềm diệt virus)."),
    ({4720, 4722, 4728, 4732, 4756},
     "Tạo/bật tài khoản (4720/4722) rồi thêm vào nhóm đặc quyền như Administrators (4732/4728/4756).",
     "Tạo tài khoản / thêm vào nhóm thường (Users) khi cài đặt hoặc do bộ phận IT thực hiện, không kèm nhóm đặc quyền."),
    ({4698},
     "Scheduled task (4698) chạy PowerShell mã hoá, tải từ mạng hoặc file trong thư mục tạm.",
     "Scheduled task của Microsoft/phần mềm cập nhật (\\Microsoft\\Windows\\..., GoogleUpdate, OneDrive...)."),
    # Nhóm ID mới (thí nghiệm toàn bộ log). Viết theo tài liệu Microsoft "Audit ..." + MITRE ATT&CK, không theo log cụ thể.
    # Phần "bình thường" (cột 3) là hướng dẫn nhận biết nhiễu; NOISE_GUIDANCE=0 bỏ phần này (lượt đối chứng).
    ({4798, 4799},
     "Trinh sát tài khoản / nhóm (MITRE T1087 / T1069): 4798/4799 do net.exe, net1.exe, whoami, PowerShell, cmd, wmic "
     "hoặc file lạ nằm ngoài thư mục hệ thống gọi, ĐI CÙNG dấu hiệu khác (lệnh trinh sát, tạo tài khoản, đăng nhập lạ). "
     "4798/4799 chỉ là ĐỌC danh sách: không tạo tài khoản, không đổi quyền -> không bao giờ là Backdoor / Privilege Escalation.",
     "Tiến trình dịch vụ của Windows, phần mềm cài trong Program Files (kể cả ứng dụng Store trong C:\\Program Files\\WindowsApps) "
     "hoặc trình cập nhật phần mềm liệt kê nhóm / toàn bộ tài khoản cục bộ (Administrator, Guest, DefaultAccount...) khi khởi động, "
     "đăng nhập, sao lưu. Chỉ có 4798/4799 mà không kèm lệnh trinh sát, tạo tài khoản hay đăng nhập lạ -> NORMAL."),
    ({4672},
     "Đặc quyền nguy hiểm (SeDebugPrivilege, SeTcbPrivilege, SeImpersonatePrivilege) gán cho tài khoản người dùng "
     "ngay sau một đăng nhập mạng lạ hoặc sau dò mật khẩu.",
     "Tài khoản quản trị hoặc tài khoản dịch vụ đăng nhập bình thường thì luôn sinh 4672; đứng một mình không phải tấn công. "
     "Đăng nhập dịch vụ (LogonType 5, services.exe) và tài khoản DWM-* / UMFD-* luôn kèm SeImpersonatePrivilege / "
     "SeAssignPrimaryTokenPrivilege."),
    ({5382},
     "Đánh cắp thông tin đăng nhập (MITRE T1555): đọc Windows Vault hàng loạt trong thời gian ngắn, đi cùng tiến trình hoặc lệnh đáng ngờ.",
     "Trình duyệt hoặc ứng dụng đọc mật khẩu đã lưu của chính người dùng khi người dùng đang làm việc; tài khoản máy "
     "(tên kết thúc bằng $) đọc vault Windows Hello (\"NGC ... Vault Resource Schema\") khi đăng nhập / mở khoá màn hình."),
    ({4797},
     "Dò tài khoản không có mật khẩu: nhiều truy vấn 4797 tới các tài khoản khác nhau, nhất là từ máy khác (Workstation lạ).",
     "Windows tự kiểm tra tài khoản cục bộ khi đăng nhập, mở màn hình tài khoản hoặc chia sẻ thư mục."),
    ({4738},
     "Sửa tài khoản để duy trì truy cập (MITRE T1098): bỏ yêu cầu mật khẩu, đặt mật khẩu không hết hạn, thêm SidHistory "
     "hoặc AllowedToDelegateTo, nhất là với tài khoản quản trị.",
     "Hệ thống cập nhật thuộc tính sau khi người dùng đổi mật khẩu hoặc khi IT chỉnh thông tin tài khoản, không đổi quyền."),
    ({4647},
     "Tự nó không phải dấu hiệu tấn công; chỉ dùng làm mốc thời gian phiên làm việc.",
     "Người dùng đăng xuất khỏi máy."),
    ({4616},
     "Che giấu dấu vết (MITRE T1070.006): đổi giờ hệ thống thủ công bằng lệnh / công cụ, đi cùng xoá log hoặc tấn công khác.",
     "Dịch vụ thời gian của Windows tự đồng bộ giờ (chênh lệch nhỏ), đổi múi giờ, khởi động máy."),
    ({1100, 4719},
     "Vô hiệu hoá ghi log (MITRE T1562.002): dịch vụ log tắt hoặc chính sách audit bị đổi / tắt khi máy vẫn đang chạy, "
     "đi cùng hoạt động đáng ngờ khác.",
     "1100 xuất hiện ngay trước khi tắt hoặc khởi động lại máy; chính sách audit đổi khi cài bản cập nhật Windows."),
    ({400, 800, 4103},
     "PowerShell độc hại (MITRE T1059.001): dòng lệnh (HostApplication / Payload) có -enc / -EncodedCommand, FromBase64String, "
     "DownloadString / Invoke-WebRequest / IEX tới URL ngoài, tắt Defender, gọi công cụ đánh cắp mật khẩu "
     "(-w hidden / -ExecutionPolicy Bypass chỉ đáng ngờ khi đi cùng các dấu hiệu này).",
     "PowerShell được mở từ công cụ lập trình, trình quản lý hệ thống hoặc script quản trị để chạy lệnh thông thường "
     "(cài đặt gói, build, kiểm tra cấu hình). -NoProfile, -NonInteractive, -ExecutionPolicy Bypass / Unrestricted, "
     "-WindowStyle Hidden do công cụ tự động gọi; không kèm mã hoá base64, tải từ mạng hay tắt bảo vệ -> NORMAL, không phải UNKNOWN."),
]


def noise_guidance_enabled() -> bool:
    """NOISE_GUIDANCE=0 -> bỏ phần 'hoạt động bình thường' của nhóm ID mới (lượt đối chứng)."""
    return os.getenv("NOISE_GUIDANCE", "1") != "0"


def build_system_prompt(schema: dict, correlation_hints: str = "", event_ids: set[int] | None = None) -> str:
    """
    Prompt TRUNG LẬP và ĐỘNG.
    - Không nói trước có hay không có tấn công; tín hiệu luật (nếu có) chỉ là gợi ý cần xác minh.
    - event_ids: các mã sự kiện có trong lô. Phần mô tả cho loại sự kiện mở rộng chỉ được thêm khi lô có loại đó;
      lô chỉ có sự kiện cơ bản nhận prompt y hệt phiên bản trước khi mở rộng thu thập.
      event_ids=None -> đưa đầy đủ mọi phần.
    """
    present = set(SUPPORTED_EVENT_IDS) if event_ids is None else set(event_ids)
    if correlation_hints:
        hints_text = (
            "\nTÍN HIỆU TỪ BỘ LUẬT (chỉ là gợi ý, BẮT BUỘC tự xác minh lại với dữ liệu; có thể là báo động giả):\n"
            f"{correlation_hints}\n"
        )
    else:
        hints_text = ""

    legend_ids = list(BASE_EVENT_IDS) + [eid for eid in EVENT_MEANING if eid not in BASE_EVENT_IDS and eid in present]
    legend = "\n".join(f"- {eid}: {EVENT_MEANING[eid]}" for eid in legend_ids)

    guidance = noise_guidance_enabled()
    ext = [(sign, normal if guidance or not ids <= NEW_EVENT_IDS else None)
           for ids, sign, normal in EXTENDED_SIGNS if ids & present]
    ext_signs = "".join(f"{i}. {sign}\n" for i, (sign, _) in enumerate(ext, start=6))
    ext_normals = "".join(f"- {normal}\n" for _, normal in ext if normal)
    last_item = 5 + len(ext) if ext else 4

    return (
        "Bạn là Chuyên gia Điều tra & Phân tích Sự cố An toàn Thông tin (SOC Tier-3 / DFIR). "
        "Nhiệm vụ của bạn là tự đọc và phân tích khách quan danh sách Windows Event Logs được cung cấp.\n\n"
        "Ý NGHĨA MÃ SỰ KIỆN:\n"
        f"{legend}\n"
        "Đầu dữ liệu có mục THỐNG KÊ số lượng từng loại sự kiện. Mọi kết luận phải khớp với thống kê đó.\n\n"
        "DẤU HIỆU TẤN CÔNG (đặt ALERT):\n"
        "1. Dò mật khẩu (MITRE T1110): từ 3 sự kiện 4625 trở lên. Nếu THỐNG KÊ có 4625 < 3 thì KHÔNG được kết luận dò mật khẩu.\n"
        "2. Đăng nhập thành công (4624) ngay sau chuỗi >=3 lần 4625.\n"
        "3. Tạo tài khoản backdoor / leo thang: 'net user ... /add' qua wmic/psexec/từ xa, hoặc 'net localgroup Administrators ... /add'.\n"
        "4. Thực thi mã độc / C2: IEX, DownloadString, Invoke-WebRequest tới URL lạ, -EncodedCommand/-enc, FromBase64String, "
        "mimikatz, procdump/comsvcs nhắm vào lsass, sửa Registry Run, schtasks /create chạy file lạ, "
        "Set-MpPreference tắt Defender, wevtutil cl / xoá nhật ký, certutil/bitsadmin tải file.\n"
        "5. Trinh sát (MITRE T1033/T1087/T1482): chuỗi whoami, net user, net group, systeminfo, nltest đi cùng dấu hiệu khác.\n"
        f"{ext_signs}\n"
        "HOẠT ĐỘNG BÌNH THƯỜNG (đặt NORMAL nếu chỉ có những thứ này):\n"
        "- Đăng nhập thành công 4624 thông thường; gõ sai mật khẩu 1-2 lần rồi đăng nhập được.\n"
        "- Mở ứng dụng văn phòng/trình duyệt/công cụ (OUTLOOK, EXCEL, WINWORD, chrome, notepad, calc, explorer, VS Code, git, python...).\n"
        "- Lệnh quản trị/chẩn đoán đơn lẻ: ipconfig, ping, hostname, Get-Service, Get-Process, sao lưu, dọn đĩa.\n"
        "- Bộ phận IT tạo tài khoản nhân viên mới (net user ... /add) KHÔNG kèm thêm vào nhóm Administrators và không có dấu hiệu khác.\n"
        "- Nhiều tài khoản đăng nhập mạng (LogonType 3) từ IP nội bộ để truy cập thư mục chia sẻ.\n"
        f"{ext_normals}"
        f"{hints_text}\n"
        "QUY TẮC PHÁN QUYẾT:\n"
        "- TUYỆT ĐỐI TRUNG THỰC VỚI DỮ LIỆU: chỉ dựa vào trường có thật trong lô này. KHÔNG bịa ra sự kiện 4625, lệnh, URL hay công cụ không có trong log.\n"
        "- Sự kiện 4688 và 4624 KHÔNG phải là dò mật khẩu.\n"
        f"- CHỈ CẦN MỘT dấu hiệu tấn công (mục 1-{last_item}) là ĐỦ để đặt ALERT. KHÔNG cần có chuỗi nhiều giai đoạn; "
        "việc không có dò mật khẩu KHÔNG phải lý do để kết luận NORMAL.\n"
        "- Cách làm: duyệt từng sự kiện, so với các dấu hiệu tấn công trước, rồi mới so với hoạt động bình thường.\n"
        "- ALERT: evidence_refs phải là event_ref của chính các sự kiện độc hại đó.\n"
        "- NORMAL: khi chỉ có hoạt động bình thường; khi đó detected_stages=[] và evidence_refs=[].\n"
        "- UNKNOWN: khi dữ liệu không đủ căn cứ.\n"
        "- Trả về kết quả dưới dạng JSON tuân thủ schema sau:\n"
        + json.dumps(schema, ensure_ascii=False)
    )


def prompt_fingerprint() -> str:
    """SHA-256 của prompt đầy đủ (mọi loại sự kiện) - ghi vào báo cáo khi khoá prompt."""
    import hashlib
    prompt = build_system_prompt(BatchVerdict.model_json_schema(), "", set(SUPPORTED_EVENT_IDS))
    return hashlib.sha256(prompt.encode()).hexdigest()


def build_batch_payload(batch: list[dict]) -> str:
    """Nội dung gửi cho mô hình: thống kê + từng sự kiện kèm mô tả mã sự kiện."""
    counts: dict[int, int] = {}
    for e in batch:
        counts[e["event_id"]] = counts.get(e["event_id"], 0) + 1
    stats = "\n".join(
        f"- {eid} ({EVENT_MEANING.get(eid, 'khác')}): {counts.get(eid, 0)} sự kiện"
        for eid in sorted(set(BASE_EVENT_IDS) | set(counts))  # chỉ mã cơ bản + mã có trong lô (giữ payload ngắn)
    )
    events = [{**e, "event_meaning": EVENT_MEANING.get(e["event_id"], "")} for e in batch]
    return (
        f"THỐNG KÊ LÔ NÀY ({len(batch)} sự kiện):\n{stats}\n\n"
        f"DANH SÁCH SỰ KIỆN (JSON):\n{json.dumps(events, ensure_ascii=False)}"
    )


def ground_verdict(verdict: BatchVerdict, batch: list[dict]) -> BatchVerdict:
    """Kiểm chứng câu trả lời của AI với dữ liệu thật để chặn kết luận bịa (hallucination)."""
    valid_refs = {e["event_ref"] for e in batch}
    verdict.evidence_refs = [r for r in verdict.evidence_refs if r in valid_refs]
    if verdict.label != "ALERT":
        return verdict

    n_failed = sum(1 for e in batch if e["event_id"] == 4625)
    notes = []
    if n_failed < 3:
        kept = [s for s in verdict.detected_stages
                if not any(k in s.lower() for k in ("brute", "dò mật khẩu", "password"))]
        if len(kept) != len(verdict.detected_stages):
            notes.append(f"Loại bỏ kết luận 'dò mật khẩu' của AI vì lô chỉ có {n_failed} sự kiện 4625.")
            verdict.detected_stages = kept
            if not kept:
                verdict.label = "NORMAL"

    # Kết luận "trinh sát" phải có lệnh trinh sát thật trong lô
    has_recon = any(
        k in ((e["data"].get("CommandLine") or "") + " " + (e["data"].get("ScriptBlockText") or "")).lower()
        for e in batch for k in RECON_COMMANDS
    )
    if not has_recon:
        kept = [s for s in verdict.detected_stages
                if not any(k in s.lower() for k in ("recon", "discovery", "trinh sát"))]
        if len(kept) != len(verdict.detected_stages):
            notes.append("Loại bỏ kết luận 'trinh sát' của AI vì lô không có lệnh trinh sát nào.")
            verdict.detected_stages = kept
            if not kept:
                verdict.label = "NORMAL"

    if verdict.label == "ALERT" and not verdict.evidence_refs:
        notes.append("AI kết luận ALERT nhưng không chỉ ra được event_ref hợp lệ nào.")
        verdict.label = "UNKNOWN"

    if notes:
        verdict.limitations = (list(verdict.limitations) + notes)[-2:]
    return verdict


RECON_COMMANDS = ("whoami", "net user", "net1 user", "net group", "net localgroup", "systeminfo",
                  "nltest", "net view", "quser", "query user", "tasklist", "get-aduser", "get-netdomain")


class SecondOpinion(BaseModel):
    """Kết quả vòng tự thẩm định: sự kiện nào bản thân nó thực sự độc hại."""
    model_config = ConfigDict(extra="forbid")

    malicious_event_refs: list[str] = Field(
        max_length=30,
        description="event_ref của những sự kiện mà BẢN THÂN nó là hành vi tấn công rõ ràng; [] nếu không có",
    )
    reason: str = Field(min_length=1, description="Giải thích ngắn 1-2 câu")


def verify_alert(batch: list[dict], verdict: dict, model: str) -> tuple[bool, str]:
    """
    Vòng 2 (self-verification): hỏi lại mô hình một câu hẹp hơn về chính các sự kiện nó trích dẫn.
    Trả về (giữ_ALERT, lý_do). Dùng khi AI là bên duy nhất muốn cảnh báo.
    """
    cited = [e for e in batch if e["event_ref"] in set(verdict.get("evidence_refs", []))] or batch
    schema = SecondOpinion.model_json_schema()
    # Prompt động: chỉ nhắc tới loại sự kiện mở rộng khi sự kiện được trích dẫn có loại đó
    cited_ids = {e["event_id"] for e in cited}
    ext = ""
    if cited_ids & {1102, 104}:
        ext += ", xoá nhật ký (1102/104)"
    if 7045 in cited_ids:
        ext += ", service chạy cmd/powershell hoặc file tên ngẫu nhiên trong C:\\Windows (7045)"
    prompt = (
        "Bạn là người KIỂM DUYỆT cảnh báo SOC, nhiệm vụ là loại bỏ báo động giả. "
        "Một phân tích viên vừa kết luận các sự kiện dưới đây là tấn công. Xét TỪNG sự kiện một cách độc lập.\n"
        "Chỉ đánh dấu độc hại khi BẢN THÂN sự kiện chứa hành vi tấn công rõ ràng, ví dụ: công cụ tấn công "
        "(mimikatz, procdump lsass), tải/thực thi mã từ xa (IEX, DownloadString, -enc), tạo tài khoản qua công cụ "
        "thực thi từ xa (wmic process call create, psexec), thêm vào nhóm Administrators, xoá nhật ký, tắt Defender, "
        f"tạo persistence (Registry Run, schtasks chạy file lạ){ext}.\n"
        "KHÔNG độc hại: đăng nhập thành công thông thường, mở ứng dụng văn phòng/trình duyệt/notepad, lệnh chẩn đoán "
        "(ipconfig, ping, hostname, Get-Service), IT tạo tài khoản nhân viên bằng 'net user ten /add' trực tiếp.\n"
        "Không bịa thông tin không có trong sự kiện. Trả JSON theo schema: " + json.dumps(schema, ensure_ascii=False)
    )
    user = (
        f"Kết luận của phân tích viên: {verdict.get('reason', '')}\n\n"
        f"CÁC SỰ KIỆN ĐƯỢC TRÍCH DẪN:\n{build_batch_payload(cited)}"
    )
    response = requests.post(
        OLLAMA_URL,
        json={
            "model": model,
            "messages": [{"role": "system", "content": prompt}, {"role": "user", "content": user}],
            "format": schema,
            "stream": False,
            "keep_alive": "5m",
            "options": {"temperature": 0, "num_ctx": 8192, "num_predict": 512},
        },
        timeout=(10, 600),
    )
    response.raise_for_status()
    opinion = SecondOpinion.model_validate_json(response.json().get("message", {}).get("content") or "{}")
    confirmed = [r for r in opinion.malicious_event_refs if r in {e["event_ref"] for e in cited}]
    return bool(confirmed), opinion.reason


def analyze_batch(
    batch: list[dict],
    model: str,
    prompt: str,
    schema: dict,
) -> tuple[dict, dict]:
    """Gửi một lô log tới Ollama và kiểm tra kết quả trả về."""
    payload = build_batch_payload(batch)

    response = requests.post(
        OLLAMA_URL,
        json={
            "model": model,
            "messages": [
                {"role": "system", "content": prompt},
                {"role": "user", "content": payload},
            ],
            "format": schema,
            "stream": False,
            "keep_alive": 0,
            "options": {
                "temperature": 0,
                "repeat_penalty": 1.15,
                "num_ctx": 8192,
                "num_predict": 1024,
            },
        },
        timeout=(10, 600),
    )
    response.raise_for_status()
    response_data = response.json()

    content = response_data.get("message", {}).get("content")
    if not content:
        raise ValueError("Ollama returned an empty model response")

    try:
        parsed = BatchVerdict.model_validate_json(content)
    except Exception as exc:
        if response_data.get("done_reason") == "length":
            raise ValueError("Model output reached the generation limit and was incomplete") from exc
        raise exc

    model_label = parsed.label
    # Kiểm chứng kết luận của AI với dữ liệu thật (bằng chứng phải tồn tại, không bịa 4625...)
    parsed = ground_verdict(parsed, batch)

    metadata = {
        "load_duration_ns": response_data.get("load_duration"),
        "prompt_eval_count": response_data.get("prompt_eval_count"),
        "eval_count": response_data.get("eval_count"),
        "done_reason": response_data.get("done_reason"),
        "model_raw_label": model_label,
    }

    return parsed.model_dump(), metadata


CONFIDENCE_BY_SOURCE = {"rule+ai": 0.95, "rule": 0.9, "ai": 0.8, "error": 0.0}
DETECTION_SOURCE_ALIAS = {"rule+ai": "hybrid", "rule": "rule", "ai": "ai_model", "error": "error"}


def combine_batch_results(
    batch_results: list[dict],
    batch_count: int,
    errors: list[str],
    rule_findings: dict,
) -> tuple[str, dict]:
    """
    Nhãn do _combine_core quyết định (luật mạnh + AI). Hàm này bổ sung:
    - risk_score: điểm rủi ro tham khảo theo nhãn (ALERT >= ALERT_RISK_THRESHOLD, NORMAL < REVIEW_RISK_THRESHOLD).
    - REVIEW: thay UNKNOWN khi bộ luật có tín hiệu yếu với điểm rủi ro >= REVIEW_RISK_THRESHOLD
      -> đưa vào hàng chờ chuyên gia thay vì bỏ ngỏ. ALERT / NORMAL KHÔNG bị thay đổi.
    - confidence (heuristic theo nguồn quyết định), detection_source (bí danh tương thích bản update).
    """
    rule_findings.setdefault("strong_stages", [])
    status, verdict = _combine_core(batch_results, batch_count, errors, rule_findings)
    rule_risk = int(rule_findings.get("risk_score", 0))
    source = verdict.get("decision_source", "")
    label = verdict["label"]

    if label == "ALERT":
        ai_alert = any(item["verdict"]["label"] == "ALERT" for item in batch_results)
        risk = max(rule_risk, 85 if ai_alert else 0, ALERT_RISK_THRESHOLD)
        confidence = CONFIDENCE_BY_SOURCE.get(source, 0.8)
    elif label == "NORMAL":
        risk = min(rule_risk, REVIEW_RISK_THRESHOLD - 1)
        confidence = 0.9 if rule_risk == 0 else 0.75
    elif source != "error" and rule_findings.get("stages") and rule_risk >= REVIEW_RISK_THRESHOLD:
        label = verdict["label"] = "REVIEW"
        verdict["reason"] = (
            "AI chưa đủ căn cứ để kết luận; bộ luật có tín hiệu yếu ("
            + "; ".join(rule_findings["stages"]) + ") -> chuyển chuyên gia xem xét."
        )
        verdict["detected_stages"] = list(rule_findings["stages"])
        verdict["evidence_refs"] = list(dict.fromkeys(verdict["evidence_refs"] + rule_findings["evidence_refs"]))
        risk = rule_risk
        confidence = 0.5
    else:
        risk = rule_risk
        confidence = 0.0 if source == "error" else 0.3

    verdict["risk_score"] = int(min(100, risk))
    verdict["confidence"] = confidence
    verdict["detection_source"] = DETECTION_SOURCE_ALIAS.get(source, source)
    return status, verdict


def _combine_core(
    batch_results: list[dict],
    batch_count: int,
    errors: list[str],
    rule_findings: dict,
) -> tuple[str, dict]:
    """
    Hợp nhất kết quả AI + bộ luật (AI tham gia quyết định):
    1. Luật MẠNH (brute force theo cửa sổ thời gian, chữ ký MITRE, thêm vào Administrators...) -> ALERT (lưới an toàn).
    2. Không có luật mạnh: nhãn do AI quyết định (đã qua kiểm chứng bằng chứng).
       - AI ALERT ở bất kỳ lô nào -> ALERT.
       - Tất cả lô NORMAL -> NORMAL (kể cả khi có tín hiệu luật YẾU, ghi chú lại).
       - Còn lại -> UNKNOWN.
    """
    if errors and not batch_results:
        return "PARTIAL_ERROR", {
            "label": "UNKNOWN",
            "reason": "Không phân tích thành công tất cả các lô log.",
            "evidence_refs": [],
            "limitations": errors,
            "detected_stages": [],
            "decision_source": "error",
        }

    ai_alerts = [item["verdict"] for item in batch_results if item["verdict"]["label"] == "ALERT"]
    labels = [item["verdict"]["label"] for item in batch_results]
    strong = rule_findings.get("strong_stages", [])
    weak = [s for s in rule_findings["stages"] if s not in strong]

    limitations: list[str] = []
    if errors:
        limitations.extend(errors)
    if batch_count > 1:
        limitations.append(
            "Các lô được phân tích riêng; cần đối chiếu sự kiện giữa các lô để xác nhận quan hệ thời gian/phiên."
        )

    if strong or ai_alerts:
        stages: list[str] = list(strong)
        refs: list[str] = []
        reasons: list[str] = []
        # Khi AI xác nhận, mọi stage của luật (kể cả yếu) đều được giữ -> giữ luôn bằng chứng của chúng
        if strong or ai_alerts:
            refs.extend(rule_findings["evidence_refs"])
        for v in ai_alerts:
            refs.extend(v.get("evidence_refs", []))
            if v.get("reason"):
                reasons.append(v["reason"])
            limitations.extend(v.get("limitations", []))
            for st in v.get("detected_stages", []):
                if st not in stages:
                    stages.append(st)
        # Tín hiệu yếu được giữ lại khi AI xác nhận có tấn công
        if ai_alerts:
            for st in weak:
                if st not in stages:
                    stages.append(st)

        source = "rule+ai" if strong and ai_alerts else ("rule" if strong else "ai")
        parts = []
        if rule_findings["details"] and (strong or ai_alerts):
            parts.append("Bộ luật tương quan ghi nhận:")
            parts.extend(f"- {d}" for d in rule_findings["details"])
        if reasons:
            parts.append(f"Nhận định của AI: {' '.join(dict.fromkeys(reasons))}")
        if source == "rule":
            limitations.append("AI không xác nhận nhưng bộ luật phát hiện dấu hiệu chắc chắn nên vẫn cảnh báo.")

        return ("PARTIAL_ERROR" if errors else "OK"), {
            "label": "ALERT",
            "reason": "\n".join(parts) if parts else "Phát hiện dấu hiệu tấn công trong log.",
            "evidence_refs": list(dict.fromkeys(refs)),
            "limitations": list(dict.fromkeys(limitations)),
            "detected_stages": stages,
            "decision_source": source,
        }

    if labels and all(label == "NORMAL" for label in labels):
        for item in batch_results:
            limitations.extend(item["verdict"].get("limitations", []))
        if weak:
            limitations.append(
                "Bộ luật có tín hiệu yếu (" + "; ".join(weak) + ") nhưng AI đánh giá là hoạt động bình thường."
            )
        return ("PARTIAL_ERROR" if errors else "OK"), {
            "label": "NORMAL",
            "reason": "AI đánh giá các sự kiện là hoạt động hệ thống / người dùng thông thường, không phát hiện dấu hiệu độc hại.",
            "evidence_refs": [],
            "limitations": list(dict.fromkeys(limitations)),
            "detected_stages": [],
            "decision_source": "ai",
        }

    refs = list(dict.fromkeys(r for item in batch_results for r in item["verdict"].get("evidence_refs", [])))
    for item in batch_results:
        limitations.extend(item["verdict"].get("limitations", []))
    return ("PARTIAL_ERROR" if errors else "OK"), {
        "label": "UNKNOWN",
        "reason": "AI chưa đủ căn cứ để kết luận và bộ luật không có dấu hiệu chắc chắn.",
        "evidence_refs": refs,
        "limitations": list(dict.fromkeys(limitations)),
        "detected_stages": [],
        "decision_source": "ai",
    }


def resolve_case_dir(case_id: str, data_dir: Path | str | None = None) -> Path:
    """
    Tìm thư mục ca: <data_dir>/<case_id> hoặc <data_dir>/<nhóm>/<case_id> (cấu trúc data_benchmark/bai_X/).
    Không chỉ định data_dir -> tìm lần lượt data01/, data/, data_benchmark/ (thứ tự cũ được giữ).
    Không tìm thấy -> trả về đường dẫn dự kiến (người gọi tự báo lỗi).
    """
    if data_dir is not None:
        dpath = Path(data_dir)
        bases = [dpath if dpath.is_absolute() else BASE / dpath]
    else:
        bases = [BASE / "data01", BASE / "data", BASE / "data_benchmark"]
    for base in bases:
        if not base.is_dir():
            continue
        if (base / case_id).is_dir():
            return base / case_id
        for sub in sorted(base.iterdir()):
            if sub.is_dir() and (sub / case_id).is_dir():
                return sub / case_id
    return bases[0] / case_id if data_dir is not None else BASE / "data" / case_id


def analyze_case(
    case_id: str,
    model_key: str = "qwen",
    max_batch_chars: int = MAX_BATCH_CHARS,
    filter_noise: bool = True,
    data_dir: Path | str | None = None,
) -> dict:
    if not case_id or any(
        char not in
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
        for char in case_id
    ):
        raise ValueError(
            "case_id: use letters, numbers, underscore or hyphen"
        )

    if model_key not in MODELS:
        raise ValueError(f"Unknown model: {model_key}")

    case_dir = resolve_case_dir(case_id, data_dir)
    if not case_dir.is_dir():
        raise ValueError(f"Case directory does not exist: {case_dir}")

    model = MODELS[model_key]
    raw_events = read_events(case_dir)

    # 1. Tiền xử lý & lọc nhiễu hệ thống (nếu được bật)
    if filter_noise:
        events = [e for e in raw_events if not is_benign_noise(e)]
        if not events:
            # Nếu lọc hết sạch thì giữ lại sự kiện thô
            events = raw_events
    else:
        events = raw_events

    # 2. Quy tắc tương quan chuỗi tấn công (Correlation Engine)
    rule_findings = correlate_security_events(events)

    # Tóm tắt gợi ý cho mô hình AI
    correlation_hints = "\n".join(f"- {d}" for d in rule_findings["details"])

    # 3. Chia lô xử lý
    batches = split_event_batches(events, max_chars=max_batch_chars)

    schema = BatchVerdict.model_json_schema()

    started = time.perf_counter()
    batch_results = []
    errors = []

    for batch_number, batch in enumerate(batches, start=1):
        batch_refs = {e["event_ref"] for e in batch}
        # Chỉ truyền gợi ý tương quan đối với các sự kiện có mặt trong lô này
        batch_hints = [
            d for d in rule_findings["details"]
            if any(ref in d for ref in batch_refs)
        ]
        prompt = build_system_prompt(
            schema,
            correlation_hints="\n".join(f"- {h}" for h in batch_hints),
            event_ids={e["event_id"] for e in batch},  # prompt động theo loại sự kiện có trong lô
        )

        try:
            verdict, metadata = analyze_batch(
                batch=batch,
                model=model,
                prompt=prompt,
                schema=schema,
            )

            batch_results.append({
                "batch": batch_number,
                "event_count": len(batch),
                "first_event_ref": batch[0]["event_ref"],
                "last_event_ref": batch[-1]["event_ref"],
                "verdict": verdict,
                **metadata,
            })

        except requests.Timeout as exc:
            errors.append(f"Batch {batch_number}: timeout: {exc}")

        except requests.RequestException as exc:
            errors.append(f"Batch {batch_number}: API error: {exc}")

        except (ValueError, KeyError, TypeError) as exc:
            errors.append(f"Batch {batch_number}: invalid output: {exc}")

    # Vòng tự thẩm định: khi KHÔNG có luật mạnh, AI là bên duy nhất muốn cảnh báo -> hỏi lại để loại báo động giả
    if not rule_findings.get("strong_stages"):
        for item in batch_results:
            v = item["verdict"]
            if v["label"] != "ALERT":
                continue
            batch = batches[item["batch"] - 1]
            try:
                keep, why = verify_alert(batch, v, model)
            except (requests.RequestException, ValueError) as exc:
                keep, why = True, f"Không chạy được vòng tự thẩm định ({exc}); giữ nguyên kết luận."
            item["second_opinion"] = {"confirmed": keep, "reason": why}
            if not keep:
                v["label"] = "NORMAL"
                v["detected_stages"] = []
                v["evidence_refs"] = []
                v["limitations"] = (list(v.get("limitations", [])) + [f"Vòng tự thẩm định bác bỏ: {why}"])[-2:]

    status, verdict = combine_batch_results(
        batch_results=batch_results,
        batch_count=len(batches),
        errors=errors,
        rule_findings=rule_findings,
    )

    result = {
        "case_id": case_id,
        "model": model,
        "ollama_url": OLLAMA_URL,
        "analysis_status": status,
        "raw_event_count": len(raw_events),
        "analyzed_event_count": len(events),
        "batch_count": len(batches),
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "verdict": verdict,
        "batch_results": batch_results,
        "errors": errors,
    }

    output_dir = BASE / "results" / case_id
    output_dir.mkdir(parents=True, exist_ok=True)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output_path = output_dir / f"{model_key}_{stamp}.json"

    output_path.write_text(
        json.dumps(
            {
                "events": events,
                "result": result,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    result["result_file"] = str(output_path)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Analyze Windows event logs with a hybrid AI Agent (Correlation Engine + Local SLM)."
    )
    parser.add_argument("--case", required=True)
    parser.add_argument(
        "--model",
        choices=MODELS.keys(),
        default="qwen",
    )
    parser.add_argument(
        "--max-batch-chars",
        type=int,
        default=MAX_BATCH_CHARS,
        help="Giới hạn số ký tự tối đa cho mỗi lô (mặc định: %(default)s)",
    )
    parser.add_argument(
        "--no-filter",
        action="store_true",
        help="Không lọc các tiến trình nhiễu nền của hệ thống",
    )
    args = parser.parse_args()

    try:
        result = analyze_case(
            args.case,
            args.model,
            max_batch_chars=args.max_batch_chars,
            filter_noise=not args.no_filter,
        )

    except (ValueError, OSError, ET.ParseError) as exc:
        parser.exit(1, f"Input error: {exc}\n")

    print(json.dumps(result, ensure_ascii=False, indent=2))
    raise SystemExit(
        0 if result["analysis_status"] == "OK" else 1
    )