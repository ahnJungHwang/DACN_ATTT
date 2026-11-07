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


BASE = Path(__file__).resolve().parent
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
    4720, 4728, 4732,                   # tạo tài khoản, thêm vào nhóm global / local
    4698,                               # tạo scheduled task
}
MAX_FIELD_CHARS = 2000  # cắt TaskContent (file XML định nghĩa task) để vừa context

FIELDS = {
    "ServiceName", "ImagePath", "ServiceType", "StartType", "AccountName",   # 7045
    "MemberName", "MemberSid", "TargetSid", "SamAccountName",                # 4720 / 4728 / 4732
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


class BatchVerdict(BaseModel):
    """Schema Reasoning-First: Mô hình suy luận và liệt kê bằng chứng trước khi kết luận nhãn."""
    model_config = ConfigDict(extra="forbid")

    detected_stages: list[str] = Field(
        max_length=5,
        description="Danh sách các giai đoạn tấn công phát hiện được (ví dụ: Password Brute Force, Reconnaissance, Backdoor Creation, Privilege Escalation, Malware Execution)"
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

    label: Literal["ALERT", "NORMAL", "UNKNOWN"]
    reason: str = Field(min_length=1)
    evidence_refs: list[str]
    limitations: list[str]
    detected_stages: list[str] = Field(default_factory=list)


def is_benign_noise(event: dict) -> bool:
    """Lọc bỏ các tiến trình và dịch vụ hệ thống định kỳ không liên quan đến điều tra."""
    eid = event.get("event_id")
    data = event.get("data", {})

    if eid == 4688:
        proc = data.get("NewProcessName", "").lower()
        base_proc = proc.split("\\")[-1]
        cmd = data.get("CommandLine", "").strip()

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

    elif eid == 4624:
        # Lọc bỏ LogonType 5 (Dịch vụ nền khởi động dưới quyền SYSTEM/Service)
        if data.get("LogonType") == "5" and data.get("TargetUserName") in (
            "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"
        ):
            return True

    elif eid == 4104:
        # Lọc bỏ các đoạn script nội bộ của PowerShell engine (Prompt, formatter)
        txt = data.get("ScriptBlockText", "")
        if "Set-StrictMode" in txt or txt.strip() == "$global:?" or (
            "prompt" in txt.lower() and len(txt) < 50
        ):
            return True

    return False


def read_events(case_dir: Path) -> list[dict]:
    """Đọc các sự kiện được hỗ trợ từ security.xml, powershell.xml (bắt buộc) và system.xml (tuỳ chọn)."""
    events = []

    for filename in ("security.xml", "powershell.xml", "system.xml"):
        path = case_dir / filename

        if not path.is_file():
            if filename == "system.xml":
                continue  # client cũ / ca cũ không có log System
            raise ValueError(f"Missing file: {filename}")

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

            data = {
                item.get("Name"): item.text or ""
                for item in event.findall("w:EventData/w:Data", NS)
                if item.get("Name") in FIELDS
            }
            # 1102 / 104 lưu dữ liệu trong <UserData><LogFileCleared>...</LogFileCleared></UserData>
            user_data = event.find("w:UserData", NS)
            if user_data is not None:
                for block in user_data:
                    for item in block:
                        name = item.tag.split("}")[-1]
                        if name in FIELDS and item.text:
                            data.setdefault(name, item.text)
            # TaskContent là cả file XML định nghĩa task -> cắt bớt; ScriptBlockText giữ nguyên như trước
            if len(data.get("TaskContent", "")) > MAX_FIELD_CHARS:
                data["TaskContent"] = data["TaskContent"][:MAX_FIELD_CHARS] + "…[cắt bớt]"

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


def correlate_security_events(events: list[dict]) -> dict:
    """
    Quy tắc phân tích chuỗi sự kiện bảo mật (Security Correlation Engine):
    Phát hiện các giai đoạn tấn công kinh điển theo MITRE ATT&CK.
    """
    # strong_stages: tín hiệu chắc chắn -> luôn ALERT (lưới an toàn).
    # Các stage còn lại là tín hiệu YẾU, mô hình AI sẽ quyết định.
    findings = {
        "stages": [],
        "strong_stages": [],
        "evidence_refs": [],
        "details": [],
    }

    # 1. Phát hiện Dò mật khẩu (Password Brute Force - MITRE T1110)
    failed_logons = [
        e for e in events if e.get("event_id") == 4625
    ]
    if len(failed_logons) >= 3:
        target_users = list(dict.fromkeys(
            e["data"].get("TargetUserName") for e in failed_logons if e["data"].get("TargetUserName")
        ))
        refs = [e["event_ref"] for e in failed_logons]
        user_str = ", ".join(target_users) if target_users else "unknown user"
        findings["stages"].append("Password Brute Force (MITRE T1110)")
        findings["strong_stages"].append("Password Brute Force (MITRE T1110)")
        findings["evidence_refs"].extend(refs)
        findings["details"].append(
            f"Phát hiện {len(failed_logons)} lần đăng nhập thất bại liên tiếp (Event 4625) nhằm vào tài khoản '{user_str}'. Bằng chứng: {', '.join(refs)}."
        )

    # 2. Phát hiện Đăng nhập thành công sau chuỗi dò quét (Valid Accounts - MITRE T1078)
    if failed_logons:
        last_failed_ref = failed_logons[-1]["event_ref"]
        success_logons = [
            e for e in events
            if e.get("event_id") == 4624 and e["event_ref"] > last_failed_ref
            and e["data"].get("LogonType") not in ("5", "")
        ]
        if success_logons:
            refs = [e["event_ref"] for e in success_logons]
            findings["stages"].append("Successful Logon Post-Brute Force (MITRE T1078)")
            # Chỉ chắc chắn khi trước đó thật sự có brute force (>=3 lần sai); gõ sai 1-2 lần là tín hiệu yếu
            if len(failed_logons) >= 3:
                findings["strong_stages"].append("Successful Logon Post-Brute Force (MITRE T1078)")
            findings["evidence_refs"].extend(refs)
            findings["details"].append(
                f"Phát hiện đăng nhập thành công (Event 4624) ngay sau chuỗi đăng nhập thất bại. Bằng chứng: {', '.join(refs)}."
            )

    # 3. Phát hiện Tạo Backdoor / Leo thang đặc quyền (Backdoor / Account Manipulation - MITRE T1136, T1098)
    backdoor_events = [
        e for e in events
        if e.get("event_id") == 4688 and (
            "/add" in (e["data"].get("CommandLine") or "").lower() and
            any(k in (e["data"].get("CommandLine") or "").lower() for k in ("net user", "net1 user", "net localgroup", "net1 localgroup"))
        )
    ]
    if backdoor_events:
        refs = [e["event_ref"] for e in backdoor_events]
        findings["stages"].append("Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098)")
        # Thêm vào nhóm Administrators là chắc chắn; chỉ tạo user có thể là IT tạo tài khoản -> để AI xét ngữ cảnh
        if any("administrators" in (e["data"].get("CommandLine") or "").lower() for e in backdoor_events):
            findings["strong_stages"].append("Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098)")
        findings["evidence_refs"].extend(refs)
        findings["details"].append(
            f"Phát hiện lệnh tạo tài khoản hoặc gán quyền quản trị cục bộ (net user /add, net localgroup Administrators /add). Bằng chứng: {', '.join(refs)}."
        )

    # 4. Phát hiện Tải & Thực thi mã độc (PowerShell Execution & C2 - MITRE T1059.001, T1547.001)
    malware_events = []
    for e in events:
        cmd = (e["data"].get("CommandLine") or "").lower()
        script = (e["data"].get("ScriptBlockText") or "").lower()
        if (
            "downloadstring" in script or "mimikatz" in script or
            "currentversion\\run" in script or "-encodedcommand" in cmd or
            ("iex" in script and "http" in script)
        ):
            malware_events.append(e)

    if malware_events:
        refs = [e["event_ref"] for e in malware_events]
        findings["stages"].append("Malware Execution / PowerShell Download Cradle (MITRE T1059.001)")
        findings["strong_stages"].append("Malware Execution / PowerShell Download Cradle (MITRE T1059.001)")
        findings["evidence_refs"].extend(refs)
        findings["details"].append(
            f"Phát hiện lệnh PowerShell tải mã độc từ xa (Download Cradle / Mimikatz / Registry Run Persistence). Bằng chứng: {', '.join(refs)}."
        )

    # 5. Phát hiện Trinh sát hệ thống (System Discovery - MITRE T1033)
    # whoami đứng một mình là lệnh quản trị thông thường; chỉ coi là Reconnaissance khi đi kèm chuỗi tấn công
    recon_events = [
        e for e in events
        if e.get("event_id") == 4688 and any(
            cmd in (e["data"].get("CommandLine") or "").lower() or
            cmd in (e["data"].get("NewProcessName") or "").lower()
            for cmd in ("whoami", "nltest", "net group", "systeminfo")
        )
    ]
    if recon_events and (failed_logons or backdoor_events or malware_events):
        refs = [e["event_ref"] for e in recon_events]
        findings["stages"].append("System Reconnaissance (MITRE T1033)")
        findings["evidence_refs"].extend(refs)
        findings["details"].append(
            f"Phát hiện lệnh khám phá và trinh sát hệ thống (whoami/discovery) trong chuỗi tấn công. Bằng chứng: {', '.join(refs)}."
        )

    def add(stage: str, evs: list[dict], detail: str, strong: bool) -> None:
        refs = [e["event_ref"] for e in evs]
        findings["stages"].append(stage)
        if strong:
            findings["strong_stages"].append(stage)
        findings["evidence_refs"].extend(refs)
        findings["details"].append(f"{detail} Bằng chứng: {', '.join(refs)}.")

    # 6. Xoá nhật ký (Indicator Removal - MITRE T1070.001): 1102 (Security) / 104 (System)
    cleared = [e for e in events if e.get("event_id") in (1102, 104)]
    if cleared:
        logs = sorted({e["data"].get("Channel") or ("Security" if e["event_id"] == 1102 else "System") for e in cleared})
        add("Indicator Removal: Clear Windows Event Logs (MITRE T1070.001)", cleared,
            f"Phát hiện nhật ký Windows bị xoá ({', '.join(logs)}) - Event 1102/104.", strong=True)

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

    # 9. Thêm vào nhóm đặc quyền (MITRE T1098): 4728/4732 với nhóm Administrators / Domain Admins...
    group_adds = [e for e in events if e.get("event_id") in (4728, 4732)]
    priv_adds = [
        e for e in group_adds
        if (e["data"].get("TargetSid") or "").upper() in PRIVILEGED_GROUP_SIDS
        or (e["data"].get("TargetUserName") or "").lower() in PRIVILEGED_GROUP_NAMES
    ]
    if priv_adds:
        groups = ", ".join(dict.fromkeys(e["data"].get("TargetUserName", "?") for e in priv_adds))
        add("Account Manipulation: Add to Privileged Group (MITRE T1098)", priv_adds,
            f"Tài khoản được thêm vào nhóm đặc quyền {groups} (Event 4728/4732).", strong=True)

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
    4728: "Thành viên được thêm vào nhóm bảo mật global (TargetUserName = tên nhóm, MemberName/MemberSid = người được thêm)",
    4732: "Thành viên được thêm vào nhóm bảo mật local (TargetUserName = tên nhóm, MemberSid = người được thêm)",
    4698: "Scheduled task mới được tạo (TaskName, TaskContent)",
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
    ({4720, 4728, 4732},
     "Tạo tài khoản (4720) rồi thêm vào nhóm đặc quyền như Administrators (4732/4728).",
     "Tạo tài khoản / thêm vào nhóm thường (Users) khi cài đặt hoặc do bộ phận IT thực hiện, không kèm nhóm đặc quyền."),
    ({4698},
     "Scheduled task (4698) chạy PowerShell mã hoá, tải từ mạng hoặc file trong thư mục tạm.",
     "Scheduled task của Microsoft/phần mềm cập nhật (\\Microsoft\\Windows\\..., GoogleUpdate, OneDrive...)."),
]


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

    ext = [(sign, normal) for ids, sign, normal in EXTENDED_SIGNS if ids & present]
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


def combine_batch_results(
    batch_results: list[dict],
    batch_count: int,
    errors: list[str],
    rule_findings: dict,
) -> tuple[str, dict]:
    """
    Hợp nhất kết quả AI + bộ luật (AI tham gia quyết định):
    1. Luật MẠNH (brute force >=3, tải/thực thi mã độc, thêm vào Administrators) -> ALERT (lưới an toàn).
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
        if strong:
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

    if data_dir is not None:
        dpath = Path(data_dir)
        case_dir = dpath / case_id if dpath.is_absolute() else BASE / dpath / case_id
    else:
        if (BASE / "data01" / case_id).is_dir():
            case_dir = BASE / "data01" / case_id
        else:
            case_dir = BASE / "data" / case_id

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