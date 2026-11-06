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

FIELDS = {
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
    """Đọc các sự kiện được hỗ trợ từ security.xml và powershell.xml."""
    events = []

    for filename in ("security.xml", "powershell.xml"):
        path = case_dir / filename

        if not path.is_file():
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

            if event_id not in {4624, 4625, 4648, 4688, 4104}:
                continue

            timestamp = system.find("w:TimeCreated", NS)
            provider = system.find("w:Provider", NS)
            execution = system.find("w:Execution", NS)

            data = {
                item.get("Name"): item.text or ""
                for item in event.findall("w:EventData/w:Data", NS)
                if item.get("Name") in FIELDS
            }

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
    findings = {
        "stages": [],
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

    findings["evidence_refs"] = list(dict.fromkeys(findings["evidence_refs"]))
    return findings


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


def build_system_prompt(schema: dict, correlation_hints: str = "") -> str:
    if correlation_hints:
        hints_text = (
            "\nKẾT QUẢ PHÂN TÍCH TƯƠNG QUAN BẢO MẬT:\n"
            f"{correlation_hints}\n"
            "Hãy đánh giá và giải thích chi tiết chuỗi tấn công này.\n"
        )
    else:
        hints_text = (
            "\nKẾT QUẢ PHÂN TÍCH TƯƠNG QUAN BẢO MẬT:\n"
            "- Không phát hiện chuỗi tấn công (không có Brute Force, không có backdoor, không có script tải mã độc).\n"
            "Nếu các sự kiện chỉ là tiến trình hệ thống Windows thông thường, hãy kết luận nhãn 'NORMAL'.\n"
        )

    return (
        "Bạn là Chuyên gia Điều tra & Phân tích Sự cố An toàn Thông tin (SOC Tier-3 / DFIR). "
        "Nhiệm vụ của bạn là phân tích khách quan danh sách Windows Event Logs được cung cấp.\n\n"
        "CÁC TIÊU CHUẨN ĐÁNH GIÁ HÀNH VI TẤN CÔNG:\n"
        "1. Dò mật khẩu (Password Brute Force - MITRE T1110): Xuất hiện nhiều sự kiện 4625 (Logon Failure) liên tiếp cho tài khoản.\n"
        "2. Đăng nhập thành công sau dò mật khẩu: Sự kiện 4624 ngay sau chuỗi 4625.\n"
        "3. Trinh sát hệ thống (System Discovery - MITRE T1033): Các lệnh khám phá như 'whoami', 'net user', 'systeminfo'.\n"
        "4. Tạo tài khoản backdoor / Leo thang: 'net user /add', 'net localgroup Administrators /add'.\n"
        "5. Tải & Thực thi mã độc: Lệnh PowerShell chứa tham số ẩn bypass hoặc ScriptBlock tải payload từ xa, mimikatz, sửa Registry Run.\n"
        f"{hints_text}\n"
        "QUY TẮC PHÁN QUYẾT:\n"
        "- TUYỆT ĐỐI TRUNG THỰC VỚI DỮ LIỆU: Chỉ kết luận dựa trên đúng các trường dữ liệu có trong sự kiện của lô này. KHÔNG ĐƯỢC tự suy diễn ra các lệnh PowerShell, URL hay công cụ không có trong log.\n"
        "- Nếu phát hiện hành vi tấn công có thật: Đặt nhãn 'ALERT', giải thích rõ ràng và liệt kê đúng event_ref làm bằng chứng.\n"
        "- Nếu các sự kiện chỉ là tiến trình hệ thống thông thường và không có hành vi độc hại: BẮT BUỘC đặt nhãn 'NORMAL', detected_stages=[], evidence_refs=[].\n"
        "- Dùng 'UNKNOWN' khi dữ liệu không đủ căn cứ để kết luận.\n"
        "- Trả về kết quả dưới dạng JSON tuân thủ schema sau:\n"
        + json.dumps(schema, ensure_ascii=False)
    )


def analyze_batch(
    batch: list[dict],
    model: str,
    prompt: str,
    schema: dict,
) -> tuple[dict, dict]:
    """Gửi một lô log tới Ollama và kiểm tra kết quả trả về."""
    payload = json.dumps(batch, ensure_ascii=False)

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

    valid_refs = {event["event_ref"] for event in batch}
    # Chỉ giữ lại các evidence_refs thực sự thuộc lô này
    cleaned_refs = [ref for ref in parsed.evidence_refs if ref in valid_refs]
    if parsed.label == "ALERT" and not cleaned_refs:
        cleaned_refs = [batch[0]["event_ref"]]
    parsed.evidence_refs = cleaned_refs

    metadata = {
        "load_duration_ns": response_data.get("load_duration"),
        "prompt_eval_count": response_data.get("prompt_eval_count"),
        "eval_count": response_data.get("eval_count"),
        "done_reason": response_data.get("done_reason"),
    }

    return parsed.model_dump(), metadata


def combine_batch_results(
    batch_results: list[dict],
    batch_count: int,
    errors: list[str],
    rule_findings: dict,
) -> tuple[str, dict]:
    """Tổng hợp kết quả giữa mô hình AI và bộ quy tắc tương quan bảo mật."""
    if errors:
        return "PARTIAL_ERROR", {
            "label": "UNKNOWN",
            "reason": "Không phân tích thành công tất cả các lô log.",
            "evidence_refs": [],
            "limitations": errors,
            "detected_stages": [],
        }

    alert_results = [
        item["verdict"]
        for item in batch_results
        if item["verdict"]["label"] == "ALERT"
    ]

    # Phán quyết ALERT chỉ được kích hoạt khi quy tắc bảo mật xác nhận có chuỗi tấn công
    if rule_findings["stages"]:
        all_refs = []
        all_reasons = []
        all_limits = []
        all_stages = list(rule_findings["stages"])

        # Bổ sung bằng chứng từ quy tắc
        all_refs.extend(rule_findings["evidence_refs"])

        for verdict in alert_results:
            all_refs.extend(verdict.get("evidence_refs", []))
            all_reasons.append(verdict.get("reason", ""))
            all_limits.extend(verdict.get("limitations", []))
            for st in verdict.get("detected_stages", []):
                if st not in all_stages:
                    all_stages.append(st)

        all_refs = list(dict.fromkeys(all_refs))
        all_limits = list(dict.fromkeys(all_limits))

        # Xây dựng bản mô tả chi tiết các giai đoạn
        combined_reason_parts = []
        if rule_findings["details"]:
            combined_reason_parts.append("Phát hiện chuỗi hành vi tấn công:")
            for d in rule_findings["details"]:
                combined_reason_parts.append(f"- {d}")

        if all_reasons:
            combined_reason_parts.append(f"Nhận định chuyên sâu của AI: {' '.join(dict.fromkeys(all_reasons))}")

        if batch_count > 1:
            all_limits.append(
                "Các lô được phân tích riêng; cần đối chiếu các sự kiện thuộc các lô khác nhau để xác nhận quan hệ thời gian/phiên."
            )

        return "OK", {
            "label": "ALERT",
            "reason": "\n".join(combined_reason_parts) if combined_reason_parts else "Phát hiện dấu hiệu tấn công trong log.",
            "evidence_refs": all_refs,
            "limitations": all_limits,
            "detected_stages": all_stages,
        }

    # Trường hợp không phát hiện chuỗi tấn công
    labels = [item["verdict"]["label"] for item in batch_results]

    # Nếu tất cả các lô đều kết luận NORMAL và không có cảnh báo tương quan
    if all(l == "NORMAL" for l in labels):
        all_limits = list(dict.fromkeys(
            limitation for item in batch_results for limitation in item["verdict"].get("limitations", [])
        ))
        if batch_count > 1:
            all_limits.append("Dữ liệu được phân tích theo nhiều lô; tất cả các lô đều là hoạt động bình thường.")
        return "OK", {
            "label": "NORMAL",
            "reason": "Các sự kiện log chỉ bao gồm hoạt động hệ thống và tác vụ quản trị thông thường, không phát hiện dấu hiệu độc hại.",
            "evidence_refs": [],
            "limitations": all_limits,
            "detected_stages": [],
        }

    if "UNKNOWN" in labels or "ALERT" in labels:
        refs = list(dict.fromkeys(
            ref for item in batch_results for ref in item["verdict"]["evidence_refs"]
        ))
        limitations = list(dict.fromkeys(
            limitation for item in batch_results for limitation in item["verdict"]["limitations"]
        ))
        limitations.append(
            "Không phát hiện chuỗi tấn công rõ ràng (không có Brute Force, Backdoor, hay Malware cradle)."
        )

        return "OK", {
            "label": "UNKNOWN",
            "reason": "Chưa thấy chuỗi tấn công xác thực trong các lô log. Giữ nhãn UNKNOWN theo quy tắc phân tích thận trọng.",
            "evidence_refs": refs,
            "limitations": limitations,
            "detected_stages": [],
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