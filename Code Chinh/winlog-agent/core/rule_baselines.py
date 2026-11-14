"""
Baseline KHÔNG dùng AI để so sánh với Qwen / Llama (gộp từ bản update 13/11/2026).

LƯU Ý KHI VIẾT BÁO CÁO: đây là bản MÔ PHỎNG lại một số luật tiêu biểu của DeepBlueCLI (regexes.txt,
ngưỡng 4625...) và SigmaHQ bằng regex Python chạy trên security.xml / powershell.xml — KHÔNG phải chạy
công cụ DeepBlueCLI / sigma-cli thật. Kết quả chạy DeepBlue.ps1 thật trên file EVTX nằm ở
eval_real/run_deepblue.ps1 -> eval_real/deepblue_results.csv.
"""
import re
import time
from pathlib import Path

from analyze import resolve_case_dir


def run_deepblue_rule_baseline(case_id: str, data_dir: Path | str | None = None) -> dict:
    """
    Công cụ DeepBlueCLI (SANS Institute - Eric Conrad).
    Phương pháp: So khớp Regex đặc trưng dòng lệnh PowerShell (regexes.txt)
    và kiểm tra ngưỡng Event ID bảo mật Windows (Event 4625 brute force, 4720/4728 account manipulation, 1102 log cleared).
    """
    started = time.perf_counter()
    target_dir = resolve_case_dir(case_id, data_dir)
    sec_file = target_dir / "security.xml"
    ps_file = target_dir / "powershell.xml"

    sec_content = sec_file.read_text(encoding="utf-8", errors="ignore") if sec_file.is_file() else ""
    ps_content = ps_file.read_text(encoding="utf-8", errors="ignore") if ps_file.is_file() else ""
    combined = sec_content + "\n" + ps_content

    alerts = []

    # 1. Logon Failure Threshold (Event 4625 >= 4)
    count_4625 = sec_content.count("<EventID>4625</EventID>")
    if count_4625 >= 4:
        alerts.append(f"DeepBlueCLI: Password Brute Force ({count_4625} failed logons - Event 4625)")

    # 2. User Account & Group Escalation (Event 4720 & 4728)
    user_created = ("<EventID>4720</EventID>" in sec_content) or bool(re.search(r"net(\.exe)?\s+user\s+.*\/add", sec_content, re.IGNORECASE))
    group_added = ("<EventID>4728</EventID>" in sec_content) or bool(re.search(r"net(\.exe)?\s+localgroup\s+Administrators\s+.*\/add", sec_content, re.IGNORECASE))
    if user_created and group_added:
        alerts.append("DeepBlueCLI: User Creation & Admin Group Escalation (Event 4720/4728)")

    # 3. PowerShell Download Cradle Regex (SANS regexes.txt)
    cradle_match = re.search(r"(DownloadString|DownloadFile|Net\.WebClient|Invoke-WebRequest.*-OutFile|IEX\s*\(New-Object)", combined, re.IGNORECASE)
    if cradle_match and re.search(r"(http|https|ftp)://", combined, re.IGNORECASE):
        if "intranet.corp.local" not in combined:
            alerts.append("DeepBlueCLI: PowerShell Download Cradle Pattern (regexes.txt)")

    # 4. Mimikatz & Credential Dumping Regex (SANS regexes.txt)
    if re.search(r"(mimikatz|Invoke-Mimikatz|sekurlsa|logonpasswords|lsadump)", combined, re.IGNORECASE):
        alerts.append("DeepBlueCLI: Mimikatz Credential Dumping Keywords (regexes.txt)")

    # 5. Sysinternals ProcDump LSASS Regex (SANS regexes.txt)
    if re.search(r"procdump(\.exe)?\s+.*lsass", combined, re.IGNORECASE):
        alerts.append("DeepBlueCLI: ProcDump LSASS Memory Dumping")

    # 6. Registry Run Key Persistence Regex (SANS regexes.txt)
    if re.search(r"CurrentVersion\\Run", combined, re.IGNORECASE) and re.search(r"(reg(\.exe)?\s+add|Set-ItemProperty)", combined, re.IGNORECASE):
        alerts.append("DeepBlueCLI: Registry Run Key Persistence Pattern")

    # 7. Scheduled Tasks Persistence Regex (SANS regexes.txt)
    if re.search(r"schtasks(\.exe)?\s+/create.*(powershell|cmd|c2|enc|\.exe)", combined, re.IGNORECASE) or re.search(r"Register-ScheduledTask", combined, re.IGNORECASE):
        alerts.append("DeepBlueCLI: Scheduled Task Persistence Pattern")

    # 8. Event Log Cleared (Event 1102 / wevtutil cl)
    if ("<EventID>1102</EventID>" in sec_content) or re.search(r"wevtutil(\.exe)?\s+cl\s+(Security|System)", combined, re.IGNORECASE):
        alerts.append("DeepBlueCLI: Security Event Log Cleared (Event 1102)")

    # 9. Obfuscated Base64 Encoded PowerShell (SANS regexes.txt)
    if re.search(r"powershell(\.exe)?.*(Hidden.*Enc|-enc\s+[A-Za-z0-9+/=]{20,}|-EncodedCommand\s+[A-Za-z0-9+/=]{20,})", combined, re.IGNORECASE):
        alerts.append("DeepBlueCLI: Obfuscated Base64 Encoded Command")

    elapsed = round(time.perf_counter() - started, 4)
    if elapsed == 0:
        elapsed = 0.005

    if alerts:
        pred_label = "ALERT"
        reason = "; ".join(alerts)
    else:
        pred_label = "NORMAL"
        reason = "DeepBlueCLI: An toàn (Không khớp quy tắc nghi vấn)"

    return {
        "success": True,
        "pred_label": pred_label,
        "elapsed_seconds": elapsed,
        "stages": alerts,
        "evidence_count": len(alerts),
        "reason": reason[:140],
        "json_valid": True,
        "error": "",
    }


def run_sigma_rule_baseline(case_id: str, data_dir: Path | str | None = None) -> dict:
    """
    Công cụ Sigma Rules (SigmaHQ Project).
    Phương pháp: Triển khai các luật Sigma chuẩn cho Windows Security & Process Creation:
    - win_security_multiple_failed_logons (Event 4625 threshold)
    - win_security_net_user_add (Event 4720/4728)
    - proc_creation_win_powershell_download_cradle
    - proc_creation_win_mimikatz
    - proc_creation_win_procdump_lsass
    - proc_creation_win_schtasks_persistence
    - proc_creation_win_registry_run_key
    - proc_creation_win_defender_disable (Set-MpPreference RealtimeMonitoring)
    - proc_creation_win_office_spawn_process (Word macro spawning powershell/cmd)
    - win_security_clear_event_log (Event 1102 / wevtutil cl)
    - proc_creation_win_powershell_encoded
    """
    started = time.perf_counter()
    target_dir = resolve_case_dir(case_id, data_dir)
    sec_file = target_dir / "security.xml"
    ps_file = target_dir / "powershell.xml"

    sec_content = sec_file.read_text(encoding="utf-8", errors="ignore") if sec_file.is_file() else ""
    ps_content = ps_file.read_text(encoding="utf-8", errors="ignore") if ps_file.is_file() else ""
    combined = sec_content + "\n" + ps_content

    alerts = []

    # Sigma Rule: win_security_multiple_failed_logons
    count_4625 = sec_content.count("<EventID>4625</EventID>")
    if count_4625 >= 4:
        alerts.append(f"Sigma [win_security_multiple_failed_logons]: {count_4625} failed logons")

    # Sigma Rule: win_security_net_user_add & admin_group
    user_created = ("<EventID>4720</EventID>" in sec_content) or bool(re.search(r"net(\.exe)?\s+user\s+.*\/add", sec_content, re.IGNORECASE))
    group_added = ("<EventID>4728</EventID>" in sec_content) or bool(re.search(r"net(\.exe)?\s+localgroup\s+Administrators\s+.*\/add", sec_content, re.IGNORECASE))
    if user_created and group_added:
        alerts.append("Sigma [win_security_net_user_add]: Backdoor Admin Account Created")

    # Sigma Rule: proc_creation_win_powershell_download_cradle
    cradle_match = re.search(r"(DownloadString|DownloadFile|Net\.WebClient|Invoke-WebRequest.*-OutFile)", combined, re.IGNORECASE)
    if cradle_match and re.search(r"(http|https|ftp)://", combined, re.IGNORECASE):
        if "intranet.corp.local" not in combined:
            alerts.append("Sigma [proc_creation_win_powershell_download_cradle]: Remote Download Cradle")

    # Sigma Rule: proc_creation_win_mimikatz
    if re.search(r"(mimikatz|Invoke-Mimikatz|sekurlsa|logonpasswords|lsadump)", combined, re.IGNORECASE):
        alerts.append("Sigma [proc_creation_win_mimikatz]: Credential Dumping Tool Detected")

    # Sigma Rule: proc_creation_win_procdump_lsass
    if re.search(r"procdump(\.exe)?\s+.*lsass", combined, re.IGNORECASE):
        alerts.append("Sigma [proc_creation_win_procdump_lsass]: LSASS Memory Dump via ProcDump")

    # Sigma Rule: proc_creation_win_schtasks_persistence
    if re.search(r"(schtasks(\.exe)?\s+/create.*(powershell|cmd|c2|enc|\.exe)|Register-ScheduledTask)", combined, re.IGNORECASE):
        alerts.append("Sigma [proc_creation_win_schtasks_persistence]: Scheduled Task Persistence")

    # Sigma Rule: proc_creation_win_registry_run_key
    if re.search(r"(CurrentVersion\\Run|CurrentVersion\\RunOnce)", combined, re.IGNORECASE) and re.search(r"(reg(\.exe)?\s+add|Set-ItemProperty)", combined, re.IGNORECASE):
        alerts.append("Sigma [proc_creation_win_registry_run_key]: Run Key Auto-Start Persistence")

    # Sigma Rule: proc_creation_win_defender_disable
    if re.search(r"Set-MpPreference.*-DisableRealtimeMonitoring", combined, re.IGNORECASE):
        alerts.append("Sigma [proc_creation_win_defender_disable]: Tampering Defender Realtime Protection")

    # Sigma Rule: proc_creation_win_office_spawn_process
    if re.search(r"winword\.exe", combined, re.IGNORECASE) and re.search(r"(powershell|cmd)\.exe", combined, re.IGNORECASE):
        alerts.append("Sigma [proc_creation_win_office_spawn_process]: Word Spawning Script Shell (Macro)")

    # Sigma Rule: win_security_clear_event_log
    if ("<EventID>1102</EventID>" in sec_content) or re.search(r"wevtutil(\.exe)?\s+cl\s+(Security|System)", combined, re.IGNORECASE):
        alerts.append("Sigma [win_security_clear_event_log]: Security Audit Log Cleared")

    # Sigma Rule: proc_creation_win_powershell_encoded
    if re.search(r"powershell(\.exe)?.*(Hidden.*Enc|-enc\s+[A-Za-z0-9+/=]{20,}|-EncodedCommand\s+[A-Za-z0-9+/=]{20,})", combined, re.IGNORECASE):
        alerts.append("Sigma [proc_creation_win_powershell_encoded]: Encoded PowerShell Command Line")

    elapsed = round(time.perf_counter() - started, 4)
    if elapsed == 0:
        elapsed = 0.005

    if alerts:
        pred_label = "ALERT"
        reason = "; ".join(alerts)
    else:
        pred_label = "NORMAL"
        reason = "Sigma Rules: An toàn (Không khớp quy tắc nghi vấn)"

    return {
        "success": True,
        "pred_label": pred_label,
        "elapsed_seconds": elapsed,
        "stages": alerts,
        "evidence_count": len(alerts),
        "reason": reason[:140],
        "json_valid": True,
        "error": "",
    }


def run_combined_rule_baseline(case_id: str, data_dir: Path | str | None = None) -> dict:
    """Hợp nhất DeepBlueCLI + Sigma Rules vào 1 đối tượng Non-AI chung."""
    db_res = run_deepblue_rule_baseline(case_id, data_dir)
    sg_res = run_sigma_rule_baseline(case_id, data_dir)

    all_alerts = list(dict.fromkeys(db_res["stages"] + sg_res["stages"]))
    pred_label = "ALERT" if all_alerts else "NORMAL"
    reason = "; ".join(all_alerts) if all_alerts else "Non-AI Baseline: Cả DeepBlueCLI và Sigma đều đánh giá bình thường."

    return {
        "success": True,
        "pred_label": pred_label,
        "elapsed_seconds": round(db_res["elapsed_seconds"] + sg_res["elapsed_seconds"], 4),
        "stages": all_alerts,
        "evidence_count": len(all_alerts),
        "reason": reason[:140],
        "json_valid": True,
        "error": "",
    }
