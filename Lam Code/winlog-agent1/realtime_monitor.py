"""
Real-time Windows Event Log Monitor & AI Security Agent
Tự động quét Windows Event Log, phát hiện dấu hiệu bất thường,
phân tích bằng Local SLM (Ollama) và gửi cảnh báo khẩn cấp tới Telegram.
"""
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

import requests

from analyze import (
    BASE,
    MODELS,
    analyze_case,
    is_benign_noise,
    read_events,
)

# ==============================================================================
# CẤU HÌNH HỆ THỐNG
# ==============================================================================
SCAN_INTERVAL_SECONDS = int(os.getenv("SCAN_INTERVAL", "15"))
MODEL_KEY = os.getenv("MODEL", "qwen")

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

REALTIME_CASE_NAME = "realtime_live"
REALTIME_DIR = BASE / "data" / REALTIME_CASE_NAME
REALTIME_DIR.mkdir(parents=True, exist_ok=True)

# ANSI Colors cho terminal
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_RED = "\033[91m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_BLUE = "\033[94m"
C_CYAN = "\033[96m"
C_DIM = "\033[90m"


def log(msg="", **kwargs):
    """In log ra console và flush ngay lập tức."""
    print(msg, flush=True, **kwargs)


def play_alert_sound():
    """Phát âm thanh cảnh báo trên Windows."""
    try:
        import winsound

        winsound.Beep(1200, 300)
        winsound.Beep(1600, 400)
    except Exception:
        sys.stdout.write("\a")
        sys.stdout.flush()


def send_telegram_alert(verdict: dict, event_count: int, elapsed: float):
    """Gửi cảnh báo khẩn cấp tới Telegram bot."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        log(f"{C_YELLOW}[!] Chưa cấu hình Telegram Bot Token hoặc Chat ID.{C_RESET}")
        return

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    reason = verdict.get("reason", "Phát hiện chuỗi sự kiện bất thường.")
    evidence = verdict.get("evidence_refs", [])
    evidence_str = ", ".join(evidence) if evidence else "N/A"

    stages = verdict.get("detected_stages", [])
    stages_str = ", ".join(stages) if stages else "Không xác định"

    message = (
        f"🚨 *CẢNH BÁO BẢO MẬT REAL-TIME* 🚨\n\n"
        f"🕒 *Thời gian:* `{now_str}`\n"
        f"⚠️ *Trạng thái:* *{verdict.get('label', 'ALERT')}*\n"
        f"📊 *Số sự kiện phân tích:* {event_count}\n"
        f"⏱️ *Thời gian AI xử lý:* {elapsed:.2f}s\n"
        f"🎯 *Giai đoạn tấn công:* `{stages_str}`\n\n"
        f"📝 *Chi tiết phát hiện:*\n{reason}\n\n"
        f"🔍 *Bằng chứng (Event Refs):* `{evidence_str}`\n"
        f"🤖 *Mô hình phân tích:* `{MODELS.get(MODEL_KEY, MODEL_KEY)}`"
    )

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown",
    }

    try:
        resp = requests.post(url, json=payload, timeout=10)
        if resp.status_code == 200:
            log(f"{C_GREEN}  [✓] Đã gửi thông báo khẩn cấp tới Telegram thành công!{C_RESET}")
        else:
            log(f"{C_RED}  [✗] Lỗi gửi Telegram ({resp.status_code}): {resp.text}{C_RESET}")
    except Exception as exc:
        log(f"{C_RED}  [✗] Không thể kết nối tới Telegram: {exc}{C_RESET}")


def fetch_events_from_windows(start_utc_iso: str) -> dict:
    """Gọi script PowerShell để trích xuất sự kiện từ mốc thời gian start_utc_iso."""
    ps_script = BASE / "fetch_realtime_events.ps1"
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(ps_script),
        "-StartTimeUtc",
        start_utc_iso,
        "-OutDir",
        str(REALTIME_DIR),
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        output = proc.stdout.strip()
        if output:
            return json.loads(output)
    except Exception as exc:
        log(f"{C_RED}[!] Lỗi trích xuất log Windows: {exc}{C_RESET}")

    return {"security_count": 0, "powershell_count": 0, "latest_utc": start_utc_iso}


def print_banner():
    """In giao diện chào mừng."""
    log(f"{C_CYAN}{C_BOLD}" + "=" * 70)
    log("   🛡️  WINLOG AI AGENT — HỆ THỐNG GIÁM SÁT REAL-TIME CHỐNG TẤN CÔNG")
    log("=" * 70 + f"{C_RESET}")
    log(f" • Mô hình AI         : {C_BOLD}{MODELS.get(MODEL_KEY, MODEL_KEY)}{C_RESET}")
    log(f" • Chu kỳ quét        : {C_BOLD}{SCAN_INTERVAL_SECONDS} giây/lần{C_RESET}")
    log(f" • Kênh cảnh báo      : {C_BOLD}Telegram Bot (Chat ID: {TELEGRAM_CHAT_ID}){C_RESET}")
    log(f" • Thư mục dữ liệu    : {REALTIME_DIR}")
    log(f"{C_CYAN}" + "-" * 70 + f"{C_RESET}")
    log(f"{C_GREEN}[*] Bắt đầu lắng nghe sự kiện từ Windows Event Log...{C_RESET}\n")


def main():
    print_banner()

    # Mốc thời gian bắt đầu quét: 10 giây trước hiện tại
    last_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    scan_round = 0
    while True:
        scan_round += 1
        now_local = datetime.now().strftime("%H:%M:%S")

        # 1. Trích xuất sự kiện mới từ Windows
        fetch_result = fetch_events_from_windows(last_utc)
        sec_count = fetch_result.get("security_count", 0)
        ps_count = fetch_result.get("powershell_count", 0)
        latest_utc = fetch_result.get("latest_utc", last_utc)

        total_new = sec_count + ps_count

        if total_new == 0:
            log(
                f"{C_DIM}[{now_local}] (Lần {scan_round}) Đang giám sát... "
                f"Không có sự kiện mới.{C_RESET}"
            )
        else:
            log(
                f"\n{C_YELLOW}[{now_local}] [PHÁT HIỆN SỰ KIỆN MỚI] "
                f"Security: {sec_count} | PowerShell: {ps_count}{C_RESET}"
            )

            # Cập nhật mốc thời gian để lần sau không đọc lại
            last_utc = latest_utc

            # Đọc và kiểm tra nhanh có sự kiện nào đáng ngờ không
            try:
                raw_events = read_events(REALTIME_DIR)
                significant_events = [e for e in raw_events if not is_benign_noise(e)]

                if not significant_events:
                    log(
                        f"{C_DIM}  [i] Tất cả {total_new} sự kiện đều là tiến trình hệ thống định kỳ (lành tính). Bỏ qua.{C_RESET}"
                    )
                else:
                    log(
                        f"{C_CYAN}  [*] Có {len(significant_events)} sự kiện quan trọng. "
                        f"Đang kích hoạt AI ({MODEL_KEY}) phân tích...{C_RESET}"
                    )

                    start_time = time.perf_counter()
                    result = analyze_case(REALTIME_CASE_NAME, model_key=MODEL_KEY)
                    elapsed = time.perf_counter() - start_time

                    verdict = result.get("verdict", {})
                    label = verdict.get("label", "UNKNOWN")

                    if label == "ALERT":
                        log(f"\n{C_RED}{C_BOLD}" + "!" * 70)
                        log(f"  🚨 PHÁT HIỆN HÀNH VI TẤN CÔNG! (ALERT)")
                        log("!" * 70 + f"{C_RESET}")
                        log(f"{C_RED}  Lý do: {verdict.get('reason')}{C_RESET}")
                        log(f"{C_RED}  Bằng chứng: {verdict.get('evidence_refs')}{C_RESET}")
                        log(f"{C_YELLOW}  Thời gian xử lý: {elapsed:.2f} giây{C_RESET}")

                        # Phát âm thanh cảnh báo & gửi Telegram
                        play_alert_sound()
                        send_telegram_alert(verdict, len(significant_events), elapsed)
                        log(f"{C_RED}" + "!" * 70 + f"\n{C_RESET}")

                    elif label == "NORMAL":
                        log(
                            f"{C_GREEN}  [✓] AI kết luận: NORMAL (Bình thường). Không phát hiện nguy cơ. ({elapsed:.2f}s){C_RESET}\n"
                        )
                    else:
                        log(
                            f"{C_YELLOW}  [?] AI kết luận: {label}. ({elapsed:.2f}s){C_RESET}\n"
                        )

            except ValueError as exc:
                if "No supported events found" in str(exc):
                    log(f"{C_DIM}  [i] Các sự kiện ghi nhận không thuộc nhóm điều tra trọng yếu. Bỏ qua.{C_RESET}")
                else:
                    log(f"{C_RED}  [!] Lỗi dữ liệu sự kiện: {exc}{C_RESET}")
            except Exception as exc:
                log(f"{C_RED}  [!] Lỗi trong quá trình phân tích: {exc}{C_RESET}")

        time.sleep(SCAN_INTERVAL_SECONDS)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log(f"\n{C_YELLOW}[*] Đã dừng hệ thống giám sát. Tạm biệt!{C_RESET}")
