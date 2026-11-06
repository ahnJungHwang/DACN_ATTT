"""FastAPI wrapper — cho phép n8n hoặc bất kỳ HTTP client nào gọi analyze_case()."""
import sys

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from analyze import analyze_case, MODELS, MAX_BATCH_CHARS

app = FastAPI(
    title="WinLog AI Agent",
    description="Phân tích Windows Event Log với Local SLM qua Ollama.",
    version="1.0.0",
)


@app.get("/", include_in_schema=False)
def root():
    """Tự động chuyển hướng trang chủ về giao diện SOC Dashboard (/dashboard)."""
    return RedirectResponse(url="/dashboard")


class AnalyzeRequest(BaseModel):
    case_id: str
    model: str = "qwen"
    max_batch_chars: int = MAX_BATCH_CHARS


@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    """
    Phân tích ca log Windows.

    - **case_id**: tên thư mục trong data/ (chỉ dùng chữ, số, _ hoặc -)
    - **model**: `qwen` hoặc `llama`
    - **max_batch_chars**: giới hạn ký tự mỗi lô (mặc định 10000)
    """
    if req.model not in MODELS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown model '{req.model}'. Valid: {list(MODELS.keys())}",
        )
    try:
        result = analyze_case(req.case_id, req.model, req.max_batch_chars)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"I/O error: {exc}")
    return result


@app.get("/health")
def health():
    """Kiểm tra server và các model đã sẵn sàng."""
    return {
        "status": "ok",
        "models": list(MODELS.keys()),
        "max_batch_chars": MAX_BATCH_CHARS,
    }


@app.get("/cases")
def list_cases():
    """Liệt kê các ca dữ liệu có sẵn trong thư mục data/."""
    from pathlib import Path

    data_dir = Path(__file__).resolve().parent / "data"
    if not data_dir.is_dir():
        return {"cases": []}
    cases = [
        d.name
        for d in sorted(data_dir.iterdir())
        if d.is_dir()
    ]
    return {"cases": cases}


class IngestRequest(BaseModel):
    client_id: str = "unknown"
    hostname: str = "unknown"
    security_xml: str = "<Events></Events>"
    powershell_xml: str = "<Events></Events>"
    model: str = "qwen"


import os

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")


def send_server_telegram_alert(verdict: dict, client_id: str, hostname: str, elapsed: float):
    """Gửi cảnh báo phát hiện tấn công từ Client về Telegram."""
    import requests
    from datetime import datetime

    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("[!] Chưa cấu hình TELEGRAM_BOT_TOKEN hoặc TELEGRAM_CHAT_ID. Bỏ qua gửi Telegram.", flush=True)
        return

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    reason = verdict.get("reason", "Phát hiện hành vi tấn công.")
    evidence = verdict.get("evidence_refs", [])
    evidence_str = ", ".join(evidence) if evidence else "N/A"
    stages = verdict.get("detected_stages", [])
    stages_str = ", ".join(stages) if stages else "Không xác định"

    message = (
        f"🚨 *CẢNH BÁO BẢO MẬT TỪ CLIENT* 🚨\n\n"
        f"🖥️ *Máy Client:* `{hostname}` (`{client_id}`)\n"
        f"🕒 *Thời gian:* `{now_str}`\n"
        f"⚠️ *Trạng thái:* *{verdict.get('label', 'ALERT')}*\n"
        f"⏱️ *Thời gian AI xử lý:* {elapsed:.2f}s\n"
        f"🎯 *Giai đoạn:* `{stages_str}`\n\n"
        f"📝 *Chi tiết phát hiện:*\n{reason}\n\n"
        f"🔍 *Bằng chứng:* `{evidence_str}`"
    )

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    try:
        requests.post(
            url,
            json={"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "Markdown"},
            timeout=10,
        )
    except Exception as exc:
        print(f"[!] Lỗi gửi Telegram: {exc}", flush=True)


@app.post("/ingest")
def ingest_logs(req: IngestRequest):
    """
    Nhận log XML từ máy Client (ví dụ 192.168.153.147), phân tích bằng Local SLM
    và tự động gửi cảnh báo Telegram nếu phát hiện tấn công.
    """
    import time
    from pathlib import Path
    from datetime import datetime, timezone
    from analyze import BASE, analyze_case, is_benign_noise, read_events

    clean_client = req.client_id.replace(".", "_").replace(":", "_")
    case_id = f"client_{clean_client}_live"
    case_dir = BASE / "data" / case_id
    case_dir.mkdir(parents=True, exist_ok=True)

    sec_file = case_dir / "security.xml"
    ps_file = case_dir / "powershell.xml"

    sec_file.write_text(req.security_xml, encoding="utf-8")
    ps_file.write_text(req.powershell_xml, encoding="utf-8")

    try:
        events = read_events(case_dir)
        significant = [e for e in events if not is_benign_noise(e)]
        if not significant:
            return {
                "client_id": req.client_id,
                "hostname": req.hostname,
                "analysis_status": "SKIPPED_BENIGN",
                "message": "Toàn bộ sự kiện là tiến trình nền hệ thống lành tính.",
                "verdict": {"label": "NORMAL", "reason": "Chỉ có tiến trình hệ thống thông thường."},
            }
    except ValueError as exc:
        if "No supported events found" in str(exc):
            return {
                "client_id": req.client_id,
                "hostname": req.hostname,
                "analysis_status": "NO_TARGET_EVENTS",
                "message": "Không có sự kiện nằm trong diện theo dõi.",
                "verdict": {"label": "NORMAL", "reason": "Không có sự kiện mục tiêu."},
            }

    started = time.perf_counter()
    print(f"\n[+] Nhan log tu Client {req.hostname} ({req.client_id}) gom {len(events)} su kien.", flush=True)
    print(f"[*] Dang chay Local SLM ({req.model}) phan tich tuong quan...", flush=True)

    try:
        result = analyze_case(case_id, model_key=req.model)
        elapsed = time.perf_counter() - started
    except Exception as exc:
        print(f"[!] Loi phan tich: {exc}", flush=True)
        raise HTTPException(status_code=500, detail=f"Lỗi phân tích: {exc}")

    verdict = result.get("verdict", {})
    label = verdict.get("label", "UNKNOWN")
    print(f"[!] Ket qua AI: {label} ({elapsed:.2f}s)", flush=True)

    if label == "ALERT":
        print(f"[!] PHAT HIEN TAN CONG! Dang ban canh bao ve Telegram...", flush=True)
        send_server_telegram_alert(verdict, req.client_id, req.hostname, elapsed)
        print(f"[✓] Da gui canh bao Telegram thanh cong!", flush=True)

    return {
        "client_id": req.client_id,
        "hostname": req.hostname,
        "elapsed_seconds": round(elapsed, 2),
        "result": result,
    }


from dashboard import setup_dashboard

setup_dashboard(app, telegram_alert_fn=send_server_telegram_alert)

