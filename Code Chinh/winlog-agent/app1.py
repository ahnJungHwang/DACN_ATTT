"""FastAPI wrapper — cho phép n8n hoặc bất kỳ HTTP client nào gọi analyze_case()."""
import sys

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

from fastapi import FastAPI, HTTPException, Request
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

N8N_WEBHOOK_URL = os.getenv("N8N_WEBHOOK_URL", "http://127.0.0.1:5679/webhook/windows-log")


def is_request_from_n8n(request: Request) -> bool:
    """Kiểm tra xem request này có phải do n8n container gọi đến hay không."""
    user_agent = request.headers.get("user-agent", "").lower()
    host_header = request.headers.get("host", "").lower()
    custom_flag = request.headers.get("x-n8n-request", "").lower()

    if custom_flag == "true":
        return True
    if "axios" in user_agent or "n8n" in user_agent:
        return True
    if "host.docker.internal" in host_header:
        return True
    return False


def forward_log_to_n8n(payload: dict) -> tuple[bool, dict]:
    """Chuyển tiếp gói log từ Client vào n8n Webhook (windows-log)."""
    import requests

    target_urls = [
        N8N_WEBHOOK_URL,
        "http://127.0.0.1:5679/webhook/windows-log",
        "http://127.0.0.1:5678/webhook/windows-log",
        "http://127.0.0.1:5679/webhook-test/windows-log",
        "http://127.0.0.1:5678/webhook-test/windows-log",
    ]
    seen = set()
    urls = []
    for u in target_urls:
        if u and u not in seen:
            seen.add(u)
            urls.append(u)

    print(f"[*] Dang chuyen tiep log vao n8n Webhook ({urls[0]})...", flush=True)

    for url in urls:
        try:
            resp = requests.post(url, json=payload, timeout=600)
            if resp.status_code in (200, 201):
                print(f"[✓] n8n Webhook da tiep nhan thanh cong tai: {url}", flush=True)
                try:
                    return True, resp.json()
                except Exception:
                    return True, {"status": "ok", "message": "n8n workflow executed successfully"}
        except Exception:
            continue

    return False, {}


@app.post("/ingest")
def ingest_logs(req: IngestRequest, request: Request):
    """
    Endpoint tiếp nhận log:
    - Nếu Client gọi: tự động chuyển tiếp log vào n8n Webhook (windows-log) để n8n điều phối toàn bộ workflow.
    - Nếu n8n gọi: phân tích bằng Local SLM (Ollama) và trả về kết cấu JSON chuẩn cho các Node của n8n.
    """
    import time
    from pathlib import Path
    from datetime import datetime, timezone
    from analyze import BASE, analyze_case, is_benign_noise, read_events

    # 1. Nếu Client đẩy log lên Server: chuyển tiếp cho n8n xử lý
    if not is_request_from_n8n(request):
        print(f"\n[+] Nhan log tu Client {req.hostname} ({req.client_id}).", flush=True)
        print(f"[*] Chuyen tiep log vao n8n Workflow (windows-log) de n8n dieu phoi...", flush=True)
        success, n8n_response = forward_log_to_n8n({
            "client_id": req.client_id,
            "hostname": req.hostname,
            "security_xml": req.security_xml,
            "powershell_xml": req.powershell_xml,
            "model": req.model,
        })
        if success:
            print(f"[✓] Luong n8n da thuc thi va dieu phoi thanh cong!", flush=True)
            return n8n_response
        else:
            print(f"[!] Khong the ket noi toi n8n Webhook. Chuyen sang phan tich truc tiep bang Local SLM...", flush=True)

    # 2. Xử lý phân tích AI (khi n8n gọi hoặc khi chạy chế độ dự phòng trực tiếp)
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
            print(f"[-] Client {req.hostname}: Toan bo su kien la tien trinh he thong lanh tinh (BENIGN).", flush=True)
            return {
                "client_id": req.client_id,
                "hostname": req.hostname,
                "analysis_status": "SKIPPED_BENIGN",
                "message": "Toàn bộ sự kiện là tiến trình nền hệ thống lành tính.",
                "verdict": {
                    "label": "NORMAL",
                    "detected_stages": [],
                    "reason": "Chỉ có tiến trình hệ thống thông thường.",
                    "evidence_refs": [],
                },
            }
    except ValueError as exc:
        if "No supported events found" in str(exc):
            return {
                "client_id": req.client_id,
                "hostname": req.hostname,
                "analysis_status": "NO_TARGET_EVENTS",
                "message": "Không có sự kiện nằm trong diện theo dõi.",
                "verdict": {
                    "label": "NORMAL",
                    "detected_stages": [],
                    "reason": "Không có sự kiện mục tiêu.",
                    "evidence_refs": [],
                },
            }

    started = time.perf_counter()
    print(f"\n[+] n8n dang yeu cau phan tich log tu Client {req.hostname} ({req.client_id}) gom {len(events)} su kien.", flush=True)
    print(f"[*] Dang chay Local SLM ({req.model}) phan tich tuong quan...", flush=True)

    try:
        result = analyze_case(case_id, model_key=req.model)
        elapsed = time.perf_counter() - started
    except Exception as exc:
        print(f"[!] Loi phan tich: {exc}", flush=True)
        raise HTTPException(status_code=500, detail=f"Lỗi phân tích: {exc}")

    verdict = result.get("verdict", {})
    label = verdict.get("label", "UNKNOWN")
    detected_stages = verdict.get("detected_stages", [])
    reason = verdict.get("reason", "")
    evidence_refs = verdict.get("evidence_refs", [])

    print(f"[!] Ket qua AI: {label} ({elapsed:.2f}s)", flush=True)
    if label == "ALERT":
        print(f"[!] PHAT HIEN TAN CONG! Tra ve ket qua cho n8n de ban canh bao Telegram...", flush=True)

    # Đảm bảo trả về đúng các trường mà n8n Workflow của bạn truy xuất:
    # {{ $json.verdict.label }}, {{ $json.hostname }}, {{ $json.client_id }},
    # {{ $json.verdict.detected_stages }}, {{ $json.verdict.reason }}, {{ $json.verdict.evidence_refs }}
    return {
        "client_id": req.client_id,
        "hostname": req.hostname,
        "verdict": {
            "label": label,
            "detected_stages": detected_stages,
            "reason": reason,
            "evidence_refs": evidence_refs,
        },
        "elapsed_seconds": round(elapsed, 2),
        "result": result,
    }


from dashboard import setup_dashboard

setup_dashboard(app)

