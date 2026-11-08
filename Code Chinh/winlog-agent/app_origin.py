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
    """Tự động chuyển hướng trang chủ về giao diện tương tác Swagger UI (/docs)."""
    return RedirectResponse(url="/docs")


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

N8N_WEBHOOK_URL = os.getenv("N8N_WEBHOOK_URL", "http://localhost:5678/webhook/windows-log")

_EMPTY_XML = {"", "<Events></Events>", "<Events />"}


def is_request_from_n8n(request: Request) -> bool:
    """Phát hiện request đến từ n8n HTTP Request node (axios) hay từ Client PowerShell."""
    ua = request.headers.get("user-agent", "").lower()
    host = request.headers.get("host", "").lower()
    if request.headers.get("x-n8n-request", "").lower() == "true":
        return True
    if "axios" in ua or "n8n" in ua:
        return True
    if "host.docker.internal" in host:
        return True
    return False


def notify_n8n_clean(client_id: str, hostname: str, model: str) -> tuple[bool, dict]:
    """
    Gửi payload KHÔNG có XML đến n8n Webhook.
    XML đã được lưu vào disk — n8n gọi lại /ingest, app.py đọc từ disk và chạy AI.
    Trả về (success, n8n_response).
    """
    import requests

    payload = {
        "client_id": client_id,
        "hostname": hostname,
        "security_xml": "",       # rỗng — XML đã lưu trên disk
        "powershell_xml": "",     # rỗng — XML đã lưu trên disk
        "model": model,
    }

    candidate_urls = [
        "http://localhost:5678/webhook/windows-log",
        "http://localhost:5678/webhook-test/windows-log",
        "http://127.0.0.1:5678/webhook/windows-log",
        "http://127.0.0.1:5678/webhook-test/windows-log",
    ]

    print(f"[*] Dang kich hoat n8n Workflow (timeout=120s)...", flush=True)
    for url in candidate_urls:
        print(f"    -> Thu: {url}", flush=True)
        try:
            resp = requests.post(url, json=payload, timeout=120)
            if resp.status_code in (200, 201):
                print(f"[✓] n8n da xu ly xong ({url})", flush=True)
                try:
                    return True, resp.json()
                except Exception:
                    return True, {"status": "ok"}
            elif resp.status_code == 500 and "No item to return" in resp.text:
                print(f"[✓] n8n da xu ly xong: Nhanh IF re sang False (NORMAL - khong gui Telegram)", flush=True)
                return True, {"status": "ok", "verdict": {"label": "NORMAL"}}
        except Exception as e:
            print(f"    [x] {url}: {e}", flush=True)
            continue

    print("[!] Khong the ket noi toi n8n. Fallback phan tich truc tiep.", flush=True)
    return False, {}


@app.post("/ingest")
def ingest_logs(req: IngestRequest, request: Request):
    """
    Luồng 2 bước:
    Bước 1 — Client gọi: lưu XML vào disk → gửi payload rỗng đến n8n → đợi n8n trả về.
    Bước 2 — n8n gọi lại: đọc XML từ disk → AI phân tích → trả verdict → n8n IF → Telegram.
    """
    import time
    from analyze import BASE, analyze_case, is_benign_noise, read_events

    clean_client = req.client_id.replace(".", "_").replace(":", "_")
    case_id = f"client_{clean_client}_live"
    case_dir = BASE / "data" / case_id

    # --- Lưu XML vào disk nếu có dữ liệu thực ---
    has_new_xml = False
    sec_count = req.security_xml.count("<Event ") + req.security_xml.count("<Event>")
    ps_count = req.powershell_xml.count("<Event ") + req.powershell_xml.count("<Event>")
    total_events = sec_count + ps_count

    if req.security_xml.strip() not in _EMPTY_XML:
        case_dir.mkdir(parents=True, exist_ok=True)
        (case_dir / "security.xml").write_text(req.security_xml, encoding="utf-8")
        has_new_xml = True
    if req.powershell_xml.strip() not in _EMPTY_XML:
        case_dir.mkdir(parents=True, exist_ok=True)
        (case_dir / "powershell.xml").write_text(req.powershell_xml, encoding="utf-8")
        has_new_xml = True

    from datetime import datetime
    now_str = datetime.now().strftime("%H:%M:%S")

    # ---- BƯỚC 1: Client gọi ----
    if not is_request_from_n8n(request):
        if not has_new_xml:
            return {
                "client_id": req.client_id,
                "hostname": req.hostname,
                "analysis_status": "NO_NEW_DATA",
                "message": "Server san sang, chua co su kien moi.",
                "timestamp": now_str,
            }

        print(f"\n====================================================================", flush=True)
        print(f"[+] [{now_str}] NHAN LOG TU CLIENT: {req.hostname} ({req.client_id})", flush=True)
        print(f"    * Tong so su kien : {total_events} (Security: {sec_count}, PowerShell: {ps_count})", flush=True)
        print(f"    * Da luu vao disk : {case_dir.name}", flush=True)
        print(f"    * Dang chuyen tiep vao n8n Workflow de dieu phoi...", flush=True)

        success, n8n_resp = notify_n8n_clean(req.client_id, req.hostname, req.model)
        if success:
            print(f"    [OK] n8n da xu ly xong! Gui phan hoi xac nhan ve Client.", flush=True)
            print(f"====================================================================", flush=True)
            return {
                "status": "SUCCESS",
                "message": f"Server da nhan {total_events} su kien va dieu phoi qua n8n thanh cong.",
                "events_count": total_events,
                "security_count": sec_count,
                "powershell_count": ps_count,
                "client_id": req.client_id,
                "hostname": req.hostname,
                "timestamp": now_str,
            }
        # n8n không khả dụng → fallback phân tích trực tiếp bên dưới
        print("[*] Fallback: n8n khong phan hoi, server phan tich truc tiep.", flush=True)

    # ---- BƯỚC 2: n8n gọi lại HOẶC fallback → đọc XML từ disk và AI phân tích ----
    if not is_request_from_n8n(request):
        source_label = "Fallback"
    else:
        source_label = "n8n Callback"
    print(f"\n---> [{now_str}] [{source_label}] Bat dau phan tich AI cho {req.hostname} ({req.client_id})...", flush=True)

    if not case_dir.exists():
        return {
            "client_id": req.client_id,
            "hostname": req.hostname,
            "analysis_status": "NO_DATA",
            "verdict": {"label": "NORMAL", "detected_stages": [], "reason": "Chua co du lieu log tren disk.", "evidence_refs": []},
        }

    # Tiền lọc sự kiện nhiễu
    try:
        events = read_events(case_dir)
        significant = [e for e in events if not is_benign_noise(e)]
        if not significant:
            print(f"[-] {req.hostname}: Toan bo su kien lanh tinh.", flush=True)
            return {
                "client_id": req.client_id,
                "hostname": req.hostname,
                "analysis_status": "SKIPPED_BENIGN",
                "verdict": {"label": "NORMAL", "detected_stages": [], "reason": "Chi co tien trinh he thong thong thuong.", "evidence_refs": []},
            }
    except ValueError as exc:
        if "No supported events found" in str(exc):
            return {
                "client_id": req.client_id,
                "hostname": req.hostname,
                "analysis_status": "NO_TARGET_EVENTS",
                "verdict": {"label": "NORMAL", "detected_stages": [], "reason": "Khong co su kien muc tieu.", "evidence_refs": []},
            }

    # Chạy AI
    print(f"[*] [{source_label}] Dang chay Local SLM ({req.model}) voi {len(events)} su kien...", flush=True)
    started = time.perf_counter()
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
        print("[!] PHAT HIEN TAN CONG! Tra ve ket qua cho n8n de gui Telegram...", flush=True)

    # Trả về đúng cấu trúc mà n8n Node IF đọc: {{ $json.verdict.label }}
    return {
        "client_id": req.client_id,
        "hostname": req.hostname,
        "elapsed_seconds": round(elapsed, 2),
        "verdict": {
            "label": label,
            "detected_stages": verdict.get("detected_stages", []),
            "reason": verdict.get("reason", ""),
            "evidence_refs": verdict.get("evidence_refs", []),
        },
    }
