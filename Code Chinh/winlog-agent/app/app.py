"""FastAPI wrapper — cho phép n8n hoặc bất kỳ HTTP client nào gọi analyze_case()."""
import sys

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

# Thư mục gốc winlog-agent (file này nằm trong app/) -> để import core/analyze.py, web/backend/siem.py, dashboard.py
from pathlib import Path as _Path
ROOT = _Path(__file__).resolve().parent.parent
for _p in (ROOT / "core", ROOT / "web" / "backend"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from analyze import analyze_case, MODELS, MAX_BATCH_CHARS
import alerting  # core/alerting.py: chống trùng cảnh báo + đo độ trễ đầu-cuối

DEDUP = alerting.AlertDeduplicator()      # ALERT_DEDUP_MINUTES (mặc định 10 phút)
LATENCY = alerting.LatencyRecorder()      # -> results/latency.csv

app = FastAPI(
    title="WinLog AI Agent",
    description="Phân tích Windows Event Log với Local SLM qua Ollama.",
    version="1.0.0",
)


import siem  # SIEM dashboard: bắt log terminal + sự kiện + cảnh báo -> web

siem.install(app)


@app.get("/", include_in_schema=False)
def root():
    """Trang chủ -> SIEM Dashboard (Swagger UI vẫn ở /docs)."""
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

    data_dir = ROOT / "data"
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
    system_xml: str = "<Events></Events>"  # 7045 / 104 (client mới)
    model: str = "qwen"
    client_sent_utc: str | None = None     # giờ client gửi (đồng hồ máy client) -> bù lệch đồng hồ khi đo độ trễ


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


def find_n8n_webhook_url() -> str:
    """Tự động dò tìm cổng n8n đang hoạt động (5679 hoặc 5678) trong vài mili-giây."""
    import requests

    env_url = os.getenv("N8N_WEBHOOK_URL")
    if env_url:
        return env_url

    # Quét nhanh endpoint /healthz trên các cổng n8n phổ biến (ưu tiên 5679 theo máy khách)
    for port in ("5679", "5678"):
        for host in ("localhost", "127.0.0.1"):
            try:
                resp = requests.get(f"http://{host}:{port}/healthz", timeout=0.8)
                if resp.status_code == 200:
                    return f"http://{host}:{port}/webhook/windows-log"
            except Exception:
                continue

    return "http://localhost:5679/webhook/windows-log"


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

    base_url = find_n8n_webhook_url()
    candidate_urls = [
        base_url,
        base_url.replace("/webhook/", "/webhook-test/"),
    ]
    # Dự phòng cổng đối ứng (5678 <-> 5679)
    alt_port = "5678" if ":5679" in base_url else "5679"
    candidate_urls.append(base_url.replace(":5679", f":{alt_port}").replace(":5678", f":{alt_port}"))
    candidate_urls.append(base_url.replace(":5679", f":{alt_port}").replace(":5678", f":{alt_port}").replace("/webhook/", "/webhook-test/"))

    print(f"[*] Dang kich hoat n8n Workflow (Target URL: {base_url})...", flush=True)
    for url in candidate_urls:
        print(f"    -> Thu: {url}", flush=True)
        try:
            # AI + tu tham dinh co the mat vai phut voi lo lon; het gio som se khien server phan tich lai lan 2
            resp = requests.post(url, json=payload, timeout=600)
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

    from datetime import datetime
    now_str = datetime.now().strftime("%H:%M:%S")
    latency_row = None  # bước 1 gán hàm ghi latency.csv; bước 2 (fallback) dùng lại

    # ---- BƯỚC 1: Client gọi ----
    if not is_request_from_n8n(request):
        sec_valid = req.security_xml.strip() not in _EMPTY_XML
        ps_valid = req.powershell_xml.strip() not in _EMPTY_XML
        sys_valid = req.system_xml.strip() not in _EMPTY_XML

        clean_sec = req.security_xml if sec_valid else "<Events></Events>"
        clean_ps = req.powershell_xml if ps_valid else "<Events></Events>"
        clean_sys = req.system_xml if sys_valid else "<Events></Events>"

        sec_count = clean_sec.count("<Event ") + clean_sec.count("<Event>")
        ps_count = clean_ps.count("<Event ") + clean_ps.count("<Event>")
        sys_count = clean_sys.count("<Event ") + clean_sys.count("<Event>")
        total_events = sec_count + ps_count + sys_count
        # Lô chỉ có log System (vd 7045 cài service) vẫn phải phân tích, không coi là heartbeat
        has_new_xml = (sec_valid or ps_valid or sys_valid) and (total_events > 0)

        if not has_new_xml:
            siem.heartbeat(req.client_id, req.hostname)
            return {
                "client_id": req.client_id,
                "hostname": req.hostname,
                "analysis_status": "NO_NEW_DATA",
                "message": "Server san sang, chua co su kien moi.",
                "timestamp": now_str,
            }

        # Lưu XML thực tế từ Client vào disk cho phiên phân tích này
        case_dir.mkdir(parents=True, exist_ok=True)
        (case_dir / "security.xml").write_text(clean_sec, encoding="utf-8")
        (case_dir / "powershell.xml").write_text(clean_ps, encoding="utf-8")
        (case_dir / "system.xml").write_text(clean_sys, encoding="utf-8")

        siem.record_events(req.client_id, req.hostname, clean_sec, clean_ps)

        # Đo độ trễ: mốc thời gian sinh sự kiện (đồng hồ client) + lúc client gửi + lúc server nhận
        server_recv = alerting.utcnow()
        event_first, event_last = alerting.event_time_range(clean_sec, clean_ps, clean_sys)
        client_sent = alerting.parse_time(req.client_sent_utc)
        LATENCY.pop_analysis(req.client_id)  # bỏ kết quả cũ còn sót (nếu có)

        def _latency_row(path: str, telegram_sent: bool, telegram_date=None) -> dict:
            return LATENCY.record(
                client_id=req.client_id, hostname=req.hostname, model=req.model, path=path,
                events_total=total_events, events_security=sec_count, event_first=event_first,
                event_last=event_last, client_sent=client_sent, server_recv=server_recv,
                done=alerting.utcnow(), analysis=LATENCY.pop_analysis(req.client_id),
                telegram_sent=telegram_sent, telegram_date=telegram_date)
        latency_row = _latency_row

        print(f"\n====================================================================", flush=True)
        print(f"[+] [{now_str}] NHAN LOG TU CLIENT: {req.hostname} ({req.client_id})", flush=True)
        print(f"    * Tong so su kien : {total_events} (Security: {sec_count}, PowerShell: {ps_count}, System: {sys_count})", flush=True)
        print(f"    * Da luu vao disk : {case_dir.name}", flush=True)
        print(f"    * Dang chuyen tiep vao n8n Workflow de dieu phoi...", flush=True)

        success, n8n_resp = notify_n8n_clean(req.client_id, req.hostname, req.model)
        if success:
            # n8n (responseMode = lastNode) chỉ trả lời SAU khi node Telegram chạy xong
            # -> lúc này = lúc cảnh báo đã gửi tới Telegram. Node Telegram trả về message_id + date.
            tg = n8n_resp if isinstance(n8n_resp, dict) else {}
            tg = tg.get("result", tg) if isinstance(tg.get("result"), dict) else tg
            telegram_sent = bool(tg.get("message_id"))
            tg_date = None
            if isinstance(tg.get("date"), (int, float)):
                from datetime import datetime as _dt, timezone as _tz
                tg_date = _dt.fromtimestamp(tg["date"], _tz.utc)
            lat = latency_row("n8n", telegram_sent, tg_date)
            _print_latency(lat)
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
                "label": lat.get("label", ""),
                "alert_status": lat.get("alert_status", ""),
                "telegram_sent": telegram_sent,
                "latency": {k: lat.get(k) for k in ("e2e_from_first_s", "e2e_from_last_s", "collect_s", "ai_s", "notify_s")},
            }
        # n8n không khả dụng → fallback phân tích trực tiếp bên dưới
        print("[*] Fallback: n8n khong phan hoi, server phan tich truc tiep.", flush=True)

    # ---- BƯỚC 2: n8n gọi lại HOẶC fallback → đọc XML từ disk và AI phân tích ----
    fallback = not is_request_from_n8n(request)
    source_label = "Fallback" if fallback else "n8n Callback"
    print(f"\n---> [{now_str}] [{source_label}] Bat dau phan tich AI cho {req.hostname} ({req.client_id})...", flush=True)
    ai_start = alerting.utcnow()

    def _clear_disk_xml():
        # Xoá XML ngay sau khi đã đọc để KHÔNG bao giờ phân tích lặp lại (cả system.xml: 7045 / 104)
        for name in ("security.xml", "powershell.xml", "system.xml"):
            try:
                (case_dir / name).write_text("<Events></Events>", encoding="utf-8")
            except Exception:
                pass

    def _finish(resp: dict, label: str, alert: dict | None = None) -> dict:
        """Ghi mốc thời gian AI cho bước 1 ghép thành 1 dòng latency.csv; fallback thì ghi luôn."""
        alert = alert or {"status": "NOT_ALERT", "notify": False}
        LATENCY.set_analysis(req.client_id, label=label, alert_status=alert["status"],
                             ai_start=ai_start, ai_done=alerting.utcnow())
        resp["notify"] = alert["notify"]
        resp["alert"] = alert
        if fallback and latency_row is not None:
            lat = latency_row("fallback", False)  # không có n8n -> không có Telegram
            _print_latency(lat)
            resp["latency"] = {k: lat.get(k) for k in ("e2e_from_first_s", "e2e_from_last_s", "collect_s", "ai_s", "notify_s")}
        return resp

    if not case_dir.exists():
        return _finish({
            "client_id": req.client_id,
            "hostname": req.hostname,
            "analysis_status": "NO_DATA",
            "verdict": {"label": "NORMAL", "detected_stages": [], "reason": "Chua co du lieu log tren disk.", "evidence_refs": []},
        }, "NORMAL")

    # Tiền lọc sự kiện nhiễu
    try:
        events = read_events(case_dir)
        significant = [e for e in events if not is_benign_noise(e)]
        if not significant:
            print(f"[-] {req.hostname}: Toan bo su kien lanh tinh.", flush=True)
            siem.record_verdict(req.client_id, req.hostname, {"label": "NORMAL", "reason": "Chi co tien trinh he thong thong thuong."}, status="SKIPPED_BENIGN", model=req.model)
            _clear_disk_xml()
            return _finish({
                "client_id": req.client_id,
                "hostname": req.hostname,
                "analysis_status": "SKIPPED_BENIGN",
                "verdict": {"label": "NORMAL", "detected_stages": [], "reason": "Chi co tien trinh he thong thong thuong.", "evidence_refs": []},
            }, "NORMAL")
    except ValueError as exc:
        if "No supported events found" in str(exc):
            _clear_disk_xml()
            return _finish({
                "client_id": req.client_id,
                "hostname": req.hostname,
                "analysis_status": "NO_TARGET_EVENTS",
                "verdict": {"label": "NORMAL", "detected_stages": [], "reason": "Khong co su kien muc tieu.", "evidence_refs": []},
            }, "NORMAL")
        raise HTTPException(status_code=400, detail=f"Log khong hop le: {exc}")

    # Chạy AI
    print(f"[*] [{source_label}] Dang chay Local SLM ({req.model}) voi {len(events)} su kien...", flush=True)
    started = time.perf_counter()
    try:
        result = analyze_case(case_id, model_key=req.model)
        elapsed = time.perf_counter() - started
    except Exception as exc:
        print(f"[!] Loi phan tich: {exc}", flush=True)
        raise HTTPException(status_code=500, detail=f"Lỗi phân tích: {exc}")
    _clear_disk_xml()

    verdict = result.get("verdict", {})
    label = verdict.get("label", "UNKNOWN")
    print(f"[!] Ket qua AI: {label} ({elapsed:.2f}s)", flush=True)

    siem.record_verdict(req.client_id, req.hostname, verdict, elapsed=round(elapsed, 2), model=req.model)

    # Chống trùng: cùng máy + cùng kỹ thuật MITRE trong ALERT_DEDUP_MINUTES phút -> không gửi Telegram lại
    alert = DEDUP.check(req.client_id, req.hostname, verdict, model=req.model)
    if label == "ALERT" and alert["notify"]:
        tag = "SU CO MOI" if alert["status"] == "NEW" else "THEM KY THUAT MOI " + ", ".join(alert["new_techniques"])
        print(f"[!] PHAT HIEN TAN CONG ({tag}) {', '.join(alert['incident_ids'])} -> gui Telegram qua n8n", flush=True)
    elif label == "ALERT":
        print(f"[=] Canh bao TRUNG {', '.join(alert['incident_ids'])} (lan {alert['repeat_count']} trong "
              f"{alert['window_minutes']:g} phut) -> KHONG gui Telegram lai", flush=True)

    # n8n Node IF đọc {{ $json.verdict.label }} == "ALERT" -> Telegram.
    # Cảnh báo trùng trả nhãn "ALERT_DUPLICATE" cho n8n để IF rẽ False (không cần sửa workflow);
    # nhãn thật vẫn ở "true_label", trong SIEM và results/alerts_log.csv.
    n8n_label = "ALERT_DUPLICATE" if (label == "ALERT" and not alert["notify"]) else label
    return _finish({
        "client_id": req.client_id,
        "hostname": req.hostname,
        "elapsed_seconds": round(elapsed, 2),
        "true_label": label,
        "verdict": {
            "label": n8n_label,
            "detected_stages": verdict.get("detected_stages", []),
            "reason": verdict.get("reason", ""),
            "evidence_refs": verdict.get("evidence_refs", []),
            "decision_source": verdict.get("decision_source", ""),  # rule+ai / ai / rule (hien trong tin Telegram)
            "incident_ids": alert.get("incident_ids", []),
        },
    }, label, alert)


def _print_latency(lat: dict) -> None:
    """In tóm tắt độ trễ đầu-cuối ra terminal server (chi tiết trong results/latency.csv)."""
    if not lat or lat.get("e2e_from_first_s") in ("", None):
        return
    tg = "da gui Telegram" if lat.get("telegram_sent") in (True, "True") else "khong gui Telegram"
    print(f"    [T] Do tre: su kien -> xong = {lat['e2e_from_first_s']}s (tu su kien cuoi: {lat['e2e_from_last_s']}s)"
          f" | client gom: {lat.get('collect_s')}s | AI: {lat.get('ai_s')}s | n8n/Telegram: {lat.get('notify_s')}s"
          f" | {lat.get('label')} {lat.get('alert_status')} | {tg}", flush=True)
