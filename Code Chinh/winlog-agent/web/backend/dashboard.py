"""Giao diện Web SOC Dashboard & API quản trị thời gian thực cho WinLog AI Agent."""
from __future__ import annotations

import csv
import io
import json
import sys
import time
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from fastapi import APIRouter, FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "core"))  # winlog-agent/core -> analyze.py
from analyze import BASE, MAX_BATCH_CHARS, MODELS, analyze_case

router = APIRouter()

# Bộ nhớ đệm lưu trực tiếp các dòng in ra console của Server (PowerShell / Uvicorn stdout)
CONSOLE_BUFFER: deque[dict[str, str]] = deque(maxlen=400)

# Cache đọc file JSON kết quả theo (path, mtime) để phản hồi API trong vài mili-giây
_RESULTS_FILE_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}


def log_to_console_buffer(msg: str, source: str = "SERVER") -> None:
    """Ghi một dòng nhật ký vào bộ nhớ đệm để hiển thị trực tiếp lên Web Terminal."""
    clean = msg.strip("\r\n")
    if not clean:
        return
    ts = datetime.now().strftime("%H:%M:%S")
    level = "INFO"
    if "[!]" in clean or "ALERT" in clean or "TAN CONG" in clean or "Lỗi" in clean or "Loi" in clean:
        level = "ALERT"
    elif "[✓]" in clean or "NORMAL" in clean or "thanh cong" in clean.lower():
        level = "SUCCESS"
    elif "[*]" in clean or "[+]" in clean:
        level = "ACTION"

    CONSOLE_BUFFER.append(
        {
            "time": ts,
            "source": source,
            "level": level,
            "text": clean,
        }
    )


class _StdoutTee(io.TextIOBase):
    """Bắt mọi lệnh print() trên Server đẩy vào CONSOLE_BUFFER mà vẫn in ra PowerShell bình thường."""

    def __init__(self, orig_stream: Any):
        self._orig = orig_stream
        self._line_buf = ""

    def write(self, s: str) -> int:
        try:
            self._orig.write(s)
        except Exception:
            pass
        if s:
            self._line_buf += s
            while "\n" in self._line_buf:
                line, self._line_buf = self._line_buf.split("\n", 1)
                if line.strip():
                    log_to_console_buffer(line, source="AI-SERVER")
        return len(s)

    def flush(self) -> None:
        try:
            self._orig.flush()
        except Exception:
            pass

    def __getattr__(self, name: str) -> Any:
        return getattr(self._orig, name)


def install_stdout_tee() -> None:
    """Kích hoạt bộ bắt luồng stdout nếu chưa gắn."""
    if not isinstance(sys.stdout, _StdoutTee):
        sys.stdout = _StdoutTee(sys.stdout)
        log_to_console_buffer("[+] Hệ thống WinLog AI SOC Dashboard đã khởi động và sẵn sàng giám sát.", "SYSTEM")


def _parse_run_timestamp(filename: str, fallback_mtime: float) -> str:
    """Trích xuất thời gian từ tên file <model>_20261102T180705861952Z.json."""
    stem = Path(filename).stem
    parts = stem.split("_", 1)
    if len(parts) == 2:
        raw_ts = parts[1]
        for fmt in ("%Y%m%dT%H%M%S%fZ", "%Y%m%dT%H%M%SZ"):
            try:
                dt = datetime.strptime(raw_ts, fmt)
                return dt.strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                pass
    return datetime.fromtimestamp(fallback_mtime).strftime("%Y-%m-%d %H:%M:%S")


def _scan_results_summary(limit: int = 80) -> dict[str, Any]:
    """Quét thư mục results/ để tổng hợp KPI và danh sách các phiên phân tích gần nhất."""
    results_dir = BASE / "results"
    all_files: list[ tuple[float, Path, str] ] = []

    if results_dir.is_dir():
        for case_dir in results_dir.iterdir():
            if not case_dir.is_dir():
                continue
            for jf in case_dir.glob("*.json"):
                try:
                    mtime = jf.stat().st_mtime
                    all_files.append((mtime, jf, case_dir.name))
                except OSError:
                    continue

    all_files.sort(key=lambda x: x[0], reverse=True)

    total_runs = len(all_files)
    alert_count = 0
    normal_count = 0
    latencies: list[float] = []
    recent_runs: list[dict[str, Any]] = []

    # Đọc toàn bộ file với bộ nhớ đệm _RESULTS_FILE_CACHE (chỉ đọc ổ đĩa khi có file mới)
    for idx, (mtime, jf, folder_name) in enumerate(all_files):
        cache_key = str(jf)
        cached = _RESULTS_FILE_CACHE.get(cache_key)
        if cached and cached[0] == mtime:
            summary_item = cached[1]
        else:
            try:
                payload = json.loads(jf.read_text(encoding="utf-8"))
            except Exception:
                continue
            res = payload.get("result", {})
            verdict = res.get("verdict", {})
            events = payload.get("events", [])
            host = events[0].get("host", "Local/Sim") if events else "Local/Sim"
            summary_item = {
                "folder": folder_name,
                "file": jf.name,
                "timestamp": _parse_run_timestamp(jf.name, mtime),
                "case_id": res.get("case_id", folder_name),
                "host": host,
                "model": res.get("model", jf.stem.split("_")[0]),
                "label": str(verdict.get("label", "NORMAL")).upper(),
                "elapsed_seconds": round(float(res.get("elapsed_seconds") or 0.0), 2),
                "raw_event_count": res.get("raw_event_count", len(events)),
                "analyzed_event_count": res.get("analyzed_event_count", len(events)),
                "detected_stages": verdict.get("detected_stages", []),
                "reason": verdict.get("reason", ""),
                "evidence_refs": verdict.get("evidence_refs", []),
            }
            _RESULTS_FILE_CACHE[cache_key] = (mtime, summary_item)

        if summary_item["label"] == "ALERT":
            alert_count += 1
        else:
            normal_count += 1

        if summary_item["elapsed_seconds"] > 0:
            latencies.append(summary_item["elapsed_seconds"])

        if idx < limit:
            recent_runs.append(summary_item)

    avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else 0.0
    return {
        "stats": {
            "total_runs": total_runs,
            "sampled_runs": total_runs,
            "alert_count": alert_count,
            "normal_count": normal_count,
            "avg_latency": avg_latency,
        },
        "recent_runs": recent_runs,
    }


def _read_powershell_client_log(max_lines: int = 80) -> list[dict[str, str]]:
    """Đọc các dòng mới nhất từ client_agent.log (nếu có trên máy)."""
    log_path = BASE / "client_agent.log"
    if not log_path.is_file():
        return []
    try:
        lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []

    out: list[dict[str, str]] = []
    for raw in lines[-max_lines:]:
        clean = raw.strip()
        if not clean:
            continue
        level = "INFO"
        if "ALERT" in clean or "LOI" in clean.upper() or "[!]" in clean:
            level = "ALERT"
        elif "NORMAL" in clean or "OK" in clean:
            level = "SUCCESS"
        out.append(
            {
                "time": clean[1:20] if clean.startswith("[") and "]" in clean else "",
                "source": "PS-CLIENT",
                "level": level,
                "text": clean,
            }
        )
    return out


@router.get("/api/dashboard/overview")
def api_dashboard_overview() -> dict[str, Any]:
    """API cung cấp toàn bộ dữ liệu thời gian thực cho giao diện SOC Dashboard."""
    summary = _scan_results_summary(limit=60)
    ps_logs = _read_powershell_client_log(max_lines=60)
    srv_logs = list(CONSOLE_BUFFER)

    # Nếu bộ nhớ đệm mới khởi động chưa có nhiều dòng, bổ sung lịch sử tóm tắt từ các ca chạy gần nhất
    synthetic_logs: list[dict[str, str]] = []
    if len(srv_logs) <= 2 and summary["recent_runs"]:
        for r in reversed(summary["recent_runs"][:15]):
            tag = "[!] PHÁT HIỆN TẤN CÔNG (ALERT)" if r["label"] == "ALERT" else "[✓] An toàn (NORMAL)"
            lvl = "ALERT" if r["label"] == "ALERT" else "SUCCESS"
            stages = ", ".join(r["detected_stages"]) if r["detected_stages"] else "None"
            synthetic_logs.append(
                {
                    "time": r["timestamp"].split(" ")[-1],
                    "source": "HISTORY",
                    "level": lvl,
                    "text": f"{tag} | Case: {r['case_id']} | Host: {r['host']} | Model: {r['model']} ({r['elapsed_seconds']}s) | Stages: {stages}",
                }
            )

    return {
        "server_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "models": MODELS,
        "stats": summary["stats"],
        "recent_runs": summary["recent_runs"],
        "console_logs": synthetic_logs + ps_logs + srv_logs,
    }


@router.get("/api/dashboard/run-detail")
def api_dashboard_run_detail(
    folder: str = Query(..., description="Tên thư mục ca phân tích trong results/"),
    file: str = Query(..., description="Tên file JSON kết quả"),
) -> dict[str, Any]:
    """Lấy toàn bộ chi tiết sự kiện Windows Event Log và kết luận AI của một phiên phân tích."""
    results_dir = (BASE / "results").resolve()
    target = (results_dir / folder / file).resolve()
    if results_dir not in target.parents or not target.is_file():
        raise HTTPException(status_code=404, detail="Không tìm thấy bản ghi kết quả.")
    try:
        return json.loads(target.read_text(encoding="utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Lỗi đọc file JSON: {exc}")


@router.get("/api/dashboard/cases")
def api_dashboard_cases() -> dict[str, Any]:
    """Liệt kê toàn bộ kịch bản kiểm thử trong data01/ và data/ kèm manifest."""
    datasets: list[dict[str, Any]] = []
    for ds_name in ("data01", "data"):
        ds_dir = BASE / ds_name
        if not ds_dir.is_dir():
            continue
        for cdir in sorted(ds_dir.iterdir()):
            if not cdir.is_dir():
                continue
            manifest_path = cdir / "manifest.json"
            meta: dict[str, Any] = {}
            if manifest_path.is_file():
                try:
                    meta = json.loads(manifest_path.read_text(encoding="utf-8"))
                except Exception:
                    meta = {}
            datasets.append(
                {
                    "dataset": ds_name,
                    "case_id": cdir.name,
                    "category": meta.get("category", "Live/Custom"),
                    "ground_truth": meta.get("ground_truth", "UNKNOWN"),
                    "actions": meta.get("actions", "Tập dữ liệu log Windows Security & PowerShell."),
                    "expected_stages": meta.get("expected_stages", []),
                }
            )
    return {"cases": datasets}


class RunCaseRequest(BaseModel):
    dataset: str = "data01"
    case_id: str
    model: str = "qwen"
    send_telegram: bool = False


@router.get("/api/dashboard/benchmark")
def api_dashboard_benchmark() -> dict[str, Any]:
    """Đọc kết quả đánh giá tổng hợp từ comparison_summary.csv và comparison_details.csv."""
    results_dir = BASE / "results"
    summary_rows: list[dict[str, str]] = []
    detail_rows: list[dict[str, str]] = []

    sum_csv = results_dir / "comparison_summary.csv"
    if sum_csv.is_file():
        try:
            with sum_csv.open("r", encoding="utf-8-sig") as f:
                summary_rows = list(csv.DictReader(f))
        except Exception:
            pass

    det_csv = results_dir / "comparison_details.csv"
    if det_csv.is_file():
        try:
            with det_csv.open("r", encoding="utf-8-sig") as f:
                detail_rows = list(csv.DictReader(f))
        except Exception:
            pass

    return {
        "summary": summary_rows,
        "details": detail_rows,
    }


def setup_dashboard(app: FastAPI, telegram_alert_fn: Callable[[dict, str, str, float], None] | None = None) -> None:
    """Tích hợp SOC Dashboard và các API điều khiển vào ứng dụng FastAPI."""
    install_stdout_tee()
    app.include_router(router)

    @app.post("/api/dashboard/run-case")
    def api_run_case(req: RunCaseRequest) -> dict[str, Any]:
        if req.dataset not in ("data", "data01"):
            raise HTTPException(status_code=400, detail="Dataset chỉ hỗ trợ 'data' hoặc 'data01'.")
        if req.model not in MODELS:
            raise HTTPException(status_code=400, detail=f"Model không hợp lệ. Hỗ trợ: {list(MODELS.keys())}")

        target_data_dir = BASE / req.dataset
        print(f"[*] [WEB-SOC] Bắt đầu phân tích kịch bản '{req.dataset}/{req.case_id}' bằng model '{req.model}'...", flush=True)
        started = time.perf_counter()
        try:
            result = analyze_case(
                req.case_id,
                model_key=req.model,
                max_batch_chars=MAX_BATCH_CHARS,
                data_dir=target_data_dir,
            )
            elapsed = time.perf_counter() - started
        except Exception as exc:
            print(f"[!] [WEB-SOC] Lỗi phân tích kịch bản '{req.case_id}': {exc}", flush=True)
            raise HTTPException(status_code=500, detail=str(exc))

        verdict = result.get("verdict", {})
        label = verdict.get("label", "NORMAL")
        print(
            f"[!] [WEB-SOC] Hoàn tất '{req.case_id}' -> Kết luận: {label} ({elapsed:.2f}s) | Lý do: {verdict.get('reason', '')[:120]}",
            flush=True,
        )

        if req.send_telegram and label == "ALERT" and telegram_alert_fn is not None:
            print(f"[!] [WEB-SOC] Đang gửi cảnh báo Telegram cho kịch bản '{req.case_id}'...", flush=True)
            telegram_alert_fn(verdict, "WEB-SIMULATOR", req.case_id, elapsed)
            print(f"[✓] [WEB-SOC] Đã gửi cảnh báo Telegram thành công!", flush=True)

        return {
            "status": "ok",
            "elapsed_seconds": round(elapsed, 2),
            "result": result,
        }

    @app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
    def dashboard_page() -> HTMLResponse:
        return HTMLResponse(content=DASHBOARD_HTML)


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>WinLog AI SOC — Trung Tâm Giám Sát An Ninh Mạng</title>
  <style>
    :root {
      --bg-main: #090d16;
      --bg-panel: #111827;
      --bg-card: #161f33;
      --bg-terminal: #060911;
      --border: #24324d;
      --text-main: #e2e8f0;
      --text-muted: #94a3b8;
      --accent-blue: #38bdf8;
      --accent-indigo: #6366f1;
      --alert-red: #ef4444;
      --alert-bg: rgba(239, 68, 68, 0.14);
      --ok-green: #10b981;
      --ok-bg: rgba(16, 185, 129, 0.14);
      --warn-amber: #f59e0b;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Segoe UI', Inter, system-ui, -apple-system, sans-serif;
      background: var(--bg-main);
      color: var(--text-main);
      min-height: 100vh;
      line-height: 1.5;
    }
    /* Header */
    .topbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 14px 24px;
      background: rgba(17, 24, 39, 0.92);
      border-bottom: 1px solid var(--border);
      position: sticky;
      top: 0;
      z-index: 50;
      backdrop-filter: blur(10px);
      flex-wrap: wrap;
      gap: 12px;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .brand-icon {
      width: 40px;
      height: 40px;
      border-radius: 10px;
      background: linear-gradient(135deg, #2563eb, #06b6d4);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 20px;
      font-weight: 800;
      box-shadow: 0 0 18px rgba(56, 189, 248, 0.35);
    }
    .brand-title h1 {
      font-size: 18px;
      font-weight: 700;
      letter-spacing: 0.3px;
      color: #f8fafc;
    }
    .brand-title p {
      font-size: 12px;
      color: var(--text-muted);
    }
    .topbar-controls {
      display: flex;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
    }
    .pill {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      padding: 6px 12px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 600;
      background: var(--bg-card);
      border: 1px solid var(--border);
      color: var(--text-main);
    }
    .dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--ok-green);
      box-shadow: 0 0 8px var(--ok-green);
      animation: pulse 2s infinite;
    }
    @keyframes pulse {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.55; transform: scale(1.2); }
    }
    .btn {
      cursor: pointer;
      border: 1px solid var(--border);
      background: var(--bg-card);
      color: var(--text-main);
      padding: 7px 14px;
      border-radius: 8px;
      font-size: 13px;
      font-weight: 600;
      transition: all 0.15s ease;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }
    .btn:hover { border-color: var(--accent-blue); color: #fff; }
    .btn-primary {
      background: linear-gradient(135deg, #2563eb, #0284c7);
      border-color: #38bdf8;
      color: #fff;
    }
    .btn-primary:hover { filter: brightness(1.12); }

    /* Container */
    .container {
      max-width: 1560px;
      margin: 0 auto;
      padding: 20px 24px 48px;
    }

    /* KPI Row */
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
      gap: 16px;
      margin-bottom: 20px;
    }
    .kpi-card {
      background: var(--bg-panel);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 16px 20px;
      position: relative;
      overflow: hidden;
    }
    .kpi-card .label {
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.6px;
      color: var(--text-muted);
      font-weight: 600;
    }
    .kpi-card .value {
      font-size: 28px;
      font-weight: 800;
      margin-top: 6px;
      color: #f8fafc;
    }
    .kpi-card .sub {
      font-size: 12px;
      color: var(--text-muted);
      margin-top: 4px;
    }
    .kpi-card.alert-card { border-left: 4px solid var(--alert-red); }
    .kpi-card.alert-card .value { color: #f87171; }
    .kpi-card.ok-card { border-left: 4px solid var(--ok-green); }
    .kpi-card.ok-card .value { color: #34d399; }
    .kpi-card.info-card { border-left: 4px solid var(--accent-blue); }
    .kpi-card.latency-card { border-left: 4px solid var(--warn-amber); }

    /* Tabs */
    .tabs {
      display: flex;
      gap: 8px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 20px;
      flex-wrap: wrap;
    }
    .tab-btn {
      background: transparent;
      border: none;
      color: var(--text-muted);
      padding: 10px 18px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      border-bottom: 2px solid transparent;
      transition: all 0.15s;
    }
    .tab-btn:hover { color: var(--text-main); }
    .tab-btn.active {
      color: var(--accent-blue);
      border-bottom-color: var(--accent-blue);
      background: rgba(56, 189, 248, 0.06);
      border-radius: 8px 8px 0 0;
    }
    .tab-content { display: none; }
    .tab-content.active { display: block; }

    /* Split layout for Live Monitor */
    .live-grid {
      display: grid;
      grid-template-columns: 1fr;
      gap: 20px;
    }
    @media (min-width: 1120px) {
      .live-grid {
        grid-template-columns: 5fr 7fr;
      }
    }

    .panel {
      background: var(--bg-panel);
      border: 1px solid var(--border);
      border-radius: 12px;
      overflow: hidden;
      display: flex;
      flex-direction: column;
    }
    .panel-header {
      padding: 12px 16px;
      background: var(--bg-card);
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      flex-wrap: wrap;
    }
    .panel-title {
      font-size: 14px;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    /* PowerShell Terminal Box */
    .terminal-window {
      background: var(--bg-terminal);
      font-family: 'Cascadia Code', Consolas, 'Courier New', monospace;
      font-size: 12.5px;
      padding: 14px;
      height: 540px;
      overflow-y: auto;
      color: #cbd5e1;
    }
    .term-line {
      padding: 3px 0;
      border-bottom: 1px dashed rgba(255,255,255,0.04);
      word-break: break-word;
    }
    .term-time { color: #64748b; margin-right: 6px; }
    .term-src {
      display: inline-block;
      padding: 1px 6px;
      border-radius: 4px;
      font-size: 10.5px;
      font-weight: 700;
      margin-right: 6px;
      background: #1e293b;
      color: #93c5fd;
    }
    .term-line.ALERT { color: #fca5a5; background: rgba(239, 68, 68, 0.08); padding-left: 6px; border-left: 3px solid var(--alert-red); }
    .term-line.SUCCESS { color: #6ee7b7; }
    .term-line.ACTION { color: #38bdf8; }

    /* Table */
    .table-wrap {
      overflow-x: auto;
      max-height: 540px;
      overflow-y: auto;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }
    th {
      position: sticky;
      top: 0;
      background: #1a2438;
      color: var(--text-muted);
      text-align: left;
      padding: 10px 12px;
      font-size: 11.5px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      border-bottom: 1px solid var(--border);
      z-index: 5;
    }
    td {
      padding: 10px 12px;
      border-bottom: 1px solid rgba(36, 50, 77, 0.6);
      vertical-align: top;
    }
    tr.clickable-row { cursor: pointer; transition: background 0.12s; }
    tr.clickable-row:hover { background: rgba(56, 189, 248, 0.08); }

    .badge {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 3px 9px;
      border-radius: 6px;
      font-size: 11.5px;
      font-weight: 700;
    }
    .badge-alert {
      background: var(--alert-bg);
      color: #f87171;
      border: 1px solid rgba(239, 68, 68, 0.4);
    }
    .badge-normal {
      background: var(--ok-bg);
      color: #34d399;
      border: 1px solid rgba(16, 185, 129, 0.4);
    }
    .stage-chip {
      display: inline-block;
      background: rgba(99, 102, 241, 0.16);
      color: #a5b4fc;
      border: 1px solid rgba(99, 102, 241, 0.35);
      border-radius: 5px;
      padding: 2px 7px;
      font-size: 11px;
      margin: 2px 4px 2px 0;
    }

    /* Form Controls */
    select, input[type="text"] {
      background: #0f172a;
      border: 1px solid var(--border);
      color: var(--text-main);
      padding: 8px 12px;
      border-radius: 8px;
      font-size: 13px;
      outline: none;
    }
    select:focus, input[type="text"]:focus { border-color: var(--accent-blue); }

    /* Modal */
    .modal-backdrop {
      position: fixed;
      inset: 0;
      background: rgba(3, 7, 18, 0.78);
      backdrop-filter: blur(4px);
      display: none;
      align-items: center;
      justify-content: center;
      z-index: 100;
      padding: 20px;
    }
    .modal-backdrop.open { display: flex; }
    .modal {
      background: var(--bg-panel);
      border: 1px solid var(--border);
      border-radius: 14px;
      max-width: 980px;
      width: 100%;
      max-height: 88vh;
      display: flex;
      flex-direction: column;
      box-shadow: 0 20px 50px rgba(0,0,0,0.6);
    }
    .modal-body {
      padding: 18px 20px;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 16px;
    }
    .code-block {
      background: var(--bg-terminal);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 12px;
      font-family: Consolas, monospace;
      font-size: 12px;
      overflow-x: auto;
      white-space: pre-wrap;
      color: #93c5fd;
    }
  </style>
</head>
<body>

  <!-- TOPBAR -->
  <header class="topbar">
    <div class="brand">
      <div class="brand-icon">🛡️</div>
      <div class="brand-title">
        <h1>WINLOG AI SOC DASHBOARD</h1>
        <p>Hệ thống Giám sát & Phân tích Tương quan Windows Event Log bằng Local SLM (Ollama)</p>
      </div>
    </div>
    <div class="topbar-controls">
      <div class="pill">
        <span class="dot"></span>
        <span>AI Server: <strong>ONLINE</strong></span>
      </div>
      <div class="pill" id="clock-pill">🕒 --:--:--</div>
      <label class="pill" style="cursor:pointer;">
        <input type="checkbox" id="auto-refresh" checked />
        <span>Tự động cập nhật (2.5s)</span>
      </label>
      <button class="btn" onclick="fetchOverview()">🔄 Làm mới</button>
      <a class="btn" href="/docs" target="_blank">📄 Swagger API (/docs)</a>
    </div>
  </header>

  <main class="container">
    <!-- KPI CARDS -->
    <section class="kpi-grid">
      <div class="kpi-card info-card">
        <div class="label">Tổng số phiên phân tích</div>
        <div class="value" id="kpi-total">--</div>
        <div class="sub">Dữ liệu lưu tại thư mục <code>results/</code></div>
      </div>
      <div class="kpi-card alert-card">
        <div class="label">Cảnh báo Tấn công (ALERT)</div>
        <div class="value" id="kpi-alert">--</div>
        <div class="sub">Phát hiện chuỗi hành vi MITRE ATT&CK</div>
      </div>
      <div class="kpi-card ok-card">
        <div class="label">Hoạt động Bình thường (NORMAL)</div>
        <div class="value" id="kpi-normal">--</div>
        <div class="sub">Log sự kiện hệ thống & quản trị hợp lệ</div>
      </div>
      <div class="kpi-card latency-card">
        <div class="label">Thời gian AI xử lý trung bình</div>
        <div class="value" id="kpi-latency">--s</div>
        <div class="sub">Suy luận cục bộ qua Ollama (Qwen / Llama)</div>
      </div>
    </section>

    <!-- NAVIGATION TABS -->
    <nav class="tabs">
      <button class="tab-btn active" onclick="switchTab('tab-live', this)">🖥️ Giám sát Thời gian thực & PowerShell Log</button>
      <button class="tab-btn" onclick="switchTab('tab-sim', this)">⚡ Chạy Phân tích Kịch bản (AI Simulator)</button>
      <button class="tab-btn" onclick="switchTab('tab-bench', this)">📊 Báo cáo So sánh Qwen 2.5 vs Llama 3.2</button>
    </nav>

    <!-- TAB 1: LIVE MONITOR -->
    <section id="tab-live" class="tab-content active">
      <div class="live-grid">
        <!-- PowerShell / Server Live Console -->
        <div class="panel">
          <div class="panel-header">
            <div class="panel-title">
              <span>💻 Luồng Nhật ký PowerShell Client & AI Server</span>
            </div>
            <div style="display:flex; gap:8px; align-items:center;">
              <label style="font-size:12px; color:var(--text-muted); cursor:pointer;">
                <input type="checkbox" id="term-autoscroll" checked /> Tự cuộn
              </label>
            </div>
          </div>
          <div class="terminal-window" id="terminal-box">
            <div class="term-line">Đang tải luồng sự kiện từ AI Server và PowerShell Agent...</div>
          </div>
        </div>

        <!-- Recent AI Analysis Feed -->
        <div class="panel">
          <div class="panel-header">
            <div class="panel-title">
              <span>🚨 Danh sách Phiên Phân tích & Cảnh báo Gần đây</span>
            </div>
            <div style="display:flex; gap:8px; align-items:center;">
              <select id="filter-label" onchange="renderRecentTable()">
                <option value="ALL">Tất cả trạng thái</option>
                <option value="ALERT">Chỉ hiện ALERT (Tấn công)</option>
                <option value="NORMAL">Chỉ hiện NORMAL (An toàn)</option>
              </select>
              <input type="text" id="filter-search" placeholder="Tìm case, host, MITRE..." oninput="renderRecentTable()" />
            </div>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Thời gian</th>
                  <th>Kịch bản / Máy trạm</th>
                  <th>Model</th>
                  <th>Trạng thái</th>
                  <th>Giai đoạn MITRE & Nhận định của AI</th>
                  <th>Thời gian</th>
                </tr>
              </thead>
              <tbody id="recent-tbody">
                <tr><td colspan="6" style="text-align:center; color:var(--text-muted);">Đang tải dữ liệu...</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </section>

    <!-- TAB 2: INTERACTIVE SIMULATOR -->
    <section id="tab-sim" class="tab-content">
      <div class="panel" style="margin-bottom:20px;">
        <div class="panel-header">
          <div class="panel-title">⚡ Kích hoạt Phân tích Kịch bản Trực tiếp trên Web</div>
        </div>
        <div style="padding:18px; display:flex; flex-wrap:wrap; gap:14px; align-items:flex-end;">
          <div style="flex:1; min-width:280px;">
            <label style="display:block; font-size:12px; color:var(--text-muted); margin-bottom:6px;">Chọn Kịch bản Kiểm thử (trong <code>data01/</code> hoặc <code>data/</code>):</label>
            <select id="sim-case-select" style="width:100%;" onchange="updateCasePreview()"></select>
          </div>
          <div>
            <label style="display:block; font-size:12px; color:var(--text-muted); margin-bottom:6px;">Mô hình Local SLM:</label>
            <select id="sim-model-select">
              <option value="qwen">Qwen 2.5 (3B Instruct Q4_K_M)</option>
              <option value="llama">Llama 3.2 (3B Instruct Q4_K_M)</option>
            </select>
          </div>
          <label class="pill" style="cursor:pointer; height:36px;">
            <input type="checkbox" id="sim-telegram-check" />
            <span>Bắn cảnh báo về Telegram nếu phát hiện ALERT</span>
          </label>
          <button class="btn btn-primary" id="btn-run-sim" onclick="runSelectedCase()" style="height:36px;">
            🚀 Chạy Phân tích AI ngay
          </button>
        </div>
        <div id="sim-case-desc" style="padding:0 18px 16px; font-size:13px; color:var(--text-muted);"></div>
      </div>

      <div id="sim-result-box" class="panel" style="display:none;">
        <div class="panel-header">
          <div class="panel-title">🔍 Kết quả Phân tích Trực tiếp</div>
        </div>
        <div style="padding:18px;" id="sim-result-content"></div>
      </div>
    </section>

    <!-- TAB 3: BENCHMARK REPORT -->
    <section id="tab-bench" class="tab-content">
      <div class="panel" style="margin-bottom:20px;">
        <div class="panel-header">
          <div class="panel-title">🏆 Bảng Tổng hợp So sánh Hiệu năng: Qwen 2.5 (3B) vs Llama 3.2 (3B)</div>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Chỉ số Đánh giá (Metric)</th>
                <th>Qwen 2.5 3B Instruct</th>
                <th>Llama 3.2 3B Instruct</th>
              </tr>
            </thead>
            <tbody id="bench-summary-tbody"></tbody>
          </table>
        </div>
      </div>

      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">📋 Chi tiết Từng Kịch bản Kiểm thử (40 Ca x 2 Mô hình = 80 Lượt chạy)</div>
          <div style="display:flex; gap:8px;">
            <select id="bench-filter-model" onchange="renderBenchDetails()">
              <option value="ALL">Cả 2 mô hình</option>
              <option value="qwen">Chỉ Qwen 2.5</option>
              <option value="llama">Chỉ Llama 3.2</option>
            </select>
            <select id="bench-filter-correct" onchange="renderBenchDetails()">
              <option value="ALL">Tất cả kết quả</option>
              <option value="True">Dự đoán ĐÚNG (True)</option>
              <option value="False">Dự đoán SAI / Báo động giả (False)</option>
            </select>
          </div>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Mô hình</th>
                <th>Mã Kịch bản (Case ID)</th>
                <th>Nhãn Thực tế</th>
                <th>AI Dự đoán</th>
                <th>Đúng/Sai</th>
                <th>Thời gian</th>
                <th>Giai đoạn phát hiện & Giải thích của AI</th>
              </tr>
            </thead>
            <tbody id="bench-detail-tbody"></tbody>
          </table>
        </div>
      </div>
    </section>
  </main>

  <!-- MODAL INSPECTOR -->
  <div class="modal-backdrop" id="detail-modal" onclick="if(event.target===this) closeModal()">
    <div class="modal">
      <div class="panel-header">
        <div class="panel-title" id="modal-title">Chi tiết Phiên Phân tích</div>
        <button class="btn" onclick="closeModal()">✖ Đóng</button>
      </div>
      <div class="modal-body" id="modal-body"></div>
    </div>
  </div>

  <script>
    let overviewData = { recent_runs: [], console_logs: [] };
    let allCasesList = [];
    let benchmarkData = { summary: [], details: [] };

    function escapeHtml(str) {
      if (str === null || str === undefined) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
    }

    function switchTab(tabId, btn) {
      document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
      document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
      document.getElementById(tabId).classList.add('active');
      btn.classList.add('active');
    }

    async function fetchOverview() {
      try {
        const resp = await fetch('/api/dashboard/overview');
        if (!resp.ok) return;
        overviewData = await resp.json();

        document.getElementById('clock-pill').textContent = '🕒 ' + overviewData.server_time;
        const st = overviewData.stats || {};
        document.getElementById('kpi-total').textContent = st.total_runs ?? 0;
        document.getElementById('kpi-alert').textContent = st.alert_count ?? 0;
        document.getElementById('kpi-normal').textContent = st.normal_count ?? 0;
        document.getElementById('kpi-latency').textContent = (st.avg_latency ?? 0) + 's';

        renderTerminal();
        renderRecentTable();
      } catch (err) {
        console.error('Lỗi tải overview:', err);
      }
    }

    function renderTerminal() {
      const box = document.getElementById('terminal-box');
      const logs = overviewData.console_logs || [];
      if (!logs.length) {
        box.innerHTML = '<div class="term-line">Chưa có nhật ký mới.</div>';
        return;
      }
      box.innerHTML = logs.map(item => `
        <div class="term-line ${escapeHtml(item.level)}">
          <span class="term-time">[${escapeHtml(item.time)}]</span>
          <span class="term-src">${escapeHtml(item.source)}</span>
          <span>${escapeHtml(item.text)}</span>
        </div>
      `).join('');
      if (document.getElementById('term-autoscroll').checked) {
        box.scrollTop = box.scrollHeight;
      }
    }

    function renderRecentTable() {
      const tbody = document.getElementById('recent-tbody');
      const filterLabel = document.getElementById('filter-label').value;
      const q = (document.getElementById('filter-search').value || '').toLowerCase();

      const rows = (overviewData.recent_runs || []).filter(r => {
        if (filterLabel !== 'ALL' && r.label !== filterLabel) return false;
        if (q) {
          const hay = `${r.case_id} ${r.host} ${r.model} ${(r.detected_stages||[]).join(' ')} ${r.reason}`.toLowerCase();
          if (!hay.includes(q)) return false;
        }
        return true;
      });

      if (!rows.length) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-muted);">Không có bản ghi phù hợp.</td></tr>';
        return;
      }

      tbody.innerHTML = rows.map(r => {
        const badge = r.label === 'ALERT'
          ? '<span class="badge badge-alert">🚨 ALERT</span>'
          : '<span class="badge badge-normal">✓ NORMAL</span>';
        const stagesHtml = (r.detected_stages || []).map(s => `<span class="stage-chip">${escapeHtml(s)}</span>`).join('');
        return `
          <tr class="clickable-row" onclick="openRunDetail('${escapeHtml(r.folder)}', '${escapeHtml(r.file)}')">
            <td style="white-space:nowrap; color:var(--text-muted); font-size:12px;">${escapeHtml(r.timestamp)}</td>
            <td>
              <div style="font-weight:700; color:#f8fafc;">${escapeHtml(r.case_id)}</div>
              <div style="font-size:11.5px; color:var(--text-muted);">🖥️ ${escapeHtml(r.host)} (${r.analyzed_event_count}/${r.raw_event_count} sự kiện)</div>
            </td>
            <td style="font-family:monospace; font-size:12px; color:#93c5fd;">${escapeHtml(r.model)}</td>
            <td>${badge}</td>
            <td>
              ${stagesHtml ? `<div style="margin-bottom:4px;">${stagesHtml}</div>` : ''}
              <div style="font-size:12.5px; color:#cbd5e1;">${escapeHtml(r.reason)}</div>
            </td>
            <td style="white-space:nowrap; font-weight:600; color:#fbbf24;">${r.elapsed_seconds}s</td>
          </tr>
        `;
      }).join('');
    }

    async function openRunDetail(folder, file) {
      const modal = document.getElementById('detail-modal');
      const body = document.getElementById('modal-body');
      document.getElementById('modal-title').textContent = `🔍 Chi tiết Phiên Phân tích: ${folder} / ${file}`;
      body.innerHTML = '<div style="color:var(--text-muted);">Đang tải chi tiết sự kiện...</div>';
      modal.classList.add('open');

      try {
        const resp = await fetch(`/api/dashboard/run-detail?folder=${encodeURIComponent(folder)}&file=${encodeURIComponent(file)}`);
        const data = await resp.json();
        const res = data.result || {};
        const verdict = res.get ? res.get('verdict') : (res.verdict || {});
        const events = data.events || [];
        const isAlert = (verdict.label === 'ALERT');

        body.innerHTML = `
          <div style="display:flex; gap:12px; flex-wrap:wrap; align-items:center;">
            <span class="badge ${isAlert ? 'badge-alert' : 'badge-normal'}" style="font-size:14px; padding:6px 14px;">
              ${isAlert ? '🚨 KẾT LUẬN: PHÁT HIỆN TẤN CÔNG (ALERT)' : '✓ KẾT LUẬN: BÌNH THƯỜNG (NORMAL)'}
            </span>
            <span class="pill">Model: <strong>${escapeHtml(res.model)}</strong></span>
            <span class="pill">Thời gian xử lý: <strong>${escapeHtml(res.elapsed_seconds)}s</strong></span>
            <span class="pill">Bằng chứng: <strong>${escapeHtml((verdict.evidence_refs || []).join(', ') || 'Không có')}</strong></span>
          </div>
          <div style="background:var(--bg-card); border:1px solid var(--border); padding:14px; border-radius:10px;">
            <div style="font-weight:700; margin-bottom:6px; color:#38bdf8;">📝 Giải thích & Lập luận của AI SLM:</div>
            <div style="white-space:pre-line; font-size:13.5px;">${escapeHtml(verdict.reason || '')}</div>
            ${(verdict.detected_stages && verdict.detected_stages.length) ? `
              <div style="margin-top:10px;">
                ${verdict.detected_stages.map(s => `<span class="stage-chip">${escapeHtml(s)}</span>`).join('')}
              </div>
            ` : ''}
          </div>
          <div>
            <div style="font-weight:700; margin-bottom:8px;">📋 Danh sách Sự kiện Windows Event Log đã phân tích (${events.length} sự kiện):</div>
            <div class="code-block">${escapeHtml(JSON.stringify(events, null, 2))}</div>
          </div>
        `;
      } catch (e) {
        body.innerHTML = `<div style="color:var(--alert-red);">Lỗi tải chi tiết: ${escapeHtml(e)}</div>`;
      }
    }

    function closeModal() {
      document.getElementById('detail-modal').classList.remove('open');
    }

    async function loadCasesAndBenchmark() {
      try {
        const cResp = await fetch('/api/dashboard/cases');
        if (cResp.ok) {
          const cData = await cResp.json();
          allCasesList = cData.cases || [];
          const sel = document.getElementById('sim-case-select');
          sel.innerHTML = allCasesList.map((c, idx) =>
            `<option value="${idx}">[${escapeHtml(c.dataset)}] ${escapeHtml(c.case_id)} — (${escapeHtml(c.ground_truth)})</option>`
          ).join('');
          updateCasePreview();
        }
      } catch (e) {}

      try {
        const bResp = await fetch('/api/dashboard/benchmark');
        if (bResp.ok) {
          benchmarkData = await bResp.json();
          renderBenchSummary();
          renderBenchDetails();
        }
      } catch (e) {}
    }

    function updateCasePreview() {
      const idx = document.getElementById('sim-case-select').value;
      const c = allCasesList[idx];
      const box = document.getElementById('sim-case-desc');
      if (!c) { box.textContent = ''; return; }
      box.innerHTML = `
        <strong>Mô tả kịch bản:</strong> ${escapeHtml(c.actions)}
        | <strong>Nhãn chuẩn (Ground Truth):</strong> <span class="badge ${c.ground_truth==='ALERT'?'badge-alert':'badge-normal'}">${escapeHtml(c.ground_truth)}</span>
        ${c.expected_stages && c.expected_stages.length ? `| <strong>MITRE kỳ vọng:</strong> ${escapeHtml(c.expected_stages.join(', '))}` : ''}
      `;
    }

    async function runSelectedCase() {
      const idx = document.getElementById('sim-case-select').value;
      const c = allCasesList[idx];
      if (!c) return;
      const model = document.getElementById('sim-model-select').value;
      const sendTele = document.getElementById('sim-telegram-check').checked;
      const btn = document.getElementById('btn-run-sim');
      const resBox = document.getElementById('sim-result-box');
      const resContent = document.getElementById('sim-result-content');

      btn.disabled = true;
      btn.textContent = '⏳ Đang chạy Local SLM...';
      resBox.style.display = 'block';
      resContent.innerHTML = `<div style="color:var(--accent-blue);">Đang gửi tập sự kiện <strong>${escapeHtml(c.case_id)}</strong> vào mô hình <strong>${escapeHtml(model)}</strong> qua Ollama... Vui lòng đợi vài giây.</div>`;

      try {
        const resp = await fetch('/api/dashboard/run-case', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            dataset: c.dataset,
            case_id: c.case_id,
            model: model,
            send_telegram: sendTele
          })
        });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.detail || 'Lỗi phân tích');

        const r = data.result || {};
        const v = r.verdict || {};
        const isAlert = v.label === 'ALERT';
        resContent.innerHTML = `
          <div style="display:flex; gap:12px; align-items:center; flex-wrap:wrap; margin-bottom:12px;">
            <span class="badge ${isAlert ? 'badge-alert' : 'badge-normal'}" style="font-size:14px; padding:6px 14px;">
              ${isAlert ? '🚨 KẾT QUẢ: ALERT (PHÁT HIỆN TẤN CÔNG)' : '✓ KẾT QUẢ: NORMAL (AN TOÀN)'}
            </span>
            <span class="pill">Thời gian suy luận: <strong>${data.elapsed_seconds}s</strong></span>
            <span class="pill">Sự kiện phân tích: <strong>${r.analyzed_event_count}/${r.raw_event_count}</strong></span>
            <span class="pill">Bằng chứng: <strong>${escapeHtml((v.evidence_refs||[]).join(', ') || 'N/A')}</strong></span>
          </div>
          <div style="margin-bottom:10px;">
            ${(v.detected_stages||[]).map(s => `<span class="stage-chip">${escapeHtml(s)}</span>`).join('')}
          </div>
          <div style="background:var(--bg-card); padding:14px; border-radius:8px; border:1px solid var(--border); white-space:pre-line;">${escapeHtml(v.reason || '')}</div>
        `;
        fetchOverview();
      } catch (err) {
        resContent.innerHTML = `<div style="color:var(--alert-red);">❌ Lỗi: ${escapeHtml(err.message)}</div>`;
      } finally {
        btn.disabled = false;
        btn.textContent = '🚀 Chạy Phân tích AI ngay';
      }
    }

    function renderBenchSummary() {
      const tbody = document.getElementById('bench-summary-tbody');
      const rows = benchmarkData.summary || [];
      if (!rows.length) {
        tbody.innerHTML = '<tr><td colspan="3" style="text-align:center; color:var(--text-muted);">Chưa có file comparison_summary.csv</td></tr>';
        return;
      }
      tbody.innerHTML = rows.map(r => `
        <tr>
          <td style="font-weight:600;">${escapeHtml(r.metric)}</td>
          <td style="color:#38bdf8; font-weight:700;">${escapeHtml(r.qwen)}</td>
          <td style="color:#a78bfa; font-weight:700;">${escapeHtml(r.llama)}</td>
        </tr>
      `).join('');
    }

    function renderBenchDetails() {
      const tbody = document.getElementById('bench-detail-tbody');
      const fModel = document.getElementById('bench-filter-model').value;
      const fCorrect = document.getElementById('bench-filter-correct').value;

      const rows = (benchmarkData.details || []).filter(r => {
        if (fModel !== 'ALL' && r.model_key !== fModel) return false;
        if (fCorrect !== 'ALL' && String(r.is_correct) !== fCorrect) return false;
        return true;
      });

      tbody.innerHTML = rows.map(r => {
        const gtBadge = r.ground_truth === 'ALERT'
          ? '<span class="badge badge-alert">ALERT</span>'
          : '<span class="badge badge-normal">NORMAL</span>';
        const predBadge = r.pred_label === 'ALERT'
          ? '<span class="badge badge-alert">ALERT</span>'
          : '<span class="badge badge-normal">NORMAL</span>';
        const okBadge = String(r.is_correct) === 'True'
          ? '<span style="color:#34d399; font-weight:700;">✓ Đúng</span>'
          : '<span style="color:#f87171; font-weight:700;">✗ Sai (FP/FN)</span>';

        return `
          <tr>
            <td style="font-family:monospace; font-weight:700; color:#93c5fd;">${escapeHtml(r.model_key.toUpperCase())}</td>
            <td style="font-weight:600;">${escapeHtml(r.case_id)}</td>
            <td>${gtBadge}</td>
            <td>${predBadge}</td>
            <td>${okBadge}</td>
            <td style="color:#fbbf24; font-weight:600;">${escapeHtml(r.elapsed_seconds)}s</td>
            <td>
              ${r.stages ? `<div style="margin-bottom:4px;">${r.stages.split(';').map(s=>`<span class="stage-chip">${escapeHtml(s.trim())}</span>`).join('')}</div>` : ''}
              <div style="font-size:12px; color:#cbd5e1;">${escapeHtml(r.reason)}</div>
            </td>
          </tr>
        `;
      }).join('');
    }

    // Khởi chạy ban đầu
    fetchOverview();
    loadCasesAndBenchmark();
    setInterval(() => {
      if (document.getElementById('auto-refresh').checked) {
        fetchOverview();
      }
    }, 2500);
  </script>
</body>
</html>
"""
