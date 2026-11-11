"""Chống gửi trùng cảnh báo + đo độ trễ đầu-cuối cho luồng /ingest.

1. AlertDeduplicator — mỗi cảnh báo ALERT được gom theo khóa (máy client, kỹ thuật MITRE).
   - Khóa chưa thấy, hoặc đã im lặng quá ALERT_DEDUP_MINUTES phút -> sự cố MỚI -> gửi Telegram.
   - Khóa đang mở (tấn công còn tiếp diễn) -> TRÙNG -> chỉ tăng bộ đếm, KHÔNG gửi Telegram.
     Mỗi lần trùng, sự cố được gia hạn (cửa sổ trượt): sự cố đóng khi im lặng đủ N phút.
   - Lô có thêm kỹ thuật mới so với sự cố đang mở -> vẫn gửi (có thông tin mới).
   - Trạng thái lưu ra results/alert_state.json -> khởi động lại server không gửi lại.
   - Mọi quyết định ghi vào results/alerts_log.csv (bằng chứng cho báo cáo).

2. LatencyRecorder — ghi results/latency.csv, mỗi lô log một dòng:
   thời điểm sinh sự kiện (đồng hồ máy client) -> client gửi -> server nhận -> AI xong
   -> n8n/Telegram xong. Chênh lệch đồng hồ client/server được bù bằng
   offset = server_nhận - client_gửi (độ trễ mạng một chiều trong VMnet < vài ms, bỏ qua).

Cấu hình (biến môi trường / .env):
    ALERT_DEDUP_MINUTES  (mặc định 10)
    WINLOG_RESULTS_DIR   (mặc định <winlog-agent>/results)
"""
from __future__ import annotations

import csv
import json
import os
import re
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent  # thư mục gốc winlog-agent (file này ở core/)


def results_dir() -> Path:
    d = Path(os.getenv("WINLOG_RESULTS_DIR") or (ROOT / "results"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z") if dt else ""


def parse_time(value: str | None) -> datetime | None:
    """ISO 8601 từ Windows (tới 7 chữ số thập phân) / PowerShell 'o' -> datetime UTC."""
    if not value:
        return None
    s = value.strip().replace("Z", "+00:00")
    # Windows ghi 7 chữ số thập phân (vd .1234567); Python chỉ nhận tối đa 6 -> cắt bớt
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


_SYSTEM_TIME = re.compile(r"SystemTime=['\"]([^'\"]+)['\"]")


def event_time_range(*xml_blobs: str) -> tuple[datetime | None, datetime | None]:
    """Thời điểm sớm nhất / muộn nhất của các sự kiện trong các khối XML (đồng hồ máy client)."""
    times = [t for blob in xml_blobs for t in (parse_time(x) for x in _SYSTEM_TIME.findall(blob or "")) if t]
    return (min(times), max(times)) if times else (None, None)


def _append_csv(path: Path, fields: list[str], row: dict) -> None:
    new = not path.exists()
    with open(path, "a", newline="", encoding="utf-8-sig" if new else "utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        if new:
            w.writeheader()
        w.writerow(row)


# =============================================================== chống trùng
_TECH = re.compile(r"T\d{4}(?:\.\d{3})?")


# AI đôi khi ghi tên kỹ thuật KHÔNG kèm mã MITRE -> quy về mã để không tách 1 cuộc tấn công thành nhiều sự cố
_NAME_TO_ID = {  # tên cụ thể đứng TRƯỚC tên chung (so khớp chuỗi con theo thứ tự)
    "successful logon post-brute force": "T1078", "valid accounts": "T1078",
    "password spraying": "T1110.003", "password brute force": "T1110", "brute force": "T1110",
    "backdoor creation": "T1098/T1136", "privilege escalation": "T1098/T1136",
    "account manipulation": "T1098", "create account": "T1136.001",
    "malware execution": "T1059.001", "powershell download cradle": "T1059.001",
    "reconnaissance": "T1033", "system reconnaissance": "T1033",
    "indicator removal": "T1070.001", "clear windows event logs": "T1070.001",
    "scheduled task persistence": "T1053.005", "new scheduled task": "T1053.005",
    "malicious service": "T1543.003/T1569.002", "new service installed": "T1543.003",
}


def _stage_name(stage: str) -> str:
    """Tên stage bỏ phần '(MITRE ...)', chữ thường, gọn khoảng trắng."""
    return re.sub(r"\s+", " ", re.sub(r"\(.*?\)", "", stage or "")).strip().lower()


def technique_key(stage: str, known: dict[str, str] | None = None) -> str:
    """'Password Brute Force (MITRE T1110)' -> 'T1110'; không có mã -> tra theo tên, cuối cùng là tên chuẩn hoá."""
    ids = _TECH.findall(stage or "")
    if ids:
        return "/".join(sorted(dict.fromkeys(ids)))
    name = _stage_name(stage)
    if known and name in known:
        return known[name]
    for k, v in _NAME_TO_ID.items():
        if k in name:
            return v
    return name or "ai-unspecified"


class AlertDeduplicator:
    LOG_FIELDS = ["time_utc", "client_id", "hostname", "label", "status", "notify", "techniques",
                  "new_techniques", "suppressed_techniques", "incident_ids", "repeat_count",
                  "window_minutes", "decision_source", "model"]

    def __init__(self, window_minutes: float | None = None):
        self.window = timedelta(minutes=float(window_minutes if window_minutes is not None
                                               else os.getenv("ALERT_DEDUP_MINUTES", "10")))
        self._lock = threading.Lock()
        self._state_path = results_dir() / "alert_state.json"
        self._log_path = results_dir() / "alerts_log.csv"
        self._state: dict[str, dict] = self._load()

    def _load(self) -> dict:
        try:
            return json.loads(self._state_path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _save(self) -> None:
        tmp = self._state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._state, ensure_ascii=False, indent=1), encoding="utf-8")
        os.replace(tmp, self._state_path)

    def check(self, client_id: str, hostname: str, verdict: dict, model: str = "",
              now: datetime | None = None) -> dict:
        """Gọi cho MỌI kết luận. Trả về {notify, status, incident_ids, repeat_count, ...}."""
        now = now or utcnow()
        label = verdict.get("label", "")
        if label != "ALERT":
            return {"notify": False, "status": "NOT_ALERT", "incident_ids": [], "repeat_count": 0,
                    "new_techniques": [], "suppressed_techniques": []}

        stages = verdict.get("detected_stages") or []
        # tên -> mã lấy từ chính các stage có mã trong cùng kết luận (vd luật ghi kèm mã, AI ghi tên trần)
        known = {_stage_name(s): technique_key(s) for s in stages if _TECH.search(s or "")}
        techs = list(dict.fromkeys(technique_key(s, known) for s in stages)) or ["ai-unspecified"]
        new, dup, incidents, repeat = [], [], [], 0
        with self._lock:
            # dọn sự cố đã đóng lâu (giữ file nhỏ)
            for k in [k for k, v in self._state.items()
                      if now - datetime.fromisoformat(v["last_seen"]) > self.window * 6]:
                self._state.pop(k)
            for t in techs:
                key = f"{client_id}|{t}"
                s = self._state.get(key)
                if s and now - datetime.fromisoformat(s["last_seen"]) <= self.window:
                    s["count"] += 1
                    s["last_seen"] = now.isoformat()
                    dup.append(t)
                else:
                    s = {"incident_id": f"INC-{now.strftime('%Y%m%d-%H%M%S')}-{len(self._state) + 1:03d}",
                         "client_id": client_id, "hostname": hostname, "technique": t,
                         "first_seen": now.isoformat(), "last_seen": now.isoformat(), "count": 1}
                    self._state[key] = s
                    new.append(t)
                incidents.append(s["incident_id"])
                repeat = max(repeat, s["count"])
            notify = bool(new)
            status = "NEW" if notify and not dup else ("NEW_TECHNIQUE" if notify else "DUPLICATE")
            self._save()
            _append_csv(self._log_path, self.LOG_FIELDS, {
                "time_utc": iso(now), "client_id": client_id, "hostname": hostname, "label": label,
                "status": status, "notify": notify, "techniques": "; ".join(techs),
                "new_techniques": "; ".join(new), "suppressed_techniques": "; ".join(dup),
                "incident_ids": "; ".join(dict.fromkeys(incidents)), "repeat_count": repeat,
                "window_minutes": self.window.total_seconds() / 60,
                "decision_source": verdict.get("decision_source", ""), "model": model,
            })
        return {"notify": notify, "status": status, "incident_ids": list(dict.fromkeys(incidents)),
                "repeat_count": repeat, "new_techniques": new, "suppressed_techniques": dup,
                "window_minutes": self.window.total_seconds() / 60}


# =============================================================== độ trễ
class LatencyRecorder:
    FIELDS = ["batch_utc", "client_id", "hostname", "model", "path", "events_total", "events_security",
              "label", "alert_status", "telegram_sent", "telegram_date_utc",
              "event_first_client", "event_last_client", "client_sent_client", "clock_offset_s",
              "server_recv_utc", "ai_start_utc", "ai_done_utc", "done_utc",
              "collect_s", "n8n_hop_s", "ai_s", "notify_s",
              "e2e_from_first_s", "e2e_from_last_s", "clock_basis"]

    def __init__(self):
        self._lock = threading.Lock()
        self._pending: dict[str, dict] = {}  # client_id -> kết quả bước 2 (AI) chờ bước 1 ghép
        self._path = results_dir() / "latency.csv"

    # bước 2 (n8n gọi lại / fallback) ghi lại thời điểm AI
    def set_analysis(self, client_id: str, **info) -> None:
        with self._lock:
            self._pending[client_id] = info

    def pop_analysis(self, client_id: str) -> dict:
        with self._lock:
            return self._pending.pop(client_id, {})

    def record(self, *, client_id: str, hostname: str, model: str, path: str,
               events_total: int, events_security: int, event_first: datetime | None,
               event_last: datetime | None, client_sent: datetime | None, server_recv: datetime,
               done: datetime, analysis: dict, telegram_sent: bool,
               telegram_date: datetime | None = None) -> dict:
        if client_sent:
            offset = (server_recv - client_sent).total_seconds()
            basis = "offset_from_client_sent"
        else:  # client cũ không gửi giờ -> giả định đồng hồ 2 máy đã đồng bộ
            offset, basis = 0.0, "assumed_synced"
        shift = timedelta(seconds=offset)

        def sec(a, b):
            return round((b - a).total_seconds(), 3) if a and b else ""

        ai_start, ai_done = analysis.get("ai_start"), analysis.get("ai_done")
        row = {
            "batch_utc": iso(server_recv), "client_id": client_id, "hostname": hostname, "model": model,
            "path": path, "events_total": events_total, "events_security": events_security,
            "label": analysis.get("label", ""), "alert_status": analysis.get("alert_status", ""),
            "telegram_sent": telegram_sent, "telegram_date_utc": iso(telegram_date),
            "event_first_client": iso(event_first), "event_last_client": iso(event_last),
            "client_sent_client": iso(client_sent), "clock_offset_s": round(offset, 3),
            "server_recv_utc": iso(server_recv), "ai_start_utc": iso(ai_start), "ai_done_utc": iso(ai_done),
            "done_utc": iso(done),
            "collect_s": sec(event_last, client_sent) if client_sent else "",
            "n8n_hop_s": sec(server_recv, ai_start), "ai_s": sec(ai_start, ai_done),
            "notify_s": sec(ai_done, done),
            "e2e_from_first_s": sec(event_first + shift, done) if event_first else "",
            "e2e_from_last_s": sec(event_last + shift, done) if event_last else "",
            "clock_basis": basis,
        }
        with self._lock:
            _append_csv(self._path, self.FIELDS, row)
        return row
