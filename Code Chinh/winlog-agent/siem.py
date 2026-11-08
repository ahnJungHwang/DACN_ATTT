"""SIEM dashboard backend cho WinLog AI Agent.

- Bắt (tee) toàn bộ output terminal của server -> đẩy lên web (Live Terminal).
- Lưu sự kiện Windows nhận từ client + kết quả phân tích AI (verdict) -> Overview/Events/Alerts.
- Đẩy realtime qua Server-Sent Events (/api/stream).

Tích hợp vào app.py chỉ cần: `import siem; siem.install(app)`.
"""
from __future__ import annotations

import asyncio
import json
import re
import sys
import threading
import time
import xml.etree.ElementTree as ET
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse

BASE = Path(__file__).resolve().parent
WEB_DIR = BASE / "web"
RESULTS_DIR = BASE / "results"

HISTORY_FILES = 60          # số file results/ gần nhất nạp lúc khởi động
MAX_EVENTS = 5000
MAX_ANALYSES = 500
MAX_TERMINAL = 1500
ACTIVE_WINDOW_SEC = 300     # agent coi là "Active" nếu có tín hiệu trong 5 phút

_lock = threading.RLock()
_bus: deque = deque(maxlen=4000)      # {seq, type, data}
_seq = 0
_events: deque = deque(maxlen=MAX_EVENTS)
_analyses: deque = deque(maxlen=MAX_ANALYSES)
_terminal: deque = deque(maxlen=MAX_TERMINAL)
_agents: dict[str, dict] = {}
_seen_keys: set = set()
_totals = {"events": 0, "alerts": 0, "analyses": 0}
_boot = time.time()

# ----------------------------------------------------------------- bus
def _publish(type_: str, data) -> int:
    global _seq
    with _lock:
        _seq += 1
        _bus.append({"seq": _seq, "type": type_, "data": data})
        return _seq


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


# ------------------------------------------------------------ terminal tee
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


class _Tee:
    """Ghi ra stream gốc đồng thời đẩy từng dòng vào bus."""

    def __init__(self, orig, name: str):
        self._orig = orig
        self._name = name
        self._buf = ""

    def write(self, s):
        try:
            n = self._orig.write(s)
        except Exception:
            n = len(s)
        try:
            self._buf += s
            while "\n" in self._buf:
                line, self._buf = self._buf.split("\n", 1)
                line = _ANSI.sub("", line.rstrip("\r"))
                if line.strip():
                    item = {"ts": _now_iso(), "stream": self._name, "line": line}
                    with _lock:
                        _terminal.append(item)
                    _publish("term", item)
        except Exception:
            pass
        return n

    def flush(self):
        try:
            self._orig.flush()
        except Exception:
            pass

    def __getattr__(self, item):
        return getattr(self._orig, item)


def _install_tee():
    if not isinstance(sys.stdout, _Tee):
        sys.stdout = _Tee(sys.stdout, "stdout")
    if not isinstance(sys.stderr, _Tee):
        sys.stderr = _Tee(sys.stderr, "stderr")
    # logger của uvicorn giữ tham chiếu stderr cũ -> trỏ lại sang tee
    import logging

    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        for h in logging.getLogger(name).handlers:
            if isinstance(h, logging.StreamHandler) and not isinstance(h.stream, _Tee):
                h.stream = sys.stderr if name != "uvicorn.access" else sys.stdout


# ---------------------------------------------------- enrichment / rules
EVENT_INFO = {
    1102: ("Audit log was cleared", 13),
    4103: ("PowerShell module logging", 3),
    4104: ("PowerShell script block", 4),
    4624: ("Successful logon", 3),
    4625: ("Failed logon", 5),
    4634: ("Logoff", 2),
    4648: ("Logon with explicit credentials", 6),
    4662: ("Operation performed on object", 5),
    4672: ("Special privileges assigned", 3),
    4688: ("New process created", 3),
    4697: ("Service installed", 9),
    4698: ("Scheduled task created", 9),
    4699: ("Scheduled task deleted", 6),
    4702: ("Scheduled task updated", 6),
    4720: ("User account created", 10),
    4722: ("User account enabled", 6),
    4724: ("Password reset attempt", 8),
    4726: ("User account deleted", 8),
    4728: ("Member added to global group", 8),
    4732: ("Member added to local group", 10),
    4738: ("User account changed", 5),
    4740: ("Account locked out", 9),
    4768: ("Kerberos TGT requested", 3),
    4769: ("Kerberos service ticket requested", 3),
    4776: ("NTLM credential validation", 4),
    7045: ("New service installed", 9),
}

SUSPICIOUS = [
    (r"mimikatz|sekurlsa|lsadump", "Credential dumping tool (Mimikatz)"),
    (r"procdump.*lsass|lsass.*(dmp|dump)|comsvcs.*minidump", "LSASS memory dump"),
    (r"-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}", "PowerShell encoded command"),
    (r"invoke-expression|\biex\b|downloadstring|downloadfile|net\.webclient|invoke-webrequest|\biwr\b", "PowerShell download/execute"),
    (r"frombase64string", "Base64 payload decoding"),
    (r"certutil.*-urlcache|bitsadmin.*/transfer", "LOLBin file download"),
    (r"vssadmin.*delete\s+shadows|wbadmin.*delete|bcdedit.*recoveryenabled", "Backup / shadow-copy destruction"),
    (r"net\s+user\s+\S+\s+\S+\s+/add|net\s+localgroup\s+administrators.*/add", "Local account / admin group tampering"),
    (r"schtasks.*/create", "Scheduled task persistence"),
    (r"reg(\.exe)?\s+(add|save).*(\\run\b|sam|security|system)", "Registry persistence / hive dump"),
    (r"-nop\b.*-w(indowstyle)?\s+hidden|-w(indowstyle)?\s+hidden.*-nop", "Hidden PowerShell"),
    (r"amsiutils|amsiinitfailed|set-mppreference.*disable", "Defense evasion (AMSI / Defender)"),
]
_SUSP_RE = [(re.compile(p, re.I | re.S), label) for p, label in SUSPICIOUS]

LOGON_TYPES = {"2": "Interactive", "3": "Network", "4": "Batch", "5": "Service", "7": "Unlock",
               "8": "NetworkCleartext", "9": "NewCredentials", "10": "RemoteInteractive", "11": "CachedInteractive"}


def _g(d: dict, *keys, default=""):
    for k in keys:
        v = d.get(k)
        if v not in (None, "", "-"):
            return str(v)
    return default


def _enrich(raw: dict, agent: str, live: bool, recv_iso: str) -> dict:
    """raw: {time, host, channel, provider, record_id, event_id, data}."""
    eid = int(raw.get("event_id") or 0)
    data = raw.get("data") or {}
    title, level = EVENT_INFO.get(eid, (f"Event {eid}", 2))

    user = _g(data, "TargetUserName", "SubjectUserName", "UserName", "User")
    ip = _g(data, "IpAddress", "SourceNetworkAddress", "SourceAddress")
    cmd = _g(data, "CommandLine", "ScriptBlockText", "Payload", "ContextInfo")
    proc = _g(data, "NewProcessName", "Image", "ProcessName")

    if eid == 4688:
        summary = f"{proc.split(chr(92))[-1] or 'process'} <- {_g(data, 'ParentProcessName').split(chr(92))[-1] or '?'}"
        if cmd:
            summary += f"  |  {cmd[:140]}"
        user = _g(data, "SubjectUserName", default=user)
    elif eid in (4624, 4625, 4648, 4776):
        lt = LOGON_TYPES.get(_g(data, "LogonType"), _g(data, "LogonType"))
        summary = f"{user or '?'}" + (f" from {ip}" if ip else "") + (f"  (logon type {lt})" if lt else "")
        if eid == 4625 and _g(data, "SubStatus", "Status"):
            summary += f"  status {_g(data, 'SubStatus', 'Status')}"
    elif eid == 4104:
        summary = " ".join(cmd.split())[:180] or "PowerShell script block"
    elif eid in (4720, 4722, 4726, 4732, 4728, 4738, 4740, 4724):
        summary = f"{_g(data, 'TargetUserName', 'MemberName')} by {_g(data, 'SubjectUserName')}"
    elif eid in (4698, 4699, 4702):
        summary = f"task {_g(data, 'TaskName')} by {_g(data, 'SubjectUserName')}"
    elif eid in (4697, 7045):
        summary = f"service {_g(data, 'ServiceName')}  {_g(data, 'ServiceFileName', 'ImagePath')[:120]}"
    else:
        summary = " ".join(f"{k}={str(v)[:40]}" for k, v in list(data.items())[:4])

    # luật phát hiện bổ sung -> nâng mức cảnh báo
    rule = title
    hay = " ".join([cmd, _g(data, "ParentProcessName"), proc])
    for rx, label in _SUSP_RE:
        if rx.search(hay):
            rule = f"{label}"
            level = max(level, 12)
            break

    return {
        "id": f"{agent}|{raw.get('record_id')}|{raw.get('time')}|{eid}",
        "ts": raw.get("time") or recv_iso,
        "recv": recv_iso,
        "live": live,
        "agent": agent,
        "host": raw.get("host") or "unknown",
        "channel": raw.get("channel") or "",
        "event_id": eid,
        "title": title,
        "rule": rule,
        "level": level,
        "user": user,
        "ip": ip,
        "summary": summary[:300],
        "data": {k: (str(v)[:600]) for k, v in data.items()},
    }


def _strip_ns(xml: str) -> str:
    return re.sub(r"\sxmlns(:\w+)?=(['\"]).*?\2", "", xml)


def parse_events_xml(xml: str, channel_hint: str = "") -> list[dict]:
    """Parse chuỗi <Events>...</Events> của client thành list raw event."""
    out: list[dict] = []
    if not xml or "<Event" not in xml:
        return out
    try:
        root = ET.fromstring(_strip_ns(xml))
    except ET.ParseError:
        try:
            root = ET.fromstring("<Events>" + _strip_ns(xml) + "</Events>")
        except ET.ParseError:
            return out
    nodes = [root] if root.tag == "Event" else root.iter("Event")
    for ev in nodes:
        sysn = ev.find("System")
        if sysn is None:
            continue
        prov = sysn.find("Provider")
        tc = sysn.find("TimeCreated")
        eid = (sysn.findtext("EventID") or "0").strip()
        data: dict = {}
        ed = ev.find("EventData")
        if ed is not None:
            for i, d in enumerate(ed.findall("Data")):
                data[d.get("Name") or f"Data{i}"] = (d.text or "").strip()
        ud = ev.find("UserData")
        if ud is not None:
            for el in ud.iter():
                if el is not ud and len(el) == 0 and (el.text or "").strip():
                    data[el.tag] = el.text.strip()
        out.append({
            "time": tc.get("SystemTime") if tc is not None else None,
            "host": sysn.findtext("Computer"),
            "channel": sysn.findtext("Channel") or channel_hint,
            "provider": prov.get("Name") if prov is not None else "",
            "record_id": sysn.findtext("EventRecordID"),
            "event_id": int(eid) if eid.isdigit() else 0,
            "data": data,
        })
    return out


# ---------------------------------------------------------------- store
def _touch_agent(client_id: str, hostname: str, *, events=0, alerts=0, label=None, live=True):
    with _lock:
        a = _agents.setdefault(client_id, {
            "client_id": client_id, "hostname": hostname, "first_seen": _now_iso(),
            "last_seen": _now_iso(), "last_ts": 0.0, "events": 0, "alerts": 0,
            "last_verdict": None, "live": live,
        })
        if hostname and hostname != "unknown":
            a["hostname"] = hostname
        if live:
            a["last_seen"] = _now_iso()
            a["last_ts"] = time.time()
            a["live"] = True
        a["events"] += events
        a["alerts"] += alerts
        if label:
            a["last_verdict"] = label
        return dict(a)


def _store_events(raws: list[dict], agent: str, live: bool, recv_iso: str) -> list[dict]:
    added = []
    with _lock:
        for raw in raws:
            ev = _enrich(raw, agent, live, recv_iso)
            key = (raw.get("host"), raw.get("record_id"), raw.get("time"), raw.get("event_id"))
            if raw.get("record_id") and key in _seen_keys:
                continue
            _seen_keys.add(key)
            _events.append(ev)
            added.append(ev)
        if live:
            _totals["events"] += len(added)
    return added


def record_events(client_id: str, hostname: str, security_xml: str, powershell_xml: str):
    """Gọi khi server nhận log mới từ client."""
    try:
        raws = parse_events_xml(security_xml, "Security") + parse_events_xml(powershell_xml, "Microsoft-Windows-PowerShell/Operational")
        added = _store_events(raws, client_id, True, _now_iso())
        _touch_agent(client_id, hostname, events=len(added))
        for ev in added:
            _publish("event", ev)
        _publish("agent", _agent_list())
    except Exception as exc:  # không bao giờ làm hỏng luồng ingest
        print(f"[siem] record_events error: {exc}", flush=True)


def heartbeat(client_id: str, hostname: str):
    try:
        _touch_agent(client_id, hostname)
        _publish("agent", _agent_list())
    except Exception:
        pass


def record_verdict(client_id: str, hostname: str, verdict: dict, *, status: str = "OK",
                   elapsed: float | None = None, model: str = "", live: bool = True, ts: str | None = None):
    """Gọi sau khi AI phân tích xong."""
    try:
        label = (verdict or {}).get("label", "UNKNOWN")
        item = {
            "id": f"{client_id}|{ts or time.time()}",
            "ts": ts or _now_iso(),
            "live": live,
            "agent": client_id,
            "host": hostname,
            "label": label,
            "status": status,
            "reason": (verdict or {}).get("reason", ""),
            "stages": (verdict or {}).get("detected_stages", []) or [],
            "evidence": (verdict or {}).get("evidence_refs", []) or [],
            "elapsed": elapsed,
            "model": model,
        }
        with _lock:
            _analyses.append(item)
            if live:
                _totals["analyses"] += 1
                if label == "ALERT":
                    _totals["alerts"] += 1
        _touch_agent(client_id, hostname, alerts=1 if (label == "ALERT" and live) else 0, label=label, live=live)
        _publish("analysis", item)
        _publish("agent", _agent_list())
    except Exception as exc:
        print(f"[siem] record_verdict error: {exc}", flush=True)


def _agent_list() -> list[dict]:
    now = time.time()
    with _lock:
        out = []
        for a in _agents.values():
            d = dict(a)
            d["status"] = "active" if (now - a.get("last_ts", 0)) < ACTIVE_WINDOW_SEC else "disconnected"
            out.append(d)
    out.sort(key=lambda x: x["last_seen"], reverse=True)
    return out


# -------------------------------------------------------------- history
def _load_history():
    """Nạp kết quả cũ trong results/ để dashboard có dữ liệu ngay khi mở."""
    if not RESULTS_DIR.is_dir():
        return
    files = sorted(RESULTS_DIR.glob("*/*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:HISTORY_FILES]
    for f in reversed(files):
        try:
            doc = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        res = doc.get("result") or {}
        case = res.get("case_id") or f.parent.name
        recv = datetime.fromtimestamp(f.stat().st_mtime, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        evs = doc.get("events") or []
        _store_events(evs, case, False, recv)
        host = (evs[0].get("host") if evs else None) or case
        if res.get("verdict"):
            record_verdict(case, host, res["verdict"], status=res.get("analysis_status", "OK"),
                           elapsed=res.get("elapsed_seconds"), model=res.get("model", ""), live=False, ts=recv)
        _touch_agent(case, host, events=0, live=False)
    # sắp xếp lại theo thời gian sự kiện
    with _lock:
        sorted_ev = sorted(_events, key=lambda e: e["ts"])
        _events.clear()
        _events.extend(sorted_ev)
    # history không tính vào "live" counters
    with _lock:
        for a in _agents.values():
            a["events"] = sum(1 for e in _events if e["agent"] == a["client_id"])


# ------------------------------------------------------------ shutdown
_stop = threading.Event()


def _hook_shutdown_signals():
    """Khi bấm Ctrl+C: báo cho các stream SSE kết thúc, nếu không uvicorn sẽ chờ mãi
    các kết nối trình duyệt đang mở và tiến trình không thoát (vẫn giữ cổng 9443).

    App được nạp TRƯỚC khi uvicorn đăng ký signal handler (self.handle_exit), nên ta
    bọc chính Server.handle_exit của uvicorn thay vì gọi signal.signal()."""
    try:
        from uvicorn.server import Server
    except Exception:
        return
    if getattr(Server.handle_exit, "_siem_wrapped", False):
        return
    orig = Server.handle_exit

    def handle_exit(self, sig, frame):
        _stop.set()
        return orig(self, sig, frame)

    handle_exit._siem_wrapped = True
    Server.handle_exit = handle_exit


# ----------------------------------------------------------------- API
def install(app: FastAPI):
    _install_tee()
    _hook_shutdown_signals()
    _load_history()

    @app.on_event("shutdown")
    def _on_shutdown():
        _stop.set()

    @app.on_event("startup")
    async def _quiet_conn_reset():
        # Windows (Proactor) in traceback "ConnectionResetError [WinError 10054]" mỗi khi
        # trình duyệt/client tự đóng kết nối -> vô hại, ẩn đi cho terminal gọn.
        loop = asyncio.get_running_loop()
        prev = loop.get_exception_handler()

        def handler(lp, ctx):
            exc = ctx.get("exception")
            if isinstance(exc, (ConnectionResetError, ConnectionAbortedError)):
                return
            if prev:
                prev(lp, ctx)
            else:
                lp.default_exception_handler(ctx)

        loop.set_exception_handler(handler)

    @app.get("/dashboard", include_in_schema=False)
    def dashboard():
        f = WEB_DIR / "index.html"
        if not f.exists():
            return HTMLResponse("<h3>Thiếu web/index.html</h3>", status_code=404)
        return FileResponse(f, headers={"Cache-Control": "no-store"})

    @app.get("/api/state", include_in_schema=False)
    def state(limit: int = Query(2000, le=MAX_EVENTS)):
        with _lock:
            return {
                "server_time": _now_iso(),
                "uptime": int(time.time() - _boot),
                "seq": _seq,
                "totals": dict(_totals),
                "events": list(_events)[-limit:],
                "analyses": list(_analyses),
                "agents": _agent_list(),
                "terminal": list(_terminal),
            }

    @app.get("/api/stream", include_in_schema=False)
    async def stream(request: Request, since: int = -1):
        # trình duyệt tự kết nối lại kèm Last-Event-ID -> tiếp tục đúng chỗ, không mất dữ liệu
        hdr = request.headers.get("last-event-id", "")
        if hdr.isdigit():
            since = int(hdr)

        async def gen():
            last = _seq if since < 0 else since
            idle = 0
            started = time.time()
            yield "retry: 2000\n\n"
            # tự đóng khi server tắt / client ngắt / sau 5 phút (trình duyệt tự nối lại)
            while not _stop.is_set() and time.time() - started < 300:
                if await request.is_disconnected():
                    break
                with _lock:
                    batch = [m for m in _bus if m["seq"] > last]
                if batch:
                    idle = 0
                    for m in batch:
                        last = m["seq"]
                        yield f"id: {m['seq']}\nevent: {m['type']}\ndata: {json.dumps(m['data'], ensure_ascii=False)}\n\n"
                else:
                    idle += 1
                    if idle >= 20:   # keep-alive ~10s
                        idle = 0
                        yield ": ping\n\n"
                await asyncio.sleep(0.5)

        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
