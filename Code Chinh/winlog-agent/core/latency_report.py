"""Tổng hợp độ trễ đầu-cuối (sự kiện Windows -> cảnh báo Telegram) và hiệu quả chống trùng cảnh báo.

Đọc  : results/latency.csv     (app.py ghi, mỗi lô log một dòng)
       results/alerts_log.csv  (app.py ghi, mỗi kết luận ALERT một dòng)
Xuất : results/LATENCY_REPORT.md      báo cáo đọc được
       results/latency_summary.csv    bảng số liệu tổng hợp (đưa vào báo cáo / Excel)
       results/latency_alerts.csv     từng cảnh báo đã gửi Telegram

Bù lệch đồng hồ client/server (kiểu NTP): mỗi lô có  recv_server - sent_client = lệch_đồng_hồ + trễ_truyền,
mà trễ truyền luôn >= 0, nên lệch đồng hồ thật ≈ GIÁ TRỊ NHỎ NHẤT của hiệu này trên mọi lô của cùng một máy.
Phần dư của từng lô là "truyền tải" (mạng, bắt tay HTTPS, chờ hàng đợi) và được tính vào độ trễ.

Cách chạy (đứng ở thư mục gốc winlog-agent):
    .venv\\Scripts\\python.exe core\\latency_report.py
    .venv\\Scripts\\python.exe core\\latency_report.py --since 2026-11-11T16:00:00     (giờ UTC)
"""
from __future__ import annotations

import argparse
import csv
import statistics
import sys
from datetime import datetime, timedelta
from pathlib import Path

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

sys.path.insert(0, str(Path(__file__).resolve().parent))
from alerting import parse_time, results_dir  # noqa: E402

# (cột, tên hiển thị)
COMPONENTS = [
    ("collect_s", "① Client gom & gửi"),
    ("transfer_s", "② Truyền tải"),
    ("n8n_hop_s", "③ n8n gọi lại"),
    ("ai_s", "④ AI phân tích"),
    ("notify_s", "⑤ n8n + Telegram"),
]
E2E = [("e2e_first_s", "Sự kiện đầu → cảnh báo"), ("e2e_last_s", "Sự kiện cuối → cảnh báo")]

# Chu kỳ bình thường: agent quét 5 s + chờ server xử lý lô trước (~5-20 s).
# Sự kiện phải nằm chờ ở client lâu hơn ngưỡng này = server ngừng / mất kết nối, agent giữ lại rồi gửi bù
# -> không phải độ trễ khi vận hành bình thường, tách riêng khỏi thống kê chính.
BACKLOG_S = 60.0


def is_backlog(r: dict) -> bool:
    c = fnum(r.get("collect_s"))
    return c is not None and c > BACKLOG_S


def fnum(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def local(dt: datetime | None) -> str:
    return dt.astimezone().strftime("%d/%m %H:%M:%S") if dt else ""


def pct(values: list[float], p: float) -> float:
    s = sorted(values)
    k = (len(s) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def summarize(rows: list[dict], col: str) -> dict | None:
    vals = [v for v in (fnum(r.get(col)) for r in rows) if v is not None]
    if not vals:
        return None
    return {"n": len(vals), "min": min(vals), "median": statistics.median(vals), "mean": statistics.fmean(vals),
            "p95": pct(vals, 0.95), "max": max(vals)}


def fmt(s: dict | None) -> str:
    return f"{s['median']:.1f} / {s['p95']:.1f} / {s['max']:.1f}" if s else "–"


def load(since: datetime | None):
    rdir = results_dir()
    lat_path, al_path = rdir / "latency.csv", rdir / "alerts_log.csv"
    lat = list(csv.DictReader(open(lat_path, encoding="utf-8-sig"))) if lat_path.exists() else []
    alerts = list(csv.DictReader(open(al_path, encoding="utf-8-sig"))) if al_path.exists() else []
    if since:
        lat = [r for r in lat if (parse_time(r["batch_utc"]) or since) >= since]
        alerts = [a for a in alerts if (parse_time(a["time_utc"]) or since) >= since]
    return rdir, lat, alerts


def recompute(lat: list[dict]) -> dict[str, float]:
    """Bù lệch đồng hồ bằng giá trị nhỏ nhất theo từng client, tính lại e2e + thêm cột truyền tải."""
    offsets: dict[str, float] = {}
    for r in lat:
        o = fnum(r.get("clock_offset_s"))
        if o is not None and r.get("clock_basis") == "offset_from_client_sent":
            offsets[r["client_id"]] = min(o, offsets.get(r["client_id"], o))
    for r in lat:
        off = offsets.get(r["client_id"], 0.0)
        shift = timedelta(seconds=off)
        done = parse_time(r.get("done_utc"))
        ef, el = parse_time(r.get("event_first_client")), parse_time(r.get("event_last_client"))
        sent, recv = parse_time(r.get("client_sent_client")), parse_time(r.get("server_recv_utc"))
        r["e2e_first_s"] = round((done - (ef + shift)).total_seconds(), 3) if done and ef else ""
        r["e2e_last_s"] = round((done - (el + shift)).total_seconds(), 3) if done and el else ""
        r["transfer_s"] = round((recv - (sent + shift)).total_seconds(), 3) if recv and sent else ""
    return offsets


def match_alert(r: dict, alerts: list[dict]) -> dict:
    """Ghép dòng latency với dòng alerts_log cùng client, thời điểm gần ai_done nhất (<= 5 s)."""
    t = parse_time(r.get("ai_done_utc"))
    best, gap = {}, 5.0
    for a in alerts:
        ta = parse_time(a.get("time_utc"))
        if a.get("client_id") == r.get("client_id") and t and ta and abs((ta - t).total_seconds()) <= gap:
            best, gap = a, abs((ta - t).total_seconds())
    return best


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--since", help="Chỉ tính các lô từ thời điểm này (ISO, giờ UTC)")
    args = ap.parse_args()
    rdir, lat, alerts = load(parse_time(args.since) if args.since else None)
    if not lat:
        print(f"Chưa có dữ liệu trong {rdir / 'latency.csv'} — hãy chạy server + client trước.")
        return
    offsets = recompute(lat)

    backlog = [r for r in lat if is_backlog(r)]
    normal_ops = [r for r in lat if not is_backlog(r)]  # thống kê chính: vận hành bình thường
    sent_all = [r for r in lat if r.get("telegram_sent") == "True"]
    sent = [r for r in sent_all if not is_backlog(r)]
    groups = [
        ("**Cảnh báo đã gửi Telegram**", sent),
        ("ALERT bị chặn vì trùng", [r for r in normal_ops if r.get("alert_status") == "DUPLICATE"]),
        ("NORMAL (không cảnh báo)", [r for r in normal_ops if r.get("label") == "NORMAL"]),
        ("Tất cả các lô (vận hành bình thường)", normal_ops),
    ]
    t0, t1 = parse_time(lat[0]["batch_utc"]), parse_time(lat[-1]["batch_utc"])
    hosts = sorted({r["hostname"] for r in lat})

    L = [
        "# Báo cáo độ trễ cảnh báo & chống trùng — WinLog AI SOC",
        "",
        f"- **Phiên đo:** {local(t0)} → {local(t1)} (giờ máy server) · máy client: {', '.join(hosts)}",
        f"- **Số lô log:** {len(lat)} · trong đó {sum(int(r.get('events_security') or 0) for r in lat)} sự kiện Security"
        f" / {sum(int(r.get('events_total') or 0) for r in lat)} sự kiện tổng",
        f"- **Mô hình:** {', '.join(sorted({r['model'] for r in lat}))} · luồng: {', '.join(sorted({r['path'] for r in lat}))}",
        f"- **Lệch đồng hồ client − server (đã bù):** "
        + ", ".join(f"{c}: {-o:+.3f} s" for c, o in offsets.items()),
        "",
        "## 1. Độ trễ đầu-cuối (giây) — trung vị / P95 / lớn nhất",
        "",
        "| Nhóm | Số lô | " + " | ".join(n for _, n in E2E) + " |",
        "|---|---:|" + "---:|" * len(E2E),
    ]
    for name, rows in groups:
        L.append(f"| {name} | {len(rows)} | " + " | ".join(fmt(summarize(rows, c)) for c, _ in E2E) + " |")
    if backlog:
        L.append(f"| *Lô tồn đọng do server ngừng (không tính ở trên)* | {len(backlog)} | "
                 + " | ".join(fmt(summarize(backlog, c)) for c, _ in E2E) + " |")
        L += ["", f"> {len(backlog)} lô có sự kiện phải chờ ở client > {BACKLOG_S:.0f} s vì server tạm ngừng"
              " (agent giữ lại rồi gửi bù khi server chạy lại — không mất log). Đây không phải độ trễ khi vận hành"
              " bình thường nên được tách riêng; chi tiết đánh dấu ⚠ ở mục 3."]

    L += ["", "## 2. Phân rã độ trễ theo từng chặng (giây) — trung vị / P95 / lớn nhất", "",
          "| Nhóm | " + " | ".join(n for _, n in COMPONENTS) + " |", "|---|" + "---:|" * len(COMPONENTS)]
    for name, rows in groups[:3]:
        L.append(f"| {name} | " + " | ".join(fmt(summarize(rows, c)) for c, _ in COMPONENTS) + " |")
    if sent:
        means = {c: (summarize(sent, c) or {}).get("mean", 0) for c, _ in COMPONENTS}
        tot = sum(means.values()) or 1
        L += ["", "Tỉ trọng trung bình của từng chặng trong một cảnh báo đã gửi: "
              + " · ".join(f"{n} **{means[c] / tot:.0%}**" for c, n in COMPONENTS)]

    L += ["", "## 3. Chi tiết từng cảnh báo đã gửi Telegram", "",
          "| # | Giờ nhận (server) | Kỹ thuật MITRE | Trạng thái | Sự kiện (Security) | ① Gom | ④ AI | ⑤ Telegram | **Sự kiện đầu → cảnh báo** | Sự kiện cuối → cảnh báo |",
          "|---:|---|---|---|---:|---:|---:|---:|---:|---:|"]
    alert_rows = []
    for i, r in enumerate(sent_all, 1):
        a = match_alert(r, alerts)
        tech = a.get("new_techniques") or a.get("techniques") or ""
        mark = " ⚠ tồn đọng" if is_backlog(r) else ""
        L.append(f"| {i} | {local(parse_time(r['server_recv_utc']))}{mark} | {tech} | {r['alert_status']} | "
                 f"{r['events_total']} ({r['events_security']}) | {r['collect_s']} | {r['ai_s']} | {r['notify_s']} | "
                 f"**{r['e2e_first_s']}** | {r['e2e_last_s']} |")
        alert_rows.append({"stt": i, "server_recv_local": local(parse_time(r["server_recv_utc"])), "technique": tech,
                           "alert_status": r["alert_status"], "events_total": r["events_total"],
                           "events_security": r["events_security"], "collect_s": r["collect_s"],
                           "transfer_s": r["transfer_s"], "n8n_hop_s": r["n8n_hop_s"], "ai_s": r["ai_s"],
                           "notify_s": r["notify_s"], "e2e_first_s": r["e2e_first_s"], "e2e_last_s": r["e2e_last_s"],
                           "telegram_date_utc": r.get("telegram_date_utc", ""),
                           "backlog_after_outage": is_backlog(r)})

    n_sent = sum(1 for a in alerts if a.get("notify") == "True")
    n_dup = sum(1 for a in alerts if a.get("status") == "DUPLICATE")
    incidents = {i.strip() for a in alerts for i in (a.get("incident_ids") or "").split(";") if i.strip()}
    L += ["", "## 4. Chống trùng cảnh báo", "",
          "| Chỉ số | Giá trị |", "|---|---:|",
          f"| Số kết luận ALERT của AI | {len(alerts)} |",
          f"| Gửi Telegram (sự cố mới / có kỹ thuật mới) | {n_sent} |",
          f"| **Bị chặn vì trùng** (cùng máy + cùng kỹ thuật trong cửa sổ) | **{n_dup}** |",
          f"| Tỉ lệ cảnh báo trùng được chặn | {n_dup / len(alerts):.0%} |" if alerts else "| Tỉ lệ chặn | – |",
          f"| Số sự cố riêng biệt (máy + kỹ thuật MITRE) | {len(incidents)} |",
          f"| Cửa sổ gom trùng | {alerts[0]['window_minutes'] if alerts else '–'} phút (trượt) |",
          "",
          "## 5. Cách đọc số liệu", "",
          "- **Sự kiện đầu → cảnh báo**: từ lúc Windows ghi sự kiện SỚM nhất của lô (đồng hồ máy client, đã bù lệch)"
          " tới lúc node Telegram trong n8n gửi xong (n8n chỉ trả lời server sau node cuối cùng). Đây là con số chính.",
          "- **Sự kiện cuối → cảnh báo**: tính từ sự kiện MUỘN nhất của lô (thường là bước tấn công cuối cùng).",
          "- ① **Client gom & gửi**: agent quét log mỗi 5 s và gửi tuần tự; sự kiện sinh ra trong lúc agent đang"
          " chờ server trả lời lô trước sẽ phải đợi tới lô sau.",
          "- ② **Truyền tải**: mạng + bắt tay HTTPS + hàng đợi, sau khi đã bù lệch đồng hồ.",
          "- ③ **n8n gọi lại**: server -> webhook n8n -> n8n gọi lại /ingest.",
          "- ④ **AI phân tích**: bộ luật tương quan + mô hình Ollama local.",
          "- ⑤ **n8n + Telegram**: node IF + gọi Telegram Bot API. Cảnh báo trùng không gọi Telegram nên chặng này ≈ 0.",
          ""]

    out_md = rdir / "LATENCY_REPORT.md"
    out_md.write_text("\n".join(L), encoding="utf-8")

    summary = []
    for name, rows in groups + ([("Lô tồn đọng do server ngừng", backlog)] if backlog else []):
        for c, n in E2E + COMPONENTS:
            s = summarize(rows, c)
            if s:
                summary.append({"group": name.strip("*"), "metric": n, "column": c, "n": s["n"],
                                **{k: round(s[k], 3) for k in ("min", "median", "mean", "p95", "max")}})
    with open(rdir / "latency_summary.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=["group", "metric", "column", "n", "min", "median", "mean", "p95", "max"])
        w.writeheader(); w.writerows(summary)
    if alert_rows:
        with open(rdir / "latency_alerts.csv", "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=list(alert_rows[0].keys()))
            w.writeheader(); w.writerows(alert_rows)

    print("\n".join(L))
    print(f"[OK] Đã ghi {out_md}\n[OK] Đã ghi {rdir / 'latency_summary.csv'}"
          + (f"\n[OK] Đã ghi {rdir / 'latency_alerts.csv'}" if alert_rows else ""))


if __name__ == "__main__":
    main()
