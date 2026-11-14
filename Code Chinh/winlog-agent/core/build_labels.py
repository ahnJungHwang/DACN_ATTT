"""Gộp nhãn của MỌI ca kiểm thử trong repo thành một file CSV (mỗi ca một dòng).

Nguồn nhãn:
    data/, data01/, data100/, data_normal/   -> <ca>/manifest.json (ground_truth)
    eval_real/                               -> eval_real/labels.json (log thật, nhãn chốt trước khi chạy model)
Không gộp blind_test/blind_set (bản ẩn danh của data01 -> đếm trùng) và data/client_*_live (log realtime, chưa gán nhãn).

Xuất:
    labels/cases_labels.csv     mỗi ca một dòng: nhãn, kỹ thuật, nguồn, số sự kiện theo loại log, khung thời gian
    labels/LABELS_SUMMARY.md    số ca NORMAL / ALERT theo từng bộ + tỉ lệ log bình thường

Cách chạy (đứng ở thư mục gốc winlog-agent):
    .venv\\Scripts\\python.exe core\\build_labels.py
    .venv\\Scripts\\python.exe core\\build_labels.py --datasets data01 data_normal     (chỉ một số bộ)
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from alerting import event_time_range, iso  # noqa: E402

# bộ dữ liệu -> loại nguồn (để người đọc biết ca tự sinh hay log thật)
MANIFEST_SETS = {
    "data": "synthetic",            # bộ tự sinh đời đầu (generate_datasets.py)
    "data01": "synthetic",          # 40 ca chuẩn (generate_data01.py)
    "data100": "synthetic_mixed",   # ghép fragment data01 + EVTX thật + log live (generate_data100.py)
    "data_normal": "real_pc",       # log bình thường thật (ps1/export_normal_logs.ps1)
}
XML_FILES = {"security": "security.xml", "powershell": "powershell.xml", "system": "system.xml"}
_EVENT = re.compile(r"<Event[\s>]")  # khớp <Event ...> / <Event>, không khớp <EventID>, <EventData>

FIELDS = ["dataset", "case_id", "ground_truth", "category", "techniques", "source_type", "description",
          "security_events", "powershell_events", "system_events", "total_events",
          "first_event_utc", "last_event_utc", "anonymized", "label_basis", "files_present", "path"]


def count_events(case_dir: Path) -> dict:
    out, blobs = {}, []
    for key, fn in XML_FILES.items():
        p = case_dir / fn
        text = p.read_text(encoding="utf-8", errors="replace") if p.is_file() else ""
        out[f"{key}_events"] = len(_EVENT.findall(text))
        blobs.append(text)
    first, last = event_time_range(*blobs)
    out["total_events"] = sum(out.values())
    out["first_event_utc"], out["last_event_utc"] = iso(first), iso(last)
    out["files_present"] = all((case_dir / f).is_file() for f in ("security.xml", "powershell.xml"))
    return out


def norm_label(v) -> str:
    v = str(v or "").strip().upper()
    return v if v in ("ALERT", "NORMAL") else (v or "UNKNOWN")


def rows_from_manifests(name: str) -> list[dict]:
    base = ROOT / name
    if not base.is_dir():
        return []
    rows = []
    for d in sorted(p for p in base.iterdir() if p.is_dir() and not p.name.endswith("_live")):
        mf = d / "manifest.json"
        if not mf.is_file():
            continue
        m = json.loads(mf.read_text(encoding="utf-8-sig"))
        stages = m.get("expected_stages") or []
        rows.append({
            "dataset": name, "case_id": m.get("case_id", d.name), "ground_truth": norm_label(m.get("ground_truth")),
            "category": m.get("category", ""), "techniques": "; ".join(stages) if isinstance(stages, list) else str(stages),
            "source_type": m.get("source") or MANIFEST_SETS.get(name, ""),
            "description": re.sub(r"\s+", " ", str(m.get("actions", ""))).strip(),
            "anonymized": m.get("anonymized", ""), "label_basis": "manifest.json",
            "path": d.relative_to(ROOT).as_posix(), **count_events(d),
        })
    return rows


def rows_from_eval_real() -> list[dict]:
    lp = ROOT / "eval_real" / "labels.json"
    if not lp.is_file():
        return []
    labels = json.loads(lp.read_text(encoding="utf-8"))
    rows = []
    for c in labels.get("cases", []):
        d = ROOT / "eval_real" / "cases" / c["case_id"]
        counts = count_events(d) if d.is_dir() else {
            "security_events": "", "powershell_events": "", "system_events": "", "total_events": "",
            "first_event_utc": "", "last_event_utc": "", "files_present": False}
        rows.append({
            "dataset": "eval_real", "case_id": c["case_id"], "ground_truth": norm_label(c.get("ground_truth")),
            "category": c.get("category", ""), "techniques": c.get("technique", ""),
            "source_type": f"real_evtx:{c.get('source', '')}", "description": c.get("file", ""),
            "anonymized": False, "label_basis": c.get("label_basis", "eval_real/labels.json"),
            "path": f"eval_real/cases/{c['case_id']}", **counts,
        })
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--datasets", nargs="*", default=list(MANIFEST_SETS) + ["eval_real"],
                    help="Các bộ cần gộp (mặc định: tất cả)")
    ap.add_argument("--out-dir", default=str(ROOT / "labels"))
    args = ap.parse_args()

    rows = []
    for name in args.datasets:
        rows += rows_from_eval_real() if name == "eval_real" else rows_from_manifests(name)
    if not rows:
        print("Không tìm thấy ca nào có nhãn.")
        return

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "cases_labels.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

    # ---- tóm tắt
    per = defaultdict(Counter)
    events = defaultdict(Counter)
    for r in rows:
        per[r["dataset"]][r["ground_truth"]] += 1
        for k in ("security_events", "total_events"):
            events[r["dataset"]][k] += int(r[k] or 0)
    total = Counter()
    for c in per.values():
        total.update(c)

    TARGET = 0.85  # tỉ lệ NORMAL mục tiêu (thực tế: phần lớn log là bình thường)

    def ratio(c: Counter) -> str:
        n = c["NORMAL"] + c["ALERT"]
        return f"{c['NORMAL'] / n:.0%}" if n else "–"

    def need(c: Counter) -> int:
        """Số ca NORMAL cần THÊM để bộ này đạt TARGET (giữ nguyên số ca ALERT)."""
        return max(0, -(-c["ALERT"] * round(TARGET * 100) // round((1 - TARGET) * 100)) - c["NORMAL"])

    L = ["# Tổng hợp nhãn bộ đánh giá", "",
         f"> Tạo lúc {datetime.now().strftime('%d/%m/%Y %H:%M')} bằng `core/build_labels.py`. "
         "Chi tiết từng ca: [`cases_labels.csv`](cases_labels.csv).", "",
         f"| Bộ dữ liệu | Loại nguồn | Số ca | NORMAL | ALERT | Không chấm điểm | **Tỉ lệ bình thường** | "
         f"Cần thêm NORMAL để đạt {TARGET:.0%} | Sự kiện Security / tổng |",
         "|---|---|---:|---:|---:|---:|---:|---:|---:|"]
    for name, c in per.items():
        src = MANIFEST_SETS.get(name, "real_evtx")
        other = sum(v for k, v in c.items() if k not in ("NORMAL", "ALERT"))
        L.append(f"| {name} | {src} | {sum(c.values())} | {c['NORMAL']} | {c['ALERT']} | {other} | **{ratio(c)}** | "
                 f"{need(c)} | {events[name]['security_events']} / {events[name]['total_events']} |")
    other = sum(v for k, v in total.items() if k not in ("NORMAL", "ALERT"))
    L.append(f"| **Tổng (có trùng lặp, chỉ để tham khảo)** | | **{sum(total.values())}** | {total['NORMAL']} | "
             f"{total['ALERT']} | {other} | {ratio(total)} | | |")
    missing = [r for r in rows if not r["files_present"]]
    L += ["", "## Ghi chú", "",
          f"- Yêu cầu đánh giá: **phần lớn là log bình thường** (gần thực tế). Mục tiêu đề xuất: ≥ {TARGET:.0%} NORMAL.",
          "- Mỗi lần đánh giá dùng **từng bộ riêng** (hoặc một bộ ghép có chủ đích), không cộng dồn mọi bộ: "
          "`data100` được ghép từ fragment của `data01`, nên dòng Tổng có trùng lặp.",
          "- Log bình thường thu thêm bằng `ps1/export_normal_logs.ps1` (lưu vào `data_normal/`), rồi chạy lại script này.",
          "- **Không chấm điểm** = nhãn `UNKNOWN`: nguồn không mô tả nội dung (vd 2 ca `eval_real` loại `unlabeled`), "
          "cố ý không tính vào chỉ số.",
          "- `source_type`: `synthetic` = log tự sinh; `synthetic_mixed` = ghép từ fragment thật/tự sinh; "
          "`real_pc` = log thật trên máy cá nhân; `real_evtx` = mẫu EVTX tấn công công khai.",
          "- Không gộp `blind_test/blind_set` (bản ẩn danh của data01) và `data/client_*_live` (log realtime chưa gán nhãn).",
          ]
    if missing:
        L.append(f"- {len(missing)} ca chưa có file XML trên máy (vd `eval_real/cases`, tạo lại bằng "
                 "`eval_real/build_cases.ps1`); vẫn giữ dòng nhãn trong CSV, cột `files_present` = False.")
    (out / "LABELS_SUMMARY.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n".join(L))
    print(f"\n[OK] {len(rows)} ca -> {out / 'cases_labels.csv'}\n[OK] {out / 'LABELS_SUMMARY.md'}")


if __name__ == "__main__":
    main()
