"""
Đánh giá hệ thống trên LOG THẬT (DeepBlueCLI, EVTX-to-MITRE).

- Nhãn lấy từ eval_real/labels.json (chốt trước khi chạy model).
- Mỗi ca 'scored' chạy lặp N lần để đo độ ổn định của mô hình.
- So sánh 3 cách: Hệ thống (luật mạnh + AI), Riêng AI, Chỉ luật (không dùng AI).
- Chỉ số kèm khoảng tin cậy 95% (Wilson).

Cách chạy:  .venv\\Scripts\\python.exe eval_real\\run_eval.py --models qwen --repeats 3
"""
import argparse
import csv
import json
import statistics
import sys
import time
from collections import Counter
from datetime import datetime
from math import sqrt
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import analyze as A  # noqa: E402

CASES_DIR = HERE / "cases"


def wilson(k: int, n: int, z: float = 1.96) -> str:
    if n == 0:
        return "n/a"
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return f"{p:.1%} ({k}/{n}; KTC95% {max(0.0, c - h):.0%}–{min(1.0, c + h):.0%})"


def ai_label_of(result: dict) -> str:
    labels = [b["verdict"]["label"] for b in result.get("batch_results", [])]
    if "ALERT" in labels:
        return "ALERT"
    if labels and all(x == "NORMAL" for x in labels):
        return "NORMAL"
    return "UNKNOWN"


def rule_labels(case_dir: Path) -> tuple[str, str]:
    events = [e for e in A.read_events(case_dir) if not A.is_benign_noise(e)] or A.read_events(case_dir)
    f = A.correlate_security_events(events)
    return ("ALERT" if f["stages"] else "NORMAL"), ("ALERT" if f["strong_stages"] else "NORMAL")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", default="qwen")
    ap.add_argument("--repeats", type=int, default=3)
    args = ap.parse_args()

    labels = json.loads((HERE / "labels.json").read_text(encoding="utf-8"))
    def complete(c: dict) -> bool:
        d = CASES_DIR / c["case_id"]
        return all((d / f).exists() for f in ("manifest.json", "security.xml", "powershell.xml", "system.xml"))

    cases = [c for c in labels["cases"] if complete(c)]
    # File bị thiếu sau khi tạo: thường do antivirus cách ly (nội dung mã độc thật) -> loại khỏi điểm, ghi vào báo cáo
    args.av_blocked = [c for c in labels["cases"] if (CASES_DIR / c["case_id"] / "manifest.json").exists() and not complete(c)]
    rows = []

    for model_key in [m.strip() for m in args.models.split(",") if m.strip()]:
        for c in cases:
            cdir = CASES_DIR / c["case_id"]
            man = json.loads((cdir / "manifest.json").read_text(encoding="utf-8-sig"))
            rule_any, rule_strong = rule_labels(cdir)
            reps = args.repeats if c["category"] in ("scored", "coverage") else 1
            for rep in range(1, reps + 1):
                t = time.perf_counter()
                try:
                    r = A.analyze_case(c["case_id"], model_key=model_key, data_dir=CASES_DIR)
                    v = r["verdict"]
                    sys_label, ai_label, src = v["label"], ai_label_of(r), v.get("decision_source", "")
                    stages = "; ".join(v.get("detected_stages", []))
                    nb, err = r.get("batch_count", 0), "; ".join(r.get("errors", []))
                except Exception as exc:  # noqa: BLE001
                    sys_label = ai_label = "ERROR"
                    src, stages, nb, err = "error", "", 0, str(exc)
                el = round(time.perf_counter() - t, 2)
                row = {
                    "model": model_key, "case_id": c["case_id"], "category": c["category"],
                    "ground_truth": c["ground_truth"], "technique": c.get("technique", ""),
                    "dual_use": bool(c.get("dual_use")), "events": man["security_count"] + man["powershell_count"] + man.get("system_count", 0),
                    "truncated": bool(man.get("truncated_to_first")), "repeat": rep,
                    "system": sys_label, "ai_only": ai_label, "rule_any": rule_any, "rule_strong": rule_strong,
                    "decision_source": src, "batches": nb, "seconds": el, "stages": stages, "error": err,
                }
                rows.append(row)
                print(f"[{model_key}] {c['case_id']:34} lan {rep} GT={c['ground_truth']:6} HT={sys_label:7} "
                      f"AI={ai_label:7} LUAT={rule_any:6} nguon={src:8} {nb} lo {el}s", flush=True)

    write_outputs(rows, labels, args)


def write_outputs(rows: list[dict], labels: dict, args) -> None:
    out_csv = HERE / "real_log_results.csv"
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    md = [
        "# Đánh giá trên log Windows THẬT (DeepBlueCLI + EVTX-to-MITRE)",
        f"**Thời gian:** `{datetime.now():%Y-%m-%d %H:%M:%S}` · **Số lần lặp mỗi ca:** {args.repeats} · "
        f"**Nhãn:** `eval_real/labels.json` (chốt trước khi chạy model, theo mô tả của nguồn)",
        "",
        "## 1. Phạm vi dữ liệu",
        "",
        "| Nhóm | Số ca | Ghi chú |",
        "|---|:---:|---|",
    ]
    cat = Counter(c["category"] for c in labels["cases"])
    md += [
        f"| Tính điểm (`scored`) | {cat['scored']} | Tấn công thật, có dấu vết trong log agent thu (4624/4625/4648/4688/4104) |",
        f"| Độ phủ mới (`coverage`) | {cat['coverage']} | Trước đây ngoài phạm vi; nay agent thu 7045 / 4720 / 4728 / 4732 |",
        f"| Không đủ bằng chứng | {cat['insufficient_evidence']} | Nguồn nói là tấn công nhưng phần log agent thu chỉ có vài 4624 |",
        f"| Không có nhãn | {cat['unlabeled']} | Nguồn không mô tả; chỉ quan sát |",
        f"| **Ngoài phạm vi agent** | {len(labels['out_of_scope'])} | Tấn công chỉ để lại dấu vết ở log agent KHÔNG thu |",
        f"| Bị antivirus chặn | {len(args.av_blocked)} | "
        + (", ".join(f"`{c['case_id']}`" for c in args.av_blocked) or "-")
        + " — Microsoft Defender cách ly file XML chứa mã độc thật; không tắt Defender, loại khỏi điểm |",
        "",
        "**Lưu ý quan trọng:** cả hai nguồn chỉ chứa log TẤN CÔNG, nên bộ này đo được **Recall (khả năng bắt tấn công)** "
        "nhưng **không đo được báo động giả**. Báo động giả phải đo bằng log hoạt động bình thường thu từ máy thật (bước 2).",
        "",
    ]

    for model in sorted({r["model"] for r in rows}):
      md += [f"## 2. Kết quả — `{model}` ({A.MODELS[model]})", ""]
      for group, title in (("scored", "Ca tấn công thật (bộ gốc 14 ca)"),
                           ("coverage", "Ca độ phủ mới (sau khi mở rộng thu thập)")):
        sc = [r for r in rows if r["model"] == model and r["category"] == group]
        if not sc:
            continue
        n_case = len({r["case_id"] for r in sc})
        md += [f"### {title}", "",
               "Recall tính theo từng lượt chạy:", "",
               "| Cách phát hiện | Recall | ",
               "|---|---|"]
        for key, name in (("system", "**Hệ thống** (luật mạnh + AI + tự thẩm định)"),
                          ("ai_only", "Riêng AI"),
                          ("rule_any", "Chỉ luật (mọi tín hiệu)"),
                          ("rule_strong", "Chỉ luật mạnh")):
            k = sum(1 for r in sc if r[key] == "ALERT")
            md.append(f"| {name} | {wilson(k, len(sc))} |")
        # theo ca (đa số phiếu) và độ ổn định
        stable = 0
        per_case = []
        for cid in dict.fromkeys(r["case_id"] for r in sc):
            rr = [r for r in sc if r["case_id"] == cid]
            sysl = Counter(r["system"] for r in rr)
            ail = Counter(r["ai_only"] for r in rr)
            if len(sysl) == 1 and len(ail) == 1:
                stable += 1
            per_case.append((cid, rr[0], sysl, ail, statistics.mean(r["seconds"] for r in rr)))
        maj = sum(1 for _, _, s, _, _ in per_case if s.most_common(1)[0][0] == "ALERT")
        md += ["",
               f"- Theo ca (đa số phiếu {args.repeats} lần): hệ thống bắt được **{wilson(maj, n_case)}**.",
               f"- **Độ ổn định:** {stable}/{n_case} ca cho cùng một kết quả (hệ thống và AI) ở mọi lần chạy.",
               f"- Lỗi kỹ thuật: {sum(1 for r in sc if r['system'] == 'ERROR')} lượt.",
               f"- Thời gian trung vị mỗi ca: {statistics.median(r['seconds'] for r in sc):.1f}s.",
               "",
               "Chi tiết từng ca:",
               "",
               "| Ca | Kỹ thuật | Sự kiện | Hệ thống | Riêng AI | Chỉ luật | Nguồn quyết định | TG TB (s) |",
               "|---|---|:---:|:---:|:---:|:---:|:---:|:---:|"]
        for cid, r0, sysl, ail, sec in per_case:
            fmt = lambda cnt: ", ".join(f"{k}×{v}" for k, v in cnt.most_common())  # noqa: E731
            src = Counter(r["decision_source"] for r in sc if r["case_id"] == cid)
            mark = " ⚠️dual-use" if r0["dual_use"] else ""
            trunc = " (cắt 300)" if r0["truncated"] else ""
            md.append(f"| `{cid}`{mark} | {r0['technique']} | {r0['events']}{trunc} | {fmt(sysl)} | {fmt(ail)} | "
                      f"{r0['rule_any']} | {fmt(src)} | {sec:.1f} |")
        md.append("")
      other = [r for r in rows if r["model"] == model and r["category"] not in ("scored", "coverage")]
      if other:
          md += ["### Ca không tính điểm (quan sát)", "",
                 "| Ca | Nhóm | Sự kiện | Hệ thống | Riêng AI | Chỉ luật |", "|---|---|:---:|:---:|:---:|:---:|"]
          for r in other:
              md.append(f"| `{r['case_id']}` | {r['category']} | {r['events']} | {r['system']} | {r['ai_only']} | {r['rule_any']} |")
          md.append("")

    md += ["## 3. Tấn công nằm ngoài phạm vi thu thập của agent", "",
           "Các mẫu dưới đây là tấn công thật nhưng agent hiện **không thể phát hiện** vì không thu loại log tương ứng:", "",
           "| File | Kỹ thuật | Cần thu thêm |", "|---|---|---|"]
    md += [f"| `{o['file']}` | {o['technique']} | {o['needed_logs']} |" for o in labels["out_of_scope"]]
    md += ["", f"CSV chi tiết từng lượt: `eval_real/{out_csv.name}`.", ""]
    (HERE / "REAL_LOG_REPORT.md").write_text("\n".join(md), encoding="utf-8")
    print(f"\nDa ghi: {HERE / 'REAL_LOG_REPORT.md'} va {out_csv}")


if __name__ == "__main__":
    main()
