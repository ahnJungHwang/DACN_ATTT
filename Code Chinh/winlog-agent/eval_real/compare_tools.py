"""Bảng so sánh công cụ trên CÙNG bộ log thật: DeepBlueCLI (không dùng AI) với hệ thống của nhóm (Qwen / Llama).

Đọc  eval_real/deepblue_results.csv   (do run_deepblue.ps1 ghi)
     eval_real/real_log_results.csv   (do run_eval.py ghi)
Ghi  eval_real/SO_SANH_CONG_CU.md

Cách chấm DeepBlueCLI: có >= 1 phát hiện -> ALERT. Riêng ca mà MỌI phát hiện chỉ là "Log Clear" thì tính là
KHÔNG bắt được: sự kiện xoá log trong các bộ mẫu là dấu vết người tạo mẫu dọn log, hệ thống của nhóm đã loại nó
(build_cases.ps1), nên tính cho DeepBlueCLI là không công bằng. Cột "thô" vẫn được in để đối chiếu.

    .venv\Scripts\python.exe eval_real\compare_tools.py
"""
import csv
import statistics
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
GROUPS = [("scored", "Tấn công thật, có dấu vết trong log agent thu"),
          ("coverage", "Độ phủ mới (7045 / 4720 / 4728 / 4732)"),
          ("out_of_scope", "Tấn công nằm ở log agent KHÔNG thu"),
          ("normal_session", "Phiên hoạt động bình thường (đo báo động giả)")]


def read(name: str) -> list[dict]:
    p = HERE / name
    return list(csv.DictReader(open(p, encoding="utf-8-sig"))) if p.exists() else []


def frac(k: int, n: int) -> str:
    return f"{k}/{n} = {k / n:.0%}" if n else "chưa có dữ liệu"


def main() -> None:
    dbc = {r["case_id"]: r for r in read("deepblue_results.csv")}
    for r in dbc.values():
        r["fair"] = "NORMAL" if r.get("log_clear_only") == "True" else r["pred_label"]

    runs = defaultdict(lambda: defaultdict(list))  # model -> case_id -> các lượt chạy
    for r in read("real_log_results.csv"):
        runs[r["model"]][r["case_id"]].append(r)
    models = sorted(runs)

    def vote(model: str, cid: str, key: str) -> str:
        rr = runs[model].get(cid)
        return Counter(r[key] for r in rr).most_common(1)[0][0] if rr else "-"

    md = ["# So sánh công cụ trên log Windows thật",
          f"**Lập lúc:** `{datetime.now():%Y-%m-%d %H:%M}` · sinh tự động bởi `eval_real/compare_tools.py`, không sửa tay.",
          "",
          "- **DeepBlueCLI**: công cụ dò theo luật, không dùng AI. Đọc **toàn bộ** file `.evtx`.",
          "- **Hệ thống của nhóm**: chỉ đọc các mã sự kiện agent thu (tối đa 300 sự kiện mỗi ca); kết quả mỗi ca lấy theo đa số các lượt chạy.",
          "- Ký hiệu `-`: ca không chạy được (file XML bị Microsoft Defender cách ly, hoặc log nằm ngoài phạm vi agent thu).",
          "- Hai nguồn mẫu chỉ có log tấn công. Báo động giả chỉ đo được khi có file trong `eval_real/normal_evtx/`.",
          "",
          "## 1. Tổng hợp",
          "",
          "| Nhóm ca | DeepBlueCLI | DeepBlueCLI (thô, tính cả xoá log) | "
          + " | ".join(f"{m}: hệ thống | {m}: riêng AI | {m}: chỉ luật" for m in models) + " |",
          "|---|---|---|" + "---|" * (3 * len(models))]
    for g, title in GROUPS:
        cs = [r for r in dbc.values() if r["category"] == g and r["ground_truth"] in ("ALERT", "NORMAL")]
        want = "NORMAL" if g == "normal_session" else "ALERT"
        cells = [frac(sum(r["fair"] == want for r in cs), len(cs)), frac(sum(r["pred_label"] == want for r in cs), len(cs))]
        for m in models:
            done = [r["case_id"] for r in cs if r["case_id"] in runs[m]]
            cells += [frac(sum(vote(m, c, k) == want for c in done), len(done)) for k in ("system", "ai_only", "rule_any")]
        md.append(f"| {title} ({'đúng NORMAL' if want == 'NORMAL' else 'bắt được'}) | " + " | ".join(cells) + " |")

    # So trên đúng những ca mà cả hai bên cùng chạy được
    for m in models:
        both = [c for c, r in dbc.items() if r["category"] in ("scored", "coverage") and c in runs[m]]
        md += ["", f"Chỉ tính {len(both)} ca tấn công mà cả DeepBlueCLI và `{m}` cùng chạy được: "
               f"DeepBlueCLI {frac(sum(dbc[c]['fair'] == 'ALERT' for c in both), len(both))}, "
               f"hệ thống {frac(sum(vote(m, c, 'system') == 'ALERT' for c in both), len(both))}, "
               f"riêng AI {frac(sum(vote(m, c, 'ai_only') == 'ALERT' for c in both), len(both))}, "
               f"chỉ luật {frac(sum(vote(m, c, 'rule_any') == 'ALERT' for c in both), len(both))}."]

    md += ["", "## 2. Thời gian xử lý mỗi ca", "", "| Công cụ | Trung vị (s) | Lớn nhất (s) |", "|---|---:|---:|"]
    t = [float(r["elapsed_seconds"]) for r in dbc.values()]
    if t:
        md.append(f"| DeepBlueCLI | {statistics.median(t):.1f} | {max(t):.1f} |")
    for m in models:
        t = [float(r["seconds"]) for rr in runs[m].values() for r in rr]
        md.append(f"| {m} (hệ thống) | {statistics.median(t):.1f} | {max(t):.1f} |")
    md += ["", "Thời gian của hệ thống gồm cả lúc chờ GPU nguội nếu chạy có giới hạn nhiệt, nên chỉ để tham khảo; "
           "độ trễ từ lúc sinh sự kiện tới lúc nhận Telegram xem `results/LATENCY_REPORT.md`.",
           "", "## 3. Chi tiết từng ca", "",
           "| Ca | Nhóm | Nhãn | DeepBlueCLI | Số phát hiện | " + " | ".join(f"{m}: hệ thống | {m}: riêng AI | {m}: chỉ luật" for m in models) + " | DeepBlueCLI thấy gì |",
           "|---|---|:---:|:---:|---:|" + ":---:|" * (3 * len(models)) + "---|"]
    for cid, r in dbc.items():
        d = r["fair"] + (" (chỉ xoá log)" if r.get("log_clear_only") == "True" else "") + (f" LỖI: {r['error']}" if r["error"] else "")
        ours = [vote(m, cid, k) for m in models for k in ("system", "ai_only", "rule_any")]
        md.append(f"| `{cid}` | {r['category']} | {r['ground_truth']} | {d} | {r['detections']} | " + " | ".join(ours) + f" | {r['messages']} |")
    md.append("")
    out = HERE / "SO_SANH_CONG_CU.md"
    out.write_text("\n".join(md), encoding="utf-8")
    print(f"Da ghi {out}")


if __name__ == "__main__":
    main()
