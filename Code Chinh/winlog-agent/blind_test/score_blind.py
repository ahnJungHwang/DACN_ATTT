"""
Chấm điểm bộ kiểm thử mù sau khi máy ảo đã gửi các ca về server.

Nguồn dự đoán (theo thứ tự ưu tiên):
  1. results/client_<prefix><Bxxx>_live/<model>_*.json  (server tự lưu sau khi AI phân tích)
  2. replay_log.csv chép từ máy ảo (nhãn server trả về trong response)
Ca không tìm thấy kết quả được đánh dấu MISSING và không tính vào chỉ số.

Ví dụ:
    .venv\\Scripts\\python.exe blind_test\\score_blind.py --model qwen --replay-log blind_test\\replay_log.csv
"""
import argparse
import csv
import json
import statistics
import sys
from datetime import datetime
from pathlib import Path

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent


def read_csv(path: Path) -> list[dict]:
    with path.open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def latest_result(results_dir: Path, client_id: str, model: str, since: str | None) -> dict | None:
    folder = results_dir / f"client_{client_id}_live"
    if not folder.is_dir():
        return None
    files = sorted(folder.glob(f"{model}_*.json"))
    if since:
        stamp = since.replace("-", "").replace(":", "")
        files = [f for f in files if f.stem.split("_", 1)[1] >= stamp]
    if not files:
        return None
    data = json.loads(files[-1].read_text(encoding="utf-8"))
    result = data.get("result", {})
    verdict = result.get("verdict", {})
    return {
        "pred": verdict.get("label", "UNKNOWN"),
        "stages": "; ".join(verdict.get("detected_stages", [])),
        "elapsed": result.get("elapsed_seconds"),
        "source": files[-1].name,
    }


def metrics(rows: list[dict]) -> dict:
    scored = [r for r in rows if r["pred"] != "MISSING"]
    tp = sum(r["gt"] == "ALERT" and r["pred"] == "ALERT" for r in scored)
    fp = sum(r["gt"] == "NORMAL" and r["pred"] == "ALERT" for r in scored)
    tn = sum(r["gt"] == "NORMAL" and r["pred"] == "NORMAL" for r in scored)
    fn = sum(r["gt"] == "ALERT" and r["pred"] != "ALERT" for r in scored)  # UNKNOWN trên ca tấn công = bỏ sót
    unk_normal = sum(r["gt"] == "NORMAL" and r["pred"] not in ("ALERT", "NORMAL") for r in scored)
    n_alert = sum(r["gt"] == "ALERT" for r in scored)
    n_normal = sum(r["gt"] == "NORMAL" for r in scored)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / n_alert if n_alert else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    lat = [float(r["elapsed"]) for r in scored if r["elapsed"] not in (None, "")]
    return {
        "total": len(rows), "scored": len(scored), "missing": len(rows) - len(scored),
        "n_alert": n_alert, "n_normal": n_normal,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn, "unknown_on_normal": unk_normal,
        "precision": precision, "recall": recall, "f1": f1,
        "accuracy": (tp + tn) / len(scored) if scored else 0.0,
        "specificity": tn / n_normal if n_normal else 0.0,
        "median_latency": statistics.median(lat) if lat else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Chấm điểm bộ kiểm thử mù.")
    parser.add_argument("--key", default="blind_test/answer_key.csv")
    parser.add_argument("--results", default="results", help="Thư mục results của server")
    parser.add_argument("--replay-log", default=None, help="replay_log.csv chép từ máy ảo")
    parser.add_argument("--model", default="qwen", choices=["qwen", "llama"])
    parser.add_argument("--prefix", default="blind_")
    parser.add_argument("--since", default=None,
                        help="Chỉ lấy kết quả từ thời điểm này (UTC, dạng 20261107T090000)")
    parser.add_argument("--baseline", default="results/comparison_details.csv",
                        help="Kết quả đánh giá có nhãn trước đây để so sánh")
    parser.add_argument("--out", default=None, help="File báo cáo (mặc định: blind_test/BLIND_REPORT_<model>.md)")
    args = parser.parse_args()

    key_rows = read_csv(ROOT / args.key)
    results_dir = ROOT / args.results
    replay = {}
    if args.replay_log:
        for r in read_csv(Path(args.replay_log)):
            if r.get("model", args.model) == args.model:
                replay[r["blind_id"]] = r
    baseline = {}
    base_path = ROOT / args.baseline
    if base_path.is_file():
        for r in read_csv(base_path):
            if r.get("model_key") == args.model:
                baseline[r["case_id"]] = r["pred_label"]

    rows = []
    for k in key_rows:
        client_id = f"{args.prefix}{k['blind_id']}"
        res = latest_result(results_dir, client_id, args.model, args.since)
        if res is None and k["blind_id"] in replay and replay[k["blind_id"]].get("label"):
            rr = replay[k["blind_id"]]
            res = {"pred": rr["label"], "stages": rr.get("stages", ""),
                   "elapsed": rr.get("elapsed_s"), "source": "replay_log"}
        if res is None:
            res = {"pred": "MISSING", "stages": "", "elapsed": None, "source": "-"}
        rows.append({
            "blind_id": k["blind_id"], "case_id": k["case_id"], "category": k["category"],
            "gt": k["ground_truth"], "pred": res["pred"], "stages": res["stages"],
            "elapsed": res["elapsed"], "source": res["source"],
            "baseline": baseline.get(k["case_id"], ""),
        })

    m = metrics(rows)
    pct = lambda x: f"{x * 100:.1f}%"
    lines = [
        f"# Kết quả kiểm thử mù ({args.model})",
        f"Chấm lúc: `{datetime.now():%Y-%m-%d %H:%M:%S}` · Số ca: {m['total']} "
        f"(chấm được {m['scored']}, thiếu kết quả {m['missing']})",
        "",
        "| Chỉ số | Giá trị |", "|---|:-:|",
        f"| Precision | {pct(m['precision'])} |",
        f"| Recall | {pct(m['recall'])} |",
        f"| F1 | {m['f1']:.3f} |",
        f"| Accuracy | {pct(m['accuracy'])} |",
        f"| Specificity (nhận đúng ca bình thường) | {pct(m['specificity'])} |",
        f"| TP / FP / TN / FN | {m['tp']} / {m['fp']} / {m['tn']} / {m['fn']} |",
        f"| UNKNOWN trên ca bình thường | {m['unknown_on_normal']} |",
        f"| Độ trễ trung vị | {m['median_latency']:.2f}s |" if m["median_latency"] else "| Độ trễ trung vị | - |",
        "",
        "## Chi tiết từng ca",
        "| Mã mù | Ca gốc | Nhóm | Nhãn đúng | Dự đoán | Kết quả | Lần chạy có nhãn trước | Giai đoạn phát hiện |",
        "|---|---|---|:-:|:-:|:-:|:-:|---|",
    ]
    changed = 0
    for r in rows:
        ok = "-" if r["pred"] == "MISSING" else ("✅" if r["pred"] == r["gt"] else "❌")
        base = r["baseline"]
        if base and r["pred"] != "MISSING" and base != r["pred"]:
            changed += 1
            base = f"**{base}** (khác)"
        lines.append(f"| {r['blind_id']} | `{r['case_id']}` | {r['category']} | {r['gt']} | "
                     f"{r['pred']} | {ok} | {base or '-'} | {r['stages'] or '-'} |")
    if baseline:
        lines += ["", f"Số ca có kết quả khác so với lần đánh giá có nhãn: **{changed}**"]

    out = Path(args.out) if args.out else HERE / f"BLIND_REPORT_{args.model}.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"Model {args.model}: chấm {m['scored']}/{m['total']} ca (thiếu {m['missing']})")
    print(f"  Precision {pct(m['precision'])} | Recall {pct(m['recall'])} | F1 {m['f1']:.3f} | "
          f"Accuracy {pct(m['accuracy'])} | Specificity {pct(m['specificity'])}")
    print(f"  TP={m['tp']} FP={m['fp']} TN={m['tn']} FN={m['fn']} UNKNOWN(normal)={m['unknown_on_normal']}")
    if baseline:
        print(f"  Khác với lần đánh giá có nhãn: {changed} ca")
    print(f"[OK] Báo cáo: {out}")
    if m["missing"]:
        print("[!] Có ca thiếu kết quả: kiểm tra server log, hoặc truyền --replay-log.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
