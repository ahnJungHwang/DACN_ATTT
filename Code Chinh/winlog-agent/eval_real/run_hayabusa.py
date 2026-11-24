"""
Chạy Hayabusa (engine Sigma thật, ~5.000 luật SigmaHQ + Hayabusa) trên cùng các ca với DeepBlueCLI:
ca có nhãn trong labels.json + out_of_scope + mỗi thư mục con của cases/_normal_evtx (ca bình thường).

- Nạp 5.000 luật mất ~1 phút/lần -> chạy MỘT lần cho mỗi thư mục evtx (profile eval-noscript tự thêm vào config/profiles.yaml: chỉ tên luật, mức, EvtxFile -
  không chép nội dung sự kiện để Defender không chặn file kết quả),
  rồi gán phát hiện về từng ca theo tên file (ca tấn công) hoặc thư mục cha (ca bình thường).
- hayabusa dfir-timeline -w: không hỏi, mọi luật trừ nhóm "noisy"; nạp luật từ mức low.
- Nhãn: ALERT nếu có phát hiện mức >= --alert-level (mặc định medium), ngược lại NORMAL.
- log_clear_only = True khi mọi phát hiện từ mức đó trở lên chỉ là xoá log (dấu vết người tạo mẫu; chấm như DeepBlueCLI).
- Hayabusa chỉ ĐỌC evtx. Công cụ đặt ở tools_rule_baseline/hayabusa-<ver>/app (không đưa vào repo).

Cách chạy:  .venv\\Scripts\\python.exe eval_real\\run_hayabusa.py --out eval_real\\hayabusa_results_24112026.csv
"""
import argparse
import csv
import json
import re
import subprocess
import tempfile
import time
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
LEVELS = ["informational", "low", "medium", "high", "critical"]
ABBR = {"info": "informational", "med": "medium", "crit": "critical"}
LOG_CLEAR = re.compile(r"log.*clear|clear.*log|cleared", re.IGNORECASE)


def level(hit: dict) -> int:
    s = (hit.get("Level") or "").lower()
    s = ABBR.get(s, s)
    return LEVELS.index(s) if s in LEVELS else 0


def case_list(labels: dict) -> list[dict]:
    def evtx(src, f):
        return (HERE / labels["sources"][src]["evtx_dir"]).resolve() / f
    cases = [{"case_id": c["case_id"], "category": c["category"], "ground_truth": c["ground_truth"],
              "dir": evtx(c["source"], c["file"]).parent, "key": c["file"].lower()} for c in labels["cases"]]
    for o in labels["out_of_scope"]:
        cases.append({"case_id": "oos_" + Path(o["file"]).stem, "category": "out_of_scope",
                      "ground_truth": "UNKNOWN" if o["technique"].startswith("(khong mo ta)") else "ALERT",
                      "dir": evtx("deepbluecli", o["file"]).parent, "key": o["file"].lower()})
    normal = HERE / "cases" / "_normal_evtx"
    for d in sorted(p for p in normal.iterdir() if p.is_dir()) if normal.exists() else []:
        cases.append({"case_id": d.name, "category": "normal_session", "ground_truth": "NORMAL",
                      "dir": normal.resolve(), "key": d.name.lower()})
    return cases


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", default=str(next((HERE.parent / "tools_rule_baseline").glob("hayabusa-*/app/hayabusa-*.exe"), "")))
    ap.add_argument("--alert-level", default="medium", choices=LEVELS)
    ap.add_argument("--threads", default="2")
    ap.add_argument("--out", default=str(HERE / "hayabusa_results.csv"))
    args = ap.parse_args()
    exe = Path(args.exe)
    min_idx = LEVELS.index(args.alert_level)
    cases = case_list(json.loads((HERE / "labels.json").read_text(encoding="utf-8")))

    hits_by_key, secs_by_dir, err_by_dir = defaultdict(list), {}, {}
    with tempfile.TemporaryDirectory() as tmp:
        for i, d in enumerate(dict.fromkeys(c["dir"] for c in cases)):
            out = Path(tmp) / f"dir{i}.csv"
            t0 = time.perf_counter()
            p = subprocess.run([str(exe), "dfir-timeline", "-d", str(d), "-o", str(out), "-p", "eval-noscript",
                                "-w", "-q", "-N", "-K", "-Q", "-C", "-m", "low", "--threads", args.threads],
                               cwd=exe.parent, capture_output=True, text=True, encoding="utf-8", errors="replace")
            secs_by_dir[d] = round(time.perf_counter() - t0, 1)
            if not out.exists():
                err_by_dir[d] = (p.stderr or p.stdout).strip()[-300:]
                continue
            for _ in range(40):  # Defender đang quét file (chứa chuỗi mã độc thật) -> chờ rồi đọc lại
                try:
                    text = out.read_text(encoding="utf-8-sig", errors="replace")
                    break
                except OSError:
                    time.sleep(3)
            else:
                err_by_dir[d] = "Khong doc duoc ket qua (co the bi antivirus chan)"
                continue
            if True:
                for h in csv.DictReader(text.splitlines()):
                    f = Path(h.get("EvtxFile", ""))
                    key = f.parent.name.lower() if f.parent.parent.name == "_normal_evtx" else f.name.lower()
                    hits_by_key[(d, key)].append(h)
            print(f"[hayabusa] {d} -> {secs_by_dir[d]}s", flush=True)

    rows = []
    for c in cases:
        hits = hits_by_key[(c["dir"], c["key"])]
        serious = [h for h in hits if level(h) >= min_idx]
        err = err_by_dir.get(c["dir"], "")
        rows.append({"case_id": c["case_id"], "category": c["category"], "ground_truth": c["ground_truth"],
                     "pred_label": "ERROR" if err else ("ALERT" if serious else "NORMAL"),
                     "log_clear_only": bool(serious) and all(LOG_CLEAR.search(h["RuleTitle"]) for h in serious),
                     "detections": len(serious), "all_detections": len(hits),
                     "max_level": LEVELS[max(map(level, hits))] if hits else "",
                     "messages": "; ".join(dict.fromkeys(f"[{h['Level']}] {h['RuleTitle']}" for h in serious))[:1500],
                     # thời gian quét cả thư mục, không tách được theo ca
                     "elapsed_seconds": secs_by_dir.get(c["dir"], ""), "error": err})
        print(f"{c['case_id']:42} {c['ground_truth']:7} -> {rows[-1]['pred_label']:6} "
              f"({len(serious)} >= {args.alert_level}, {len(hits)} tong)", flush=True)

    with open(args.out, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"Da ghi {args.out}")


if __name__ == "__main__":
    main()
