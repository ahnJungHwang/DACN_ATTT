"""
Bộ đánh giá GỘP trên log thật: ca tấn công (labels.json) + ca bình thường từ máy thật (build_normal_cases.ps1).

Công cụ: Qwen, Llama (hệ thống luật + AI), luật của nhóm (không AI), Sigma (mô phỏng regex, core/rule_baselines.py).
DeepBlueCLI thật chạy riêng bằng run_deepblue.ps1 -> CSV, gộp vào báo cáo ở bước --report.

- Mỗi ca chạy 1 lần (temperature=0; lần chạy 20/11 cho 14/14 ca cùng kết quả qua 3 lần lặp).
- Bảo vệ GPU: trước MỖI lần gọi mô hình chờ GPU <= ngưỡng (mặc định 58°C; một lần gọi ~10s làm GPU tăng thêm
  ~8-10°C nên đỉnh khoảng 65-70°C); nếu sau một lần gọi GPU >= 68°C thì hạ ngưỡng 2°C (thấp nhất 50°C);
  GPU >= 75°C -> dừng. Nhiệt độ ghi mỗi giây vào gpu_log_<tag>.csv.
- Chạy tiếp được khi bị dừng: bỏ qua (công cụ, ca) đã có trong CSV.

Cách chạy:
  .venv\\Scripts\\python.exe eval_real\\run_combined_eval.py --tools rules,sigma,qwen,llama
  .venv\\Scripts\\python.exe eval_real\\run_combined_eval.py --report --deepblue eval_real\\deepblue_results_24112026.csv
"""
import argparse
import csv
import json
import statistics
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "core"))
sys.path.insert(0, str(HERE))
import analyze as A  # noqa: E402
import rule_baselines as RB  # noqa: E402
from run_eval import ai_label_of, rule_labels, wilson  # noqa: E402

CASES_DIR = HERE / "cases"
FIELDS = ["tool", "case_id", "category", "ground_truth", "pred", "ai_only", "decision_source",
          "risk_score", "stages", "seconds", "gpu_before", "gpu_after", "error"]


def load_cases() -> list[dict]:
    labels = json.loads((HERE / "labels.json").read_text(encoding="utf-8"))
    need = ("manifest.json", "security.xml", "powershell.xml", "system.xml")
    cases = [{"case_id": c["case_id"], "category": c["category"], "ground_truth": c["ground_truth"]}
             for c in labels["cases"] if all((CASES_DIR / c["case_id"] / f).exists() for f in need)]
    for mf in sorted(CASES_DIR.glob("*/manifest.json")):
        m = json.loads(mf.read_text(encoding="utf-8-sig"))
        if m.get("category") == "normal_session":
            cases.append({"case_id": m["case_id"], "category": "normal_session", "ground_truth": "NORMAL"})
    return cases


def gpu_temp() -> int:
    out = subprocess.run(["nvidia-smi", "--query-gpu=temperature.gpu", "--format=csv,noheader"],
                         capture_output=True, text=True).stdout
    return int(float(out.split()[0]))


class GpuGuard:
    def __init__(self, limit: int, floor: int = 50, hot: int = 68, abort: int = 75):
        self.limit, self.floor, self.hot, self.abort = limit, floor, hot, abort
        self.calls = 0

    def wait(self):
        t = gpu_temp()
        if t >= self.abort:
            raise SystemExit(f"[!] GPU {t}°C >= {self.abort}°C -> dừng để bảo vệ máy.")
        while t > self.limit:
            time.sleep(3)
            t = gpu_temp()

    def after(self):
        self.calls += 1
        t = gpu_temp()
        if t >= self.hot and self.limit > self.floor:
            self.limit -= 2
            print(f"    [gpu] {t}°C sau lần gọi -> hạ ngưỡng chờ còn {self.limit}°C", flush=True)

    def install(self):
        for name in ("analyze_batch", "verify_alert"):
            fn = getattr(A, name)

            def wrapped(*a, _fn=fn, **k):
                self.wait()
                try:
                    return _fn(*a, **k)
                finally:
                    self.after()
            setattr(A, name, wrapped)


def run(args) -> None:
    out = Path(args.out)
    done = set()
    if out.exists():
        with open(out, encoding="utf-8") as f:
            done = {(r["tool"], r["case_id"]) for r in csv.DictReader(f)}
    new_file = not out.exists()
    cases = load_cases()
    tools = [t.strip() for t in args.tools.split(",") if t.strip()]
    print(f"{len(cases)} ca ({sum(c['category'] == 'normal_session' for c in cases)} bình thường); công cụ: {tools}")

    guard = GpuGuard(args.gpu_limit)
    guard.install()
    sampler = None
    if any(t in ("qwen", "llama") for t in tools):
        log = open(HERE / f"gpu_log_{args.tag}.csv", "a", encoding="utf-8")
        sampler = subprocess.Popen(["nvidia-smi", "--query-gpu=timestamp,temperature.gpu,utilization.gpu",
                                    "--format=csv,noheader", "-l", "1"], stdout=log, stderr=subprocess.DEVNULL)
    try:
        with open(out, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=FIELDS)
            if new_file:
                w.writeheader()
            for tool in tools:
                for c in cases:
                    if (tool, c["case_id"]) in done:
                        continue
                    row = {k: "" for k in FIELDS} | {"tool": tool, **c}
                    t0 = time.perf_counter()
                    try:
                        if tool == "rules":
                            row["pred"] = rule_labels(CASES_DIR / c["case_id"])[0]
                        elif tool == "sigma":
                            r = RB.run_sigma_rule_baseline(c["case_id"], data_dir=CASES_DIR)
                            row["pred"], row["stages"] = r["pred_label"], "; ".join(r["stages"])
                        else:
                            row["gpu_before"] = gpu_temp()
                            r = A.analyze_case(c["case_id"], model_key=tool, data_dir=CASES_DIR)
                            v = r["verdict"]
                            row |= {"pred": v["label"], "ai_only": ai_label_of(r),
                                    "decision_source": v.get("decision_source", ""), "risk_score": v.get("risk_score", ""),
                                    "stages": "; ".join(v.get("detected_stages", [])), "error": "; ".join(r.get("errors", []))}
                            row["gpu_after"] = gpu_temp()
                    except SystemExit:
                        raise
                    except Exception as exc:  # noqa: BLE001
                        row["pred"], row["error"] = "ERROR", str(exc)[:300]
                    row["seconds"] = round(time.perf_counter() - t0, 2)
                    w.writerow(row)
                    f.flush()
                    print(f"[{tool}] {c['case_id']:34} GT={c['ground_truth']:7} -> {row['pred']:7} "
                          f"{row['seconds']}s gpu {row['gpu_before']}->{row['gpu_after']}", flush=True)
    finally:
        if sampler:
            sampler.terminate()


def report(args) -> None:
    with open(args.out, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for tool, path in (("deepblue", args.deepblue), ("hayabusa", args.hayabusa)):
        if not path:
            continue
        with open(path, encoding="utf-8-sig") as f:
            for r in csv.DictReader(f):
                # Chấm công bằng: phát hiện duy nhất là xoá log = dấu vết người tạo mẫu, không tính
                pred = "NORMAL" if r["log_clear_only"] == "True" else r["pred_label"]
                rows.append({"tool": tool, "case_id": r["case_id"], "category": r["category"],
                             "ground_truth": r["ground_truth"], "pred": pred, "stages": r["messages"],
                             "seconds": r["elapsed_seconds"]})
    names = {"qwen": "Qwen 2.5 3B (luật + AI)", "llama": "Llama 3.2 3B (luật + AI)", "rules": "Luật của nhóm (không AI)",
             "sigma": "Sigma mô phỏng (regex)", "deepblue": "DeepBlueCLI (công cụ thật)",
             "hayabusa": "Hayabusa + Sigma (công cụ thật, mức >= medium)"}
    order = [t for t in ("qwen", "llama", "rules", "deepblue", "hayabusa", "sigma") if any(r["tool"] == t for r in rows)]
    # So sánh trên CÙNG một tập ca: ca mọi công cụ đều chạy được (không ERROR, không bị antivirus chặn)
    ok = [{r["case_id"] for r in rows if r["tool"] == t and r["pred"] != "ERROR"} for t in order]
    common = set.intersection(*ok)
    dropped = sorted({r["case_id"] for r in rows if r["category"] in ("scored", "coverage", "normal_session")} - common)
    rows = [r for r in rows if r["case_id"] in common]

    md = [f"# So sánh công cụ trên bộ log thật gộp ({datetime.now():%d/%m/%Y})", "",
          "- **Tấn công:** ca có nhãn trong `labels.json` (DeepBlueCLI + EVTX-to-MITRE). `scored` = có dấu vết trong log agent thu; "
          "`coverage` = dịch vụ / tài khoản mới (7045, 4720, 4728, 4732).",
          "- **Bình thường:** log laptop thật của một thành viên (Security + PowerShell/Operational, 21–24/11/2026), "
          "cắt cửa sổ 10 phút (`build_normal_cases.ps1`), ẩn danh tên máy / email / thư mục hồ sơ.",
          "- Ca DeepBlueCLI chỉ phát hiện \"Log Clear\" được tính là NORMAL (dấu vết người tạo mẫu). "
          "Sigma ở đây là bản **mô phỏng bằng regex** (`core/rule_baselines.py`), không phải engine Sigma thật.",
          "- UNKNOWN / REVIEW: với ca tấn công tính là bỏ sót; với ca bình thường không tính là báo nhầm (ghi riêng).",
          "- DeepBlueCLI và Hayabusa đọc **toàn bộ** file evtx (cả sự kiện agent không thu); Qwen / Llama / luật nhóm chỉ thấy "
          "sự kiện agent thu (4624/4625/4648/4688/1102/4720/4728/4732/4698/4104/7045/104).",
          f"- Mọi công cụ được chấm trên cùng tập ca. Loại {len(dropped)} ca có công cụ lỗi / bị antivirus chặn: "
          + (", ".join(f"`{c}`" for c in dropped) or "không có"), "",
          "## 1. Tổng hợp", "",
          "| Công cụ | Bắt tấn công `scored` | Bắt `coverage` | Báo nhầm trên ca bình thường | REVIEW/UNKNOWN (bình thường) | Precision | F1 | TG trung vị/ca |",
          "|---|---|---|---|:---:|:---:|:---:|:---:|"]
    fps = {}
    for t in order:
        tr = [r for r in rows if r["tool"] == t]
        sc = [r for r in tr if r["category"] == "scored" and r["ground_truth"] == "ALERT"]
        cv = [r for r in tr if r["category"] == "coverage" and r["ground_truth"] == "ALERT"]
        nm = [r for r in tr if r["category"] == "normal_session"]
        att = sc + cv
        tp = sum(r["pred"] == "ALERT" for r in att)
        fp = [r for r in nm if r["pred"] == "ALERT"]
        fps[t] = fp
        prec = tp / (tp + len(fp)) if tp + len(fp) else 0
        rec = tp / len(att) if att else 0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0
        unsure = sum(r["pred"] in ("REVIEW", "UNKNOWN") for r in nm)
        secs = [float(r["seconds"]) for r in tr if r.get("seconds")]
        md.append(f"| {names[t]} | {wilson(sum(r['pred'] == 'ALERT' for r in sc), len(sc))} | "
                  f"{sum(r['pred'] == 'ALERT' for r in cv)}/{len(cv)} | {wilson(len(fp), len(nm))} | {unsure} | "
                  f"{prec:.1%} | {f1:.3f} | {statistics.median(secs) if secs else 0:.2f}s |")

    md += ["", "## 2. Ca bình thường bị báo nhầm", ""]
    for t in order:
        md.append(f"**{names[t]}:** " + (", ".join(f"`{r['case_id']}`" for r in fps[t]) or "không có"))
        for r in fps[t][:15]:
            md.append(f"  - `{r['case_id']}`: {(r.get('stages') or '')[:200]}")
        md.append("")

    md += ["## 3. Từng ca tấn công", "", "| Ca | Nhóm | " + " | ".join(names[t] for t in order) + " |",
           "|---|---|" + "|".join(":---:" for _ in order) + "|"]
    by = {(r["tool"], r["case_id"]): r["pred"] for r in rows}
    att_ids = list(dict.fromkeys(r["case_id"] for r in rows if r["category"] in ("scored", "coverage")))
    for cid in att_ids:
        cat = next(r["category"] for r in rows if r["case_id"] == cid)
        md.append(f"| `{cid}` | {cat} | " + " | ".join(by.get((t, cid), "–") for t in order) + " |")

    gpu = HERE / f"gpu_log_{args.tag}.csv"
    if gpu.exists():
        temps = [float(x.split(",")[1]) for x in gpu.read_text(encoding="utf-8").splitlines() if x.count(",") >= 2 and x.split(",")[1].strip().replace(".", "", 1).isdigit()]
        if temps:
            md += ["", "## 4. Nhiệt độ GPU khi chạy mô hình", "",
                   f"- Mẫu mỗi giây: {len(temps)} · cao nhất **{max(temps)}°C** · trung bình {statistics.mean(temps):.1f}°C · "
                   f"số giây >= 60°C: {sum(t >= 60 for t in temps)}"]
    Path(args.md).write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"Đã ghi {args.md}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--tools", default="rules,sigma,qwen,llama")
    ap.add_argument("--tag", default=datetime.now().strftime("%d%m%Y"))
    ap.add_argument("--out", default="")
    ap.add_argument("--md", default="")
    ap.add_argument("--gpu-limit", type=int, default=58)
    ap.add_argument("--report", action="store_true")
    ap.add_argument("--deepblue", default="")
    ap.add_argument("--hayabusa", default="")
    a = ap.parse_args()
    a.out = a.out or str(HERE / f"combined_results_{a.tag}.csv")
    a.md = a.md or str(HERE / f"SO_SANH_CONG_CU_GOP_{a.tag}.md")
    report(a) if a.report else run(a)
