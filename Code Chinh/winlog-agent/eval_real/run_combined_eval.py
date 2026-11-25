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
import os
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
          "risk_score", "stages", "seconds", "gpu_before", "gpu_after", "error", "noise_guidance", "prompt_fingerprint"]
LABELS = {"ALERT", "NORMAL", "UNKNOWN", "REVIEW", "NOISE_ONLY", "ERROR"}
UNSCORED_CATS = ("insufficient_evidence", "unlabeled")
NORMAL_CATS = ("normal_session", "normal_full")
NEED = ("manifest.json", "security.xml", "powershell.xml", "system.xml")


def load_cases(case_set: str = "legacy", split: str = "all", only: set[str] | None = None) -> list[dict]:
    """legacy = 12 ID agent thu (ca labels.json + normal_session).
    full = ca normal_full theo split; ca tấn công <id>_full chỉ kèm khi split là test / all (dev không chạy ca tấn công)."""
    labels = json.loads((HERE / "labels.json").read_text(encoding="utf-8"))
    suffix = "_full" if case_set == "full" else ""
    cases = []
    if case_set == "legacy" or split in ("test", "all"):
        cases = [{"case_id": c["case_id"] + suffix, "category": c["category"], "ground_truth": c["ground_truth"]}
                 for c in labels["cases"] if all((CASES_DIR / (c["case_id"] + suffix) / f).exists() for f in NEED)]
    want = "normal_full" if case_set == "full" else "normal_session"
    for mf in sorted(CASES_DIR.glob("*/manifest.json")):
        m = json.loads(mf.read_text(encoding="utf-8-sig"))
        if m.get("category") == want and (case_set == "legacy" or split == "all" or m.get("split") == split):
            cases.append({"case_id": m["case_id"], "category": want, "ground_truth": "NORMAL"})
    return [c for c in cases if only is None or c["case_id"] in only]


def is_noise_only(case_dir: Path) -> bool:
    """True khi ca có sự kiện nhưng bộ lọc nhiễu bỏ hết (analyze_case lúc đó sẽ gửi lại TOÀN BỘ cho AI -> không gọi)."""
    events = A.read_events(case_dir)
    return bool(events) and all(A.is_benign_noise(e) for e in events)


def skip_as_noise(set_name: str, category: str, case_dir: Path) -> bool:
    """Chỉ lượt --set full và chỉ ca bình thường mới bỏ qua ca chỉ toàn nhiễu. Ca tấn công luôn gửi mô hình (lọc hết sự
    kiện của ca tấn công là bỏ sót, không được giấu); lượt cũ (legacy) chạy y như trước."""
    return set_name == "full" and category in NORMAL_CATS and is_noise_only(case_dir)


def split_noise_only(rows: list[dict]) -> tuple[list[dict], list[str], list[str]]:
    """-> (dòng giữ lại, ca bình thường chỉ toàn nhiễu: bỏ khỏi mọi công cụ,
    ca tấn công có NOISE_ONLY (CSV cũ): giữ lại, NOISE_ONLY != ALERT nên tính là bỏ sót)."""
    noise = {r["case_id"] for r in rows if r["pred"] == "NOISE_ONLY"}
    normal = sorted({r["case_id"] for r in rows if r["case_id"] in noise and r["category"] in NORMAL_CATS})
    return [r for r in rows if r["case_id"] not in normal], normal, sorted(noise - set(normal))


def events_after_noise(case_dirs: list[Path]) -> int:
    """Số sự kiện còn lại sau bộ lọc nhiễu = phần luật / AI thực sự thấy (bước cuối của phễu)."""
    return sum(sum(not A.is_benign_noise(e) for e in A.read_events(d)) for d in case_dirs)


def complete(row: dict) -> bool:
    """Dòng CSV ghi đủ: đủ cột (DictReader để None ở cột thiếu / thừa) và nhãn hợp lệ (bỏ dòng cắt dở kiểu 'ALE')."""
    return None not in row and None not in row.values() and row.get("pred") in LABELS


def load_done(path: Path) -> set[tuple[str, str]]:
    """(công cụ, ca) đã có kết quả; bỏ qua dòng ghi dở khi phiên bị ngắt."""
    if not path.exists():
        return set()
    with open(path, encoding="utf-8") as f:
        return {(r["tool"], r["case_id"]) for r in csv.DictReader(f) if complete(r)}


def safe_temp() -> int | str:
    try:
        return gpu_temp()
    except (OSError, ValueError, IndexError):
        return ""


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
    done = load_done(out)
    new_file = not out.exists() or not out.stat().st_size
    if not new_file and out.read_text(encoding="utf-8").partition("\n")[0].strip() != ",".join(FIELDS):
        sys.exit(f"{out} có cột khác bản hiện tại (CSV cũ) -> đổi --tag để ghi file mới")
    if not new_file and out.stat().st_size and not out.read_bytes().endswith(b"\n"):
        with open(out, "ab") as fb:  # dòng cuối ghi dở (phiên bị ngắt) -> xuống dòng để dòng mới không dính vào
            fb.write(b"\n")
    only = None
    if args.only:
        only = {x.strip() for x in Path(args.only).read_text(encoding="utf-8").splitlines() if x.strip()}
    cases = load_cases(args.set, args.split, only)
    tools = [t.strip() for t in args.tools.split(",") if t.strip()]
    print(f"{len(cases)} ca ({sum(c['category'] in NORMAL_CATS for c in cases)} bình thường); công cụ: {tools}; "
          f"NOISE_GUIDANCE={os.getenv('NOISE_GUIDANCE', '1')}")

    sampler = None
    if not args.no_gpu_guard:
        GpuGuard(args.gpu_limit).install()
    if not args.no_gpu_guard and any(t in ("qwen", "llama") for t in tools):
        log = open(HERE / f"gpu_log_{args.tag}.csv", "a", encoding="utf-8")
        sampler = subprocess.Popen(["nvidia-smi", "--query-gpu=timestamp,temperature.gpu,utilization.gpu",
                                    "--format=csv,noheader", "-l", "1"], stdout=log, stderr=subprocess.DEVNULL)
    guidance, fingerprint = os.getenv("NOISE_GUIDANCE", "1"), A.prompt_fingerprint()
    try:
        noise_only: dict[str, bool] = {}
        with open(out, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=FIELDS)
            if new_file:
                w.writeheader()
            for tool in tools:
                for c in cases:
                    if (tool, c["case_id"]) in done:
                        continue
                    row = {k: "" for k in FIELDS} | {"tool": tool, **c, "noise_guidance": guidance,
                                                     "prompt_fingerprint": fingerprint if tool in ("qwen", "llama") else ""}
                    t0 = time.perf_counter()
                    try:
                        if noise_only.setdefault(c["case_id"],
                                                 skip_as_noise(args.set, c["category"], CASES_DIR / c["case_id"])):
                            row["pred"], row["decision_source"] = "NOISE_ONLY", "noise_filter"
                        elif tool == "rules":
                            row["pred"] = rule_labels(CASES_DIR / c["case_id"])[0]
                        elif tool == "sigma":
                            r = RB.run_sigma_rule_baseline(c["case_id"], data_dir=CASES_DIR)
                            row["pred"], row["stages"] = r["pred_label"], "; ".join(r["stages"])
                        else:
                            row["gpu_before"] = safe_temp()
                            r = A.analyze_case(c["case_id"], model_key=tool, data_dir=CASES_DIR)
                            v = r["verdict"]
                            row |= {"pred": v["label"], "ai_only": ai_label_of(r),
                                    "decision_source": v.get("decision_source", ""), "risk_score": v.get("risk_score", ""),
                                    "stages": "; ".join(v.get("detected_stages", [])), "error": "; ".join(r.get("errors", []))}
                            row["gpu_after"] = safe_temp()
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


def funnel_section() -> list[str]:
    """Phễu số liệu (build_normal_cases.ps1 -IdSet Full) + thông tin khoá prompt (prompt_freeze.json)."""
    md = ["## 0. Phễu số liệu và prompt đã khoá", ""]
    summ = CASES_DIR / "_full_build_summary.json"
    if summ.exists():
        s = json.loads(summ.read_text(encoding="utf-8-sig"))
        kept = {sp: events_after_noise([CASES_DIR / c["case_id"] for c in load_cases("full", sp)
                                        if c["category"] in NORMAL_CATS]) for sp in ("dev", "test")}
        md += [f"- Nguồn: " + ", ".join(f"{k} {v:,}" for k, v in s["files"].items()) + f" (mốc chia {s['split_at']}).",
               "", "| | Phần chỉnh (dev) | Phần kiểm tra (test) |", "|---|---:|---:|",
               f"| Tổng sự kiện | {s['total']['dev']:,} | {s['total']['test']:,} |",
               f"| Sự kiện thuộc ID được đọc (trước bộ lọc nhiễu) | {s['selected']['dev']:,} | {s['selected']['test']:,} |",
               f"| Còn lại sau bộ lọc nhiễu (luật / AI thấy) | {kept['dev']:,} | {kept['test']:,} |",
               f"| Cửa sổ 10 phút (= số ca) | {s['windows']['dev']} | {s['windows']['test']} |", ""]
    freeze = HERE / "prompt_freeze.json"
    if freeze.exists():
        f = json.loads(freeze.read_text(encoding="utf-8"))
        md += [f"- Prompt khoá lúc {f.get('frozen_at', '?')}"
               + (f" (commit `{f['frozen_commit']}`, sha tính trên bản checkout Windows CRLF)" if f.get("frozen_commit") else "")
               + f": SHA-256 `analyze.py` `{f.get('analyze_sha256', '?')}`, "
               f"prompt `{f.get('prompt_fingerprint', '?')}`"
               + (f", prompt đối chứng `{f['prompt_fingerprint_baseline']}`" if f.get("prompt_fingerprint_baseline") else "")
               + f"; Ollama {f.get('ollama_colab', '?')}, GPU {f.get('gpu', '?')}.", ""]
    else:
        md += ["- (chưa có `prompt_freeze.json`)", ""]
    return md


def unscored_section(rows: list[dict], order: list[str], names: dict[str, str]) -> list[str]:
    """Ca tấn công không chấm điểm (log agent thu không đủ dấu vết / chưa gán nhãn): vẫn in kết quả từng công cụ."""
    ids = list(dict.fromkeys(r["case_id"] for r in rows))
    if not ids:
        return []
    by = {(r["tool"], r["case_id"]): r["pred"] for r in rows}
    md = ["", "## 3b. Ca không chấm điểm (insufficient_evidence / unlabeled)", "",
          "Không tính vào bảng trên: log agent thu không đủ dấu vết để gán nhãn chắc (`insufficient_evidence`) "
          "hoặc chưa gán nhãn (`unlabeled`). `–` = công cụ không có kết quả cho ca này.", "",
          "| Ca | Nhóm | Nhãn | " + " | ".join(names[t] for t in order) + " |",
          "|---|---|---|" + "|".join(":---:" for _ in order) + "|"]
    for cid in ids:
        r0 = next(r for r in rows if r["case_id"] == cid)
        md.append(f"| `{cid}` | {r0['category']} | {r0['ground_truth']} | "
                  + " | ".join(by.get((t, cid), "–") for t in order) + " |")
    return md


def report(args) -> None:
    with open(args.out, encoding="utf-8") as f:
        rows = [r for r in csv.DictReader(f) if complete(r)]  # bỏ dòng ghi dở
    if args.baseline:  # lượt đối chứng: cùng ca, prompt bỏ cột "hoạt động bình thường" (NOISE_GUIDANCE=0)
        with open(args.baseline, encoding="utf-8") as f:
            rows += [r | {"tool": r["tool"] + "_base"} for r in csv.DictReader(f)
                     if complete(r) and r["tool"] in ("qwen", "llama")]
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
    full = args.set == "full"
    if full:  # CSV DeepBlueCLI / Hayabusa dùng tên ca gốc -> bỏ hậu tố _full để ghép
        rows = [r | {"case_id": r["case_id"].removesuffix("_full")} for r in rows]
    names = {"qwen": "Qwen 2.5 3B (luật + AI)", "llama": "Llama 3.2 3B (luật + AI)", "rules": "Luật của nhóm (không AI)",
             "sigma": "Sigma mô phỏng (regex)", "deepblue": "DeepBlueCLI (công cụ thật)",
             "hayabusa": "Hayabusa + Sigma (công cụ thật, mức >= medium)",
             "qwen_base": "Qwen 2.5 3B — đối chứng (bỏ cột bình thường)",
             "llama_base": "Llama 3.2 3B — đối chứng (bỏ cột bình thường)"}
    order = [t for t in ("qwen", "llama", "qwen_base", "llama_base", "rules", "deepblue", "hayabusa", "sigma")
             if any(r["tool"] == t for r in rows)]
    # Ca bình thường chỉ toàn nhiễu không được tính cho công cụ nào; ca tấn công bị lọc hết vẫn tính (bỏ sót)
    rows, noise_only, attack_noise = split_noise_only(rows)
    # So sánh trên CÙNG một tập ca: ca mọi công cụ đều chạy được (không ERROR, không bị antivirus chặn)
    ok = [{r["case_id"] for r in rows if r["tool"] == t and r["pred"] != "ERROR"} for t in order]
    common = set.intersection(*ok)
    dropped = sorted({r["case_id"] for r in rows if r["category"] in ("scored", "coverage", *NORMAL_CATS)} - common)
    unscored = [r for r in rows if r["category"] in UNSCORED_CATS]  # giữ cả ca thiếu dòng của công cụ nào đó
    prompts = {t: sorted({r.get("prompt_fingerprint") or "" for r in rows if r["tool"] == t} - {""}) for t in order}
    rows = [r for r in rows if r["case_id"] in common]

    if full:
        md = [f"# Test toàn bộ log máy thật, có hướng dẫn nhận biết nhiễu ({datetime.now():%d/%m/%Y})", "",
              "- Thiết kế: `md/THIET_KE_TEST_TOAN_BO_LOG_25112026.md`. Hướng dẫn nhiễu chỉnh trên log **trước 22/11**, "
              "khoá, rồi mới chạy phần **kiểm tra 22–24/11** dưới đây.",
              "- **Tấn công:** ca `labels.json` dựng lại với cả Event ID mới (bản `_full`). "
              "**Bình thường:** log laptop thật của một thành viên, cửa sổ 10 phút, đã ẩn danh.",
              "- Qwen / Llama / luật nhóm thấy 12 ID agent thu + nhóm ID mới (4798/4799/4672/5382/4797/4738/4647/4616/1100/4719/"
              "4103/400/800); ID chỉ toàn nhiễu bị bỏ ở mức code. DeepBlueCLI và Hayabusa đọc **toàn bộ** evtx của cùng cửa sổ "
              "(DeepBlueCLI không đọc được log \"Windows PowerShell\" cổ điển).",
              "- Ca DeepBlueCLI / Hayabusa chỉ phát hiện \"Log Clear\" tính là NORMAL. Sigma mô phỏng = regex trong `core/rule_baselines.py`.",
              "- UNKNOWN / REVIEW: với ca tấn công tính là bỏ sót; với ca bình thường không tính là báo nhầm (ghi riêng).",
              "- Đối chứng (`NOISE_GUIDANCE=0`) chỉ bỏ cột \"hoạt động bình thường\" của nhóm ID mới. Cột dấu hiệu tấn công "
              "vẫn giữ các điều kiện đã chỉnh trên phần dev (4798/4799 chỉ là đọc; -w hidden / -ExecutionPolicy Bypass chỉ đáng "
              "ngờ khi đi cùng dấu hiệu khác; 4647 tự nó không phải tấn công) -> đây không phải lượt \"không có hướng dẫn\".",
              f"- Ca bình thường chỉ toàn nhiễu (không gọi mô hình, không tính cho công cụ nào): {len(noise_only)}."
              + (" Ca tấn công bị bộ lọc nhiễu bỏ hết sự kiện (giữ lại, tính là bỏ sót nếu được chấm): "
                 + ", ".join(f"`{c}`" for c in attack_noise) + "." if attack_noise else ""),
              f"- Mọi công cụ được chấm trên cùng tập ca. Loại {len(dropped)} ca có công cụ lỗi / bị antivirus chặn: "
              + (", ".join(f"`{c}`" for c in dropped) or "không có"), ""]
        md += funnel_section()
        if any(prompts.values()):  # CSV mới ghi prompt từng dòng
            md += ["- Prompt theo từng dòng CSV: " + "; ".join(f"{names[t]} " + ", ".join(f"`{p[:12]}…`" for p in ps)
                                                           for t, ps in prompts.items() if ps) + ".", ""]
        md += ["## 1. Tổng hợp (phần kiểm tra)", "",
               "| Công cụ | Bắt tấn công `scored` | Bắt `coverage` | Báo nhầm trên ca bình thường | REVIEW/UNKNOWN (bình thường) | Precision | F1 | TG trung vị/ca |",
               "|---|---|---|---|:---:|:---:|:---:|:---:|"]
    else:
        md = None
    md = md or [f"# So sánh công cụ trên bộ log thật gộp ({datetime.now():%d/%m/%Y})", "",
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
        nm = [r for r in tr if r["category"] in NORMAL_CATS]
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
    md += unscored_section(unscored, order, names)

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
    ap.add_argument("--set", default="legacy", choices=["legacy", "full"])
    ap.add_argument("--split", default="all", choices=["dev", "test", "all"])
    ap.add_argument("--only", default="", help="file: mỗi dòng một case_id")
    ap.add_argument("--no-gpu-guard", action="store_true", help="tắt bộ canh nhiệt (Colab)")
    ap.add_argument("--cases-dir", default="")
    ap.add_argument("--baseline", default="", help="CSV lượt đối chứng NOISE_GUIDANCE=0 (chỉ dùng với --report)")
    a = ap.parse_args()
    if a.cases_dir:
        CASES_DIR = Path(a.cases_dir).resolve()
    a.out = a.out or str(HERE / f"combined_results_{a.tag}.csv")
    a.md = a.md or str(HERE / (f"SO_SANH_TOAN_BO_LOG_{a.tag}.md" if a.set == "full" else f"SO_SANH_CONG_CU_GOP_{a.tag}.md"))
    report(a) if a.report else run(a)
