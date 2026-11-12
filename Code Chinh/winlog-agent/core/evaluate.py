"""
Hệ thống Đánh giá & So sánh Hiệu năng Mô hình SLM (Qwen vs Llama)
Tự động chạy qua các ca kiểm thử trong thư mục data/, đối chiếu với Ground Truth,
tính toán Precision, Recall, F1, độ trễ và xuất báo cáo so sánh.
"""
import argparse
import csv
import json
import os
import statistics
import sys
import time
from datetime import datetime
from pathlib import Path

# Đảm bảo mã hóa UTF-8 cho console Windows
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

from analyze import BASE, MODELS, analyze_case, OLLAMA_URL

# Danh sách ca mặc định được thiết kế để chuẩn hóa đánh giá
DEFAULT_EVAL_CASES = [
    "case_attack_01",
    "case_attack_new",
    "case_demo_02",
    "case_normal_01",
]


def check_ollama_status() -> bool:
    """Kiểm tra dịch vụ Ollama có đang hoạt động không."""
    import requests
    try:
        base_url = OLLAMA_URL.replace("/api/chat", "/api/tags")
        res = requests.get(base_url, timeout=3)
        return res.status_code == 200
    except Exception:
        return False


def get_available_cases(data_dir: Path) -> list[dict]:
    """Tìm tất cả các ca có đủ file security.xml, powershell.xml và manifest.json."""
    cases = []
    if not data_dir.is_dir():
        return cases

    for d in sorted(data_dir.iterdir()):
        if not d.is_dir():
            continue
        sec = d / "security.xml"
        ps = d / "powershell.xml"
        manifest_path = d / "manifest.json"

        if sec.is_file() and ps.is_file():
            ground_truth = "UNKNOWN"
            actions = ""
            if manifest_path.is_file():
                try:
                    meta = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
                    ground_truth = meta.get("ground_truth", "UNKNOWN").upper()
                    actions = meta.get("actions", "")
                except Exception:
                    pass

            if ground_truth == "UNKNOWN":
                if "attack" in d.name.lower() or "demo" in d.name.lower():
                    ground_truth = "ALERT"
                elif "normal" in d.name.lower():
                    ground_truth = "NORMAL"

            cases.append({
                "case_id": d.name,
                "ground_truth": ground_truth,
                "actions": actions,
                "dir": d,
            })
    return cases


def run_single_evaluation(
    case_id: str,
    model_key: str,
    filter_noise: bool = True,
    data_dir: Path | str | None = None,
) -> dict:
    """Thực thi một ca kiểm nghiệm và ghi nhận các thông số kỹ thuật."""
    started = time.perf_counter()
    try:
        res = analyze_case(
            case_id=case_id,
            model_key=model_key,
            filter_noise=filter_noise,
            data_dir=data_dir,
        )
        elapsed = round(time.perf_counter() - started, 3)
        verdict = res.get("verdict", {})
        pred_label = verdict.get("label", "UNKNOWN")
        stages = verdict.get("detected_stages", [])
        evidence_refs = verdict.get("evidence_refs", [])
        reason = verdict.get("reason", "").replace("\n", " ")
        # Nhãn riêng của AI (sau kiểm chứng + tự thẩm định), không tính lớp luật
        ai_batch = [b["verdict"]["label"] for b in res.get("batch_results", [])]
        if "ALERT" in ai_batch:
            ai_label = "ALERT"
        elif ai_batch and all(lb == "NORMAL" for lb in ai_batch):
            ai_label = "NORMAL"
        else:
            ai_label = "UNKNOWN"

        return {
            "success": res.get("analysis_status") == "OK",
            "pred_label": pred_label,
            "elapsed_seconds": res.get("elapsed_seconds", elapsed),
            "stages": stages,
            "evidence_count": len(evidence_refs),
            "reason": reason[:120] + ("..." if len(reason) > 120 else ""),
            "json_valid": True,
            "error": "",
            "decision_source": verdict.get("decision_source", ""),
            "ai_label": ai_label,
        }
    except Exception as exc:
        elapsed = round(time.perf_counter() - started, 3)
        return {
            "success": False,
            "pred_label": "ERROR",
            "elapsed_seconds": elapsed,
            "stages": [],
            "evidence_count": 0,
            "reason": f"Lỗi: {exc}",
            "json_valid": False,
            "error": str(exc),
            "decision_source": "error",
            "ai_label": "ERROR",
        }


def pace_model_calls(limit: int, abort: int = 78) -> None:
    """Bọc các hàm gọi mô hình trong analyze.py: chờ GPU <= limit °C trước mỗi lần gọi (bảo vệ laptop)."""
    import subprocess
    import analyze

    def gpu_temp() -> int:
        out = subprocess.run(["nvidia-smi", "--query-gpu=temperature.gpu", "--format=csv,noheader"],
                             capture_output=True, text=True).stdout
        return int(float(out.split()[0]))

    def wait():
        t = gpu_temp()
        if t >= abort:
            raise SystemExit(f"[!] GPU {t}°C >= {abort}°C -> dừng đánh giá để bảo vệ máy.")
        while t > limit:
            time.sleep(5)
            t = gpu_temp()

    for name in ("analyze_batch", "verify_alert"):
        fn = getattr(analyze, name)
        setattr(analyze, name, lambda *a, _fn=fn, **k: (wait(), _fn(*a, **k))[1])


def calculate_metrics(records: list[dict], label_key: str = "pred_label") -> dict:
    """Tính toán ma trận nhầm lẫn và các chỉ số Precision, Recall, F1."""
    tp = fp = tn = fn = unknown = errors = 0
    latencies = []

    for r in records:
        gt = r["ground_truth"]
        pred = r[label_key]
        latencies.append(r["elapsed_seconds"])

        if pred == "ERROR":
            errors += 1
            continue
        if pred == "UNKNOWN":
            unknown += 1
            if gt == "ALERT":
                fn += 1
            continue

        if gt == "ALERT":
            if pred == "ALERT":
                tp += 1
            else:
                fn += 1
        elif gt == "NORMAL":
            if pred == "ALERT":
                fp += 1
            else:
                tn += 1

    total = len(records)
    n_normal = sum(1 for r in records if r["ground_truth"] == "NORMAL")
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    accuracy = ((tp + tn) / total) if total > 0 else 0.0

    valid_json_count = sum(1 for r in records if r["json_valid"])
    valid_json_rate = (valid_json_count / total * 100.0) if total > 0 else 0.0

    median_lat = statistics.median(latencies) if latencies else 0.0
    avg_lat = statistics.mean(latencies) if latencies else 0.0

    return {
        "total_cases": total,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "unknown": unknown,
        "errors": errors,
        "n_normal": n_normal,
        "fpr": round(fp / n_normal * 100, 1) if n_normal else 0.0,
        "precision": round(precision * 100, 1),
        "recall": round(recall * 100, 1),
        "f1": round(f1, 3),
        "accuracy": round(accuracy * 100, 1),
        "valid_json_rate": round(valid_json_rate, 1),
        "median_latency": round(median_lat, 2),
        "avg_latency": round(avg_lat, 2),
        "alert_by_source": {
            src: sum(1 for r in records if r[label_key] == "ALERT" and r.get("decision_source") == src)
            for src in ("rule+ai", "ai", "rule")
        },
    }


def main():
    parser = argparse.ArgumentParser(description="Đánh giá so sánh hiệu năng các Local SLM trên Windows Event Log.")
    parser.add_argument("--models", default="qwen,llama", help="Danh sách model cần so sánh (cách nhau bằng dấu phẩy)")
    parser.add_argument("--cases", default="", help="Danh sách case_id cụ thể (để trống để tự động quét toàn bộ)")
    parser.add_argument("--quick", action="store_true", help="Chỉ chạy nhanh 4 ca kiểm thử mẫu mặc định")
    parser.add_argument("--no-filter", action="store_true", help="Không lọc tiến trình nhiễu")
    parser.add_argument("--data-dir", default="", help="Thư mục chứa dữ liệu ca kiểm thử (mặc định: data01 nếu có, không thì data)")
    parser.add_argument("--output-dir", default="", help="Thư mục xuất báo cáo (mặc định: results/)")
    parser.add_argument("--max-gpu-temp", type=int, default=0,
                        help="Chờ GPU nguội tới ngưỡng này (°C) trước MỖI lần gọi mô hình; dừng hẳn nếu >= 78°C. 0 = tắt")
    args = parser.parse_args()
    if args.max_gpu_temp:
        pace_model_calls(args.max_gpu_temp)

    models_to_run = [m.strip() for m in args.models.split(",") if m.strip()]
    invalid_models = [m for m in models_to_run if m not in MODELS]
    if invalid_models:
        print(f"[!] Lỗi: Model không hợp lệ: {invalid_models}. Chọn từ: {list(MODELS.keys())}")
        return

    if args.data_dir:
        dpath = Path(args.data_dir)
        data_dir = dpath if dpath.is_absolute() else (BASE / dpath)
    else:
        data_dir = (BASE / "data01") if (BASE / "data01").is_dir() else (BASE / "data")

    all_cases = get_available_cases(data_dir)

    if args.cases:
        filter_names = set(c.strip() for c in args.cases.split(",") if c.strip())
        cases_to_run = [c for c in all_cases if c["case_id"] in filter_names]
    elif args.quick:
        cases_to_run = [c for c in all_cases if c["case_id"] in DEFAULT_EVAL_CASES]
    else:
        # Chạy toàn bộ các ca kiểm thử benchmark (loại trừ các thư mục đệm live capture)
        cases_to_run = [c for c in all_cases if not c["case_id"].endswith("_live")]

    if not cases_to_run:
        print("[!] Không tìm thấy ca kiểm nghiệm nào hợp lệ trong data/.")
        return

    out_dir = Path(args.output_dir) if args.output_dir else (BASE / "results")
    out_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print("      HỆ THỐNG ĐÁNH GIÁ & SO SÁNH NĂNG LỰC MÔ HÌNH SLM LOCAL (OLLAMA)")
    print("=" * 80)
    print(f" - Số lượng ca kiểm thử : {len(cases_to_run)}")
    print(f" - Danh sách mô hình    : {', '.join(models_to_run)}")
    print(f" - Lọc nhiễu hệ thống   : {'Tắt' if args.no_filter else 'Bật'}")
    print(f" - Thư mục xuất kết quả : {out_dir}")
    print("=" * 80)

    # Kiểm tra Ollama
    if not check_ollama_status():
        print(f"\n[!] CẢNH BÁO: Không kết nối được tới Ollama tại {OLLAMA_URL}.")
        print("    Vui lòng đảm bảo ứng dụng Ollama đang chạy ngầm trên máy.\n")

    detailed_records = []
    summary_by_model = {}

    for model_key in models_to_run:
        full_model_name = MODELS[model_key]
        print(f"\n[>>>] ĐANG THỰC HIỆN ĐÁNH GIÁ MÔ HÌNH: {model_key.upper()} ({full_model_name})")
        print("-" * 80)
        print(f"{'Case ID':<20} | {'GroundTruth':<11} | {'Dự đoán':<9} | {'TG(s)':<6} | {'Stages / Ghi chú'}")
        print("-" * 80)

        model_records = []
        for c in cases_to_run:
            cid = c["case_id"]
            gt = c["ground_truth"]

            res = run_single_evaluation(
                case_id=cid,
                model_key=model_key,
                filter_noise=not args.no_filter,
                data_dir=data_dir,
            )

            pred = res["pred_label"]
            match_icon = "✓" if (pred == gt and pred in ("ALERT", "NORMAL")) else "✗"
            stages_summary = ", ".join(res["stages"]) if res["stages"] else res["reason"]

            print(f"{cid:<20} | {gt:<11} | {pred:<7} {match_icon} | {res['elapsed_seconds']:<6.2f} | {stages_summary[:35]}")

            record = {
                "model_key": model_key,
                "model_name": full_model_name,
                "case_id": cid,
                "ground_truth": gt,
                "pred_label": pred,
                "is_correct": (pred == gt),
                "elapsed_seconds": res["elapsed_seconds"],
                "json_valid": res["json_valid"],
                "evidence_count": res["evidence_count"],
                "stages": "; ".join(res["stages"]),
                "reason": res["reason"],
                "error": res["error"],
                "decision_source": res["decision_source"],
                "ai_label": res["ai_label"],
            }
            model_records.append(record)
            detailed_records.append(record)

        summary_by_model[model_key] = calculate_metrics(model_records)
        summary_by_model[model_key]["ai_only"] = calculate_metrics(model_records, label_key="ai_label")

    # --------------------------------------------------------------------------
    # XUẤT BẢNG SO SÁNH TỔNG HỢP RA CONSOLE
    # --------------------------------------------------------------------------
    print("\n" + "=" * 80)
    print("                     BẢNG TỔNG HỢP SO SÁNH HIỆU NĂNG")
    print("=" * 80)
    header_fmt = "{:<35} | " + " | ".join(["{:<18}" for _ in models_to_run])
    print(header_fmt.format("Chỉ số đánh giá (Metric)", *[m.upper() for m in models_to_run]))
    print("-" * 80)

    rows = [
        ("Tên đầy đủ mô hình", lambda m: MODELS[m]),
        ("Tổng số ca kiểm thử", lambda m: str(summary_by_model[m]["total_cases"])),
        ("Độ chuẩn xác (Precision)", lambda m: f"{summary_by_model[m]['precision']}%"),
        ("Độ nhạy phát hiện (Recall)", lambda m: f"{summary_by_model[m]['recall']}%"),
        ("Điểm F1-Score", lambda m: f"{summary_by_model[m]['f1']}"),
        ("Độ chính xác tổng thể (Accuracy)", lambda m: f"{summary_by_model[m]['accuracy']}%"),
        ("Báo động giả (False Positive - FP)", lambda m: f"{summary_by_model[m]['fp']} ca"),
        ("Bỏ sót tấn công (False Negative - FN)", lambda m: f"{summary_by_model[m]['fn']} ca"),
        ("Tỉ lệ báo động giả (FP / số ca NORMAL)", lambda m: f"{summary_by_model[m]['fpr']}% ({summary_by_model[m]['fp']}/{summary_by_model[m]['n_normal']})"),
        ("Không kết luận được (UNKNOWN / lỗi)", lambda m: f"{summary_by_model[m]['unknown']} / {summary_by_model[m]['errors']} ca"),
        ("Tỷ lệ xuất JSON hợp lệ (Valid JSON)", lambda m: f"{summary_by_model[m]['valid_json_rate']}%"),
        ("Thời gian trung vị (Median Latency)", lambda m: f"{summary_by_model[m]['median_latency']}s"),
        ("Thời gian trung bình (Mean Latency)", lambda m: f"{summary_by_model[m]['avg_latency']}s"),
        ("Cảnh báo do Luật + AI xác nhận", lambda m: f"{summary_by_model[m]['alert_by_source']['rule+ai']} ca"),
        ("Cảnh báo do AI tự phát hiện", lambda m: f"{summary_by_model[m]['alert_by_source']['ai']} ca"),
        ("Cảnh báo chỉ do Luật (AI không xác nhận)", lambda m: f"{summary_by_model[m]['alert_by_source']['rule']} ca"),
        ("[Riêng AI] Precision", lambda m: f"{summary_by_model[m]['ai_only']['precision']}%"),
        ("[Riêng AI] Recall", lambda m: f"{summary_by_model[m]['ai_only']['recall']}%"),
        ("[Riêng AI] F1-Score", lambda m: f"{summary_by_model[m]['ai_only']['f1']}"),
        ("[Riêng AI] Accuracy", lambda m: f"{summary_by_model[m]['ai_only']['accuracy']}%"),
        ("[Riêng AI] Báo động giả / Bỏ sót", lambda m: f"{summary_by_model[m]['ai_only']['fp']} / {summary_by_model[m]['ai_only']['fn']} ca"),
    ]

    for label, fn in rows:
        vals = [fn(m) for m in models_to_run]
        print(header_fmt.format(label, *vals))
    print("=" * 80)

    # --------------------------------------------------------------------------
    # GHI RA FILE CSV VÀ BÁO CÁO MARKDOWN
    # --------------------------------------------------------------------------
    # 1. comparison_details.csv
    details_csv_path = out_dir / "comparison_details.csv"
    with open(details_csv_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "model_key", "model_name", "case_id", "ground_truth", "pred_label",
            "is_correct", "elapsed_seconds", "json_valid", "evidence_count",
            "stages", "reason", "error", "decision_source", "ai_label"
        ])
        writer.writeheader()
        writer.writerows(detailed_records)

    # 2. comparison_summary.csv
    summary_csv_path = out_dir / "comparison_summary.csv"
    with open(summary_csv_path, mode="w", newline="", encoding="utf-8") as f:
        summary_fields = ["metric"] + models_to_run
        writer = csv.writer(f)
        writer.writerow(summary_fields)
        for label, fn in rows:
            writer.writerow([label] + [fn(m) for m in models_to_run])

    # 3. COMPARISON_REPORT.md
    report_md_path = out_dir / "COMPARISON_REPORT.md"
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    md_lines = [
        "# 📊 BÁO CÁO KẾT QUẢ SO SÁNH HIỆU NĂNG MÔ HÌNH SLM",
        f"**Thời gian thực nghiệm:** `{now_str}`  \n"
        f"**Môi trường suy luận:** Ollama Local API (`{OLLAMA_URL}`)  \n",
        "## 1. Bảng chỉ số đối chiếu tổng hợp",
        "",
        "| Chỉ số đánh giá | " + " | ".join([f"**{m.upper()}** (`{MODELS[m]}`)" for m in models_to_run]) + " |",
        "|---| " + " | ".join([":---:" for _ in models_to_run]) + " |",
    ]
    for label, fn in rows:
        if label == "Tên đầy đủ mô hình":
            continue
        vals = [fn(m) for m in models_to_run]
        md_lines.append(f"| **{label}** | " + " | ".join(vals) + " |")

    md_lines.extend([
        "",
        "## 2. Chi tiết kết quả từng ca thử nghiệm",
        "",
        "| Model | Case ID | Ground Truth | Hệ thống | Riêng AI | Nguồn quyết định | Kết quả | Thời gian (s) | Giai đoạn tấn công phát hiện |",
        "|---|---|:---:|:---:|:---:|:---:|:---:|:---:|---|",
    ])

    for r in detailed_records:
        status_icon = "✅ Đúng" if r["is_correct"] else "❌ Sai"
        stages_disp = r["stages"] if r["stages"] else r["reason"][:50]
        md_lines.append(
            f"| `{r['model_key']}` | `{r['case_id']}` | **{r['ground_truth']}** | `{r['pred_label']}` | `{r['ai_label']}` | {r['decision_source']} | {status_icon} | {r['elapsed_seconds']}s | {stages_disp} |"
        )

    md_lines.extend([
        "",
        "## 3. Nhận định và Kết luận",
        "- **Cơ chế quyết định**: Luật MẠNH (brute force >= 3 lần sai, tải/thực thi mã độc, thêm vào nhóm Administrators) luôn cảnh báo làm lưới an toàn; các trường hợp còn lại do AI quyết định sau khi kiểm chứng bằng chứng với dữ liệu "
        "và qua vòng tự thẩm định (self-verification).",
        "- **Hệ thống** = nhãn cuối cùng. **Riêng AI** = nhãn của mô hình (sau kiểm chứng), không tính lớp luật — thể hiện năng lực tự phân tích của AI.",
        "- **Độ chuẩn xác và Nhạy (Precision / Recall)**: So sánh khả năng phân biệt giữa hành vi quản trị thông thường và tấn công mạng.",
        "- **Khả năng bám sát cấu trúc (JSON Compliance)**: Đảm bảo khả năng tích hợp tự động vào hệ thống SOC/EDR.",
        "- **Khuyến nghị lựa chọn**: Mô hình có điểm F1 cao nhất và tỷ lệ False Negative = 0 nên được ưu tiên triển khai chính thức.",
    ])

    report_md_path.write_text("\n".join(md_lines), encoding="utf-8")

    print(f"\n[✓] ĐÃ LƯU BÁO CÁO THÀNH CÔNG:")
    print(f"    1. Tệp chi tiết CSV : {details_csv_path}")
    print(f"    2. Tệp tóm tắt CSV  : {summary_csv_path}")
    print(f"    3. Báo cáo Markdown : {report_md_path}")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()

