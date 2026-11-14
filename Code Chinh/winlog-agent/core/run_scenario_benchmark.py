"""
Đánh giá phân tầng theo kịch bản trên bộ benchmark 600 ca (data_benchmark/, gộp từ bản update 13/11/2026).
Mỗi bài 200 ca (50 Attack + 150 Normal), tổng 600 ca (150 Attack / 25% + 450 Normal / 75%):
  Bài 1: Từng sự kiện đơn lẻ & chữ ký tĩnh (Atomic Signatures)
  Bài 2: Chuỗi sự kiện đa bước & tương quan hành vi (Multi-stage Attack Chains)
  Bài 3: Chống nhận diện nhầm do người dùng vô ý (Hard Negatives & Mistakes)

Kết quả ghi vào results/benchmark600/ (KHÔNG ghi đè results/comparison_*.csv của evaluate.py).
Ca đã chạy được lấy lại từ results/benchmark600/comparison_details.csv (cache); --force-rerun để chạy lại.
LƯU Ý: dữ liệu benchmark là log TỔNG HỢP do core/build_600_cases.py sinh ra, không phải log thật.
"""
import argparse
import csv
import json
import sys
from pathlib import Path

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

from evaluate import (  # noqa: E402
    ALIASES,
    ALL_EVAL_TARGETS,
    BASE,
    calculate_metrics,
    classify_result,
    pace_model_calls,
    resolve_case_dir,
    run_single_evaluation,
)

SCENARIOS_EXPANDED = {
    "1": {
        "folder": "bai_1_chu_ky_tinh",
        "title": "BÀI 1: TỪNG SỰ KIỆN ĐƠN LẺ & CHỮ KÝ TĨNH (Atomic & Signatures)",
        "desc": "Bắt các sự kiện độc lập có chữ ký/công cụ độc hại rõ ràng (Mimikatz, Procdump, Base64 PS, vssadmin, "
                "certutil decode, bitsadmin, sam dump, cipher) đối chiếu 150 tác vụ văn phòng và tiện ích tiêu chuẩn.",
    },
    "2": {
        "folder": "bai_2_chuoi_da_buoc",
        "title": "BÀI 2: THEO CHUỖI SỰ KIỆN LIÊN HOÀN (Multi-stage Attack Chains)",
        "desc": "Xâu chuỗi nhiều sự kiện đa bước (brute force liên hoàn, Discovery T1033, backdoor account, BloodHound, "
                "PsExec, WMIC remote, DCSync, admin share, tar staging, DNS exfil) đối chiếu 150 quy trình nghiệp vụ hợp lệ.",
    },
    "3": {
        "folder": "bai_3_nguoi_dung_vo_y",
        "title": "BÀI 3: CHỐNG NHẬN DIỆN NHẦM DO NGƯỜI DÙNG VÔ Ý (Hard Negatives & Mistakes)",
        "desc": "Tránh báo động giả khi nhân viên gõ nhầm mật khẩu, IT tạo user, tải file nội bộ LAN, lỗi đường dẫn task, "
                "certutil tính SHA256; đối chiếu 50 tấn công ẩn danh (LOLBAS, AMSI patch, net stop EventLog, ransomware rename, CMSTP).",
    },
}

DETAIL_FIELDS = ["scenario", "model_key", "case_id", "ground_truth", "pred_label", "classification",
                 "elapsed_seconds", "json_valid", "decision_source", "ai_label", "risk_score", "stages", "reason"]


def get_scenario_cases(scenario_key: str, data_dir: Path) -> list[str]:
    folder_path = data_dir / SCENARIOS_EXPANDED[scenario_key]["folder"]
    if not folder_path.is_dir():
        return []
    return sorted(d.name for d in folder_path.iterdir() if d.is_dir() and (d / "manifest.json").is_file())


def load_cached_results(out_dir: Path) -> dict:
    cache = {}
    details_file = out_dir / "comparison_details.csv"
    if details_file.is_file():
        try:
            with open(details_file, "r", encoding="utf-8") as f:
                for r in csv.DictReader(f):
                    cache[(r["model_key"], r["case_id"])] = r
        except (OSError, KeyError, csv.Error):
            pass
    return cache


def read_ground_truth(case_id: str, data_dir: Path) -> str:
    gt = "ALERT" if "att" in case_id else "NORMAL"
    manifest_file = resolve_case_dir(case_id, data_dir) / "manifest.json"
    if manifest_file.is_file():
        try:
            gt = json.loads(manifest_file.read_text(encoding="utf-8-sig")).get("ground_truth", gt).upper()
        except (OSError, ValueError):
            pass
    return gt


def metrics_rows(summary: dict) -> list[tuple]:
    def warn(n):
        return f"{n} ca ⚠️" if n > 0 else "0 ca"
    return [
        ("Tổng số ca kiểm thử", lambda m: f"{summary[m]['total_cases']} ca"),
        ("Số ca tấn công thực tế", lambda m: f"{summary[m]['actual_positives']} ca"),
        ("Số ca bình thường thực tế", lambda m: f"{summary[m]['actual_negatives']} ca"),
        ("Bắt trúng tấn công (TP)", lambda m: f"{summary[m]['tp']} ca"),
        ("Đúng bình thường (TN)", lambda m: f"{summary[m]['tn']} ca"),
        ("Báo động giả (FP)", lambda m: warn(summary[m]["fp"])),
        ("Bỏ sót tấn công (FN)", lambda m: warn(summary[m]["fn"])),
        ("Chuyển chuyên gia (REVIEW) / UNKNOWN", lambda m: f"{summary[m]['review']} / {summary[m]['unknown']} ca"),
        ("Độ chuẩn xác (Precision)", lambda m: f"{summary[m]['precision']}%"),
        ("Độ nhạy (Recall)", lambda m: f"{summary[m]['recall']}%"),
        ("Điểm F1-Score", lambda m: f"{summary[m]['f1']}"),
        ("Độ chính xác (Accuracy)", lambda m: f"{summary[m]['accuracy']}%"),
        ("Tỉ lệ báo động giả (FPR)", lambda m: f"{summary[m]['fpr']}%"),
        ("Thời gian phân tích TB", lambda m: f"{summary[m]['avg_latency']}s"),
        ("Độ trễ toàn trình (ƯỚC LƯỢNG)", lambda m: f"{summary[m]['e2e_latency']}s"),
    ]


def print_table(title: str, summary: dict, models: list[str]) -> None:
    print("\n" + "=" * 115, flush=True)
    print(f"      {title}", flush=True)
    print("=" * 115, flush=True)
    fmt = "{:<40} | " + " | ".join(["{:<16}"] * len(models))
    print(fmt.format("Chỉ số đánh giá", *[m.upper() for m in models]), flush=True)
    print("-" * 115, flush=True)
    for label, fn in metrics_rows(summary):
        print(fmt.format(label, *[fn(m) for m in models]), flush=True)
    print("=" * 115, flush=True)


def make_checkpoint(out_dir: Path):
    """Trả về hàm lưu NGAY từng ca vừa chạy xong vào comparison_details.csv (ghi tạm rồi thay file).

    Nhờ vậy nếu script bị dừng giữa chừng (vd GPU quá nóng -> dừng bảo vệ máy), các ca đã chạy vẫn còn
    và lần chạy sau tiếp tục từ chỗ dừng thay vì chạy lại từ đầu."""
    state = load_cached_results(out_dir)

    def save(record: dict) -> None:
        state[(record["model_key"], record["case_id"])] = record
        tmp = out_dir / "comparison_details.csv.tmp"
        write_csv(tmp, list(state.values()), DETAIL_FIELDS)
        tmp.replace(out_dir / "comparison_details.csv")

    return save


def run_scenario(scenario_key: str, models_to_run: list[str], data_dir: Path, cached_map: dict, on_record=None):
    sc_info = SCENARIOS_EXPANDED[scenario_key]
    case_ids = get_scenario_cases(scenario_key, data_dir)

    print("\n" + "=" * 115, flush=True)
    print(f"      {sc_info['title']}", flush=True)
    print("=" * 115, flush=True)
    print(f" • Mục tiêu : {sc_info['desc']}", flush=True)
    print(f" • Số ca thử nghiệm: {len(case_ids)} ca", flush=True)
    print(f" • Danh sách đối tượng: {', '.join(models_to_run)}", flush=True)
    print("=" * 115, flush=True)

    summary_by_model, detailed_records = {}, []
    for m in models_to_run:
        print(f"\n[>>>] ĐANG ĐÁNH GIÁ: {m.upper()} ({ALL_EVAL_TARGETS[m]})", flush=True)
        print("-" * 115, flush=True)
        print(f"{'STT':<4} | {'Case ID':<40} | {'GroundTruth':<10} | {'Dự đoán':<8} | {'Phân loại':<20} | {'TG(s)':<6} | Diễn giải", flush=True)
        print("-" * 115, flush=True)

        model_records = []
        for idx, cid in enumerate(case_ids, start=1):
            cached = cached_map.get((m, cid))
            if cached and cached.get("pred_label") != "ERROR":  # ca lỗi lần trước được chạy lại
                record = {k: cached.get(k, "") for k in DETAIL_FIELDS}
                record["scenario"] = scenario_key
                record["elapsed_seconds"] = float(cached.get("elapsed_seconds") or 0)
                record["json_valid"] = str(cached.get("json_valid", "True")) == "True"
            else:
                gt = read_ground_truth(cid, data_dir)
                res = run_single_evaluation(case_id=cid, model_key=m, filter_noise=True, data_dir=data_dir)
                record = {
                    "scenario": scenario_key,
                    "model_key": m,
                    "case_id": cid,
                    "ground_truth": gt,
                    "pred_label": res["pred_label"],
                    "classification": classify_result(gt, res["pred_label"]),
                    "elapsed_seconds": res["elapsed_seconds"],
                    "json_valid": res["json_valid"],
                    "decision_source": res.get("decision_source", ""),
                    "ai_label": res.get("ai_label", ""),
                    "risk_score": res.get("risk_score", 0),
                    "stages": "; ".join(res["stages"]),
                    "reason": res["reason"] or ", ".join(res["stages"]),
                }
                if on_record:
                    on_record(record)
            reason = str(record["reason"])
            print(f"{idx:02d}   | {cid:<40} | {record['ground_truth']:<10} | {record['pred_label']:<8} | "
                  f"{record['classification']:<20} | {record['elapsed_seconds']:<6.3f} | "
                  f"{reason if len(reason) <= 45 else reason[:42] + '...'}", flush=True)
            model_records.append(record)
            detailed_records.append(record)

        summary_by_model[m] = calculate_metrics(model_records)

    print_table(f"BẢNG SO SÁNH CHỈ SỐ: {sc_info['title']}", summary_by_model, models_to_run)
    return summary_by_model, detailed_records


def write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def summary_row(scenario: str, m: str, met: dict) -> dict:
    return {
        "scenario": scenario, "model_key": m, "model_name": ALL_EVAL_TARGETS[m],
        "total_cases": met["total_cases"], "tp": met["tp"], "tn": met["tn"], "fp": met["fp"], "fn": met["fn"],
        "review": met["review"], "unknown": met["unknown"], "errors": met["errors"],
        "precision": met["precision"], "recall": met["recall"], "f1": met["f1"], "accuracy": met["accuracy"],
        "fpr": met["fpr"], "avg_inference_latency": met["avg_latency"], "e2e_latency_estimate": met["e2e_latency"],
    }


def main():
    parser = argparse.ArgumentParser(description="Đánh giá phân tầng 3 kịch bản trên benchmark 600 ca (200 ca mỗi bài).")
    parser.add_argument("--scenario", default="all", choices=["1", "2", "3", "all"])
    parser.add_argument("--models", default="qwen,llama,deepblue,sigma",
                        help="qwen, llama, deepblue, sigma, non_ai_baseline (deepblue/sigma = mô phỏng luật regex)")
    parser.add_argument("--data-dir", default="data_benchmark", help="Thư mục dữ liệu (tương đối với thư mục gốc)")
    parser.add_argument("--output-dir", default="results/benchmark600", help="Thư mục xuất kết quả + cache")
    parser.add_argument("--force-rerun", action="store_true", help="Bỏ qua cache, suy luận lại toàn bộ")
    parser.add_argument("--max-gpu-temp", type=int, default=0,
                        help="Chờ GPU nguội tới ngưỡng này (°C) trước mỗi lần gọi mô hình. 0 = tắt")
    args = parser.parse_args()
    if args.max_gpu_temp:
        pace_model_calls(args.max_gpu_temp)

    models_to_run = list(dict.fromkeys(
        ALIASES.get(m.strip().lower(), m.strip().lower()) for m in args.models.split(",") if m.strip()
    ))
    invalid = [m for m in models_to_run if m not in ALL_EVAL_TARGETS]
    if invalid:
        print(f"[!] Đối tượng không hợp lệ: {invalid}. Chọn từ: {list(ALL_EVAL_TARGETS)}")
        return

    data_dir = Path(args.data_dir) if Path(args.data_dir).is_absolute() else BASE / args.data_dir
    if not data_dir.is_dir():
        print(f"[!] Không tìm thấy thư mục dữ liệu: {data_dir} (sinh bằng: python core/build_600_cases.py)")
        return
    out_dir = Path(args.output_dir) if Path(args.output_dir).is_absolute() else BASE / args.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    cached_map = {} if args.force_rerun else load_cached_results(out_dir)

    scenarios = ["1", "2", "3"] if args.scenario == "all" else [args.scenario]
    all_details, summary_rows = [], []
    checkpoint = make_checkpoint(out_dir)
    for sc_key in scenarios:
        summary, details = run_scenario(sc_key, models_to_run, data_dir, cached_map, on_record=checkpoint)
        all_details.extend(details)
        if details:
            write_csv(out_dir / f"scenario_{sc_key}_details.csv", details, DETAIL_FIELDS)
        summary_rows.extend(summary_row(f"Bài {sc_key}", m, summary[m]) for m in models_to_run)

    # Cache: gộp kết quả lần này vào các kết quả đã có (chạy riêng từng bài vẫn được lưu lại)
    merged = load_cached_results(out_dir)
    merged.update({(r["model_key"], r["case_id"]): r for r in all_details})
    if merged:
        write_csv(out_dir / "comparison_details.csv", list(merged.values()), DETAIL_FIELDS)

    if args.scenario == "all" and all_details:
        grand = {m: calculate_metrics([r for r in all_details if r["model_key"] == m]) for m in models_to_run}
        summary_rows.extend(summary_row(f"TỔNG THỂ {len(all_details) // max(len(models_to_run), 1)} CA", m, grand[m])
                            for m in models_to_run)
        print_table(f"BẢNG SO SÁNH TỔNG HỢP: TOÀN BỘ {len(all_details) // max(len(models_to_run), 1)} CA",
                    grand, models_to_run)

    if summary_rows:
        write_csv(out_dir / "comparison_summary.csv", summary_rows, list(summary_rows[0].keys()))
    print(f"\n[✓] HOÀN TẤT. Kết quả lưu tại: {out_dir}")


if __name__ == "__main__":
    main()
