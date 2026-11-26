"""
Scan Raw Windows Log - Scenario 3 Engine for WinLog AI SOC
Processes raw exported Windows logs (CSV) through Local SLMs (Qwen / LLaMA)
with real-time progress, live threat alerts, and automated markdown reports.
"""

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Fix terminal encoding on Windows
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

import requests

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from core.analyze import (
    MODELS,
    OLLAMA_URL,
    MAX_BATCH_CHARS,
    BatchVerdict,
    build_system_prompt,
    build_batch_payload,
    ground_verdict,
    correlate_security_events,
    is_benign_noise,
    verify_alert,
)

DEFAULT_ALL_CSV = BASE_DIR / "Windows Log" / "NHAN-LAM-LAPTOP_20261124_193235" / "All_Security_PowerShell.csv"
DEFAULT_KEY_CSV = BASE_DIR / "Windows Log" / "NHAN-LAM-LAPTOP_20261124_193235" / "Key_Events.csv"

def get_gpu_temperature() -> int | None:
    """Đọc nhiệt độ GPU NVIDIA qua nvidia-smi (độ C)."""
    try:
        res = subprocess.run(
            ["nvidia-smi", "--query-gpu=temperature.gpu", "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=1.5
        )
        val = res.stdout.strip()
        return int(val) if val.isdigit() else None
    except Exception:
        return None

def extract_message_data(event_id: int, msg: str) -> dict:
    """Parse key attributes from raw Windows Event message."""
    data = {}
    clean_msg = msg.replace("\r", " ").strip()
    
    # 1. Check details style: Key=Value
    matches = re.findall(r"([A-Za-z0-9_]+)=([^\r\n|\t]+)", clean_msg)
    for k, v in matches:
        v_str = v.strip()
        if v_str:
            data[k] = v_str

    # 2. Check Security style: Key: Value
    matches_sec = re.findall(r"([A-Za-z0-9 ]+):\s*([^\r\n|\t]+)", clean_msg)
    for k, v in matches_sec:
        k_clean = k.strip().replace(" ", "")
        v_str = v.strip()
        if v_str and k_clean not in data:
            data[k_clean] = v_str

    # 3. Special field extractions
    if event_id in (4104, 4103):
        # PowerShell Script Block text
        data["ScriptBlockText"] = clean_msg[:2500]
    elif event_id == 4688:
        # Process creation command line fallback
        if "CommandLine" not in data:
            m = re.search(r"Process Command Line:\s*([^\r\n]+)", clean_msg, re.IGNORECASE)
            if m:
                data["CommandLine"] = m.group(1).strip()
    elif event_id in (600, 400, 403):
        # Classic PowerShell Host
        if "HostApplication" not in data:
            m = re.search(r"HostApplication=([^\r\n|]+)", clean_msg)
            if m:
                data["HostApplication"] = m.group(1).strip()

    # Truncate any oversized fields
    for k, v in list(data.items()):
        if isinstance(v, str) and len(v) > 1500:
            data[k] = v[:1500] + "...[truncated]"

    # Fallback message summary if nothing parsed
    if not data:
        data["Message"] = clean_msg[:500]

    return data


def load_csv_events(csv_path: Path, limit: int | None = None) -> list[dict]:
    """Load and parse CSV logs into standardized SOC event format."""
    events = []
    print(f"[*] Đang đọc file log: {csv_path.name}...")
    
    with open(csv_path, mode="r", encoding="utf-8-sig", errors="ignore") as f:
        reader = csv.DictReader(f)
        idx = 0
        for row in reader:
            idx += 1
            if limit and idx > limit:
                break
            
            try:
                eid = int(row.get("Id", "0"))
            except ValueError:
                eid = 0

            msg = row.get("Message", "")
            data = extract_message_data(eid, msg)
            
            events.append({
                "time": row.get("TimeCreated", ""),
                "host": row.get("MachineName", "Nhan-Lam-Laptop"),
                "channel": row.get("LogName", ""),
                "provider": row.get("ProviderName", ""),
                "record_id": f"rec_{idx:06d}",
                "event_id": eid,
                "event_ref": f"E{idx:05d}",
                "data": data,
            })
            
    print(f"[+] Đã tải thành công {len(events):,} sự kiện.")
    return events


def create_event_batches(events: list[dict], max_chars: int = 14000, max_items: int = 40) -> list[list[dict]]:
    """Split events into LLM-digestible chunks with size and count bounds."""
    batches = []
    current_batch = []
    current_chars = 0

    for ev in events:
        ev_str = json.dumps(ev, ensure_ascii=False)
        ev_len = len(ev_str)

        if current_batch and (current_chars + ev_len > max_chars or len(current_batch) >= max_items):
            batches.append(current_batch)
            current_batch = [ev]
            current_chars = ev_len
        else:
            current_batch.append(ev)
            current_chars += ev_len

    if current_batch:
        batches.append(current_batch)

    return batches


def query_ollama(model_name: str, system_prompt: str, user_payload: str, schema: dict) -> dict:
    """Send structured inference request to local Ollama instance."""
    resp = requests.post(
        OLLAMA_URL,
        json={
            "model": model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_payload},
            ],
            "format": schema,
            "stream": False,
            "options": {
                "temperature": 0.0,
                "num_ctx": 8192,
                "num_predict": 512,
            },
        },
        timeout=(15, 300),
    )
    resp.raise_for_status()
    raw_content = resp.json().get("message", {}).get("content", "{}")
    return json.loads(raw_content)


def run_scanner(
    csv_path: Path,
    model_key: str = "qwen",
    limit: int | None = None,
    max_batch_chars: int = 14000,
    filter_noise: bool = True,
    verify: bool = True,
    max_temp: int = 75,
    delay: float = 1.0,
    stop_on_overheat: bool = False,
    resume: bool = True,
):
    model_name = MODELS.get(model_key, model_key)
    schema = BatchVerdict.model_json_schema()
    system_prompt = build_system_prompt(schema)
    cur_gpu_temp = get_gpu_temperature()

    print("=" * 75)
    print("      WINLOG SOC - QUÉT LOG WINDOWS BẰNG AI LOCAL SLM (KỊCH BẢN 3)")
    print("=" * 75)
    print(f"- Nguồn dữ liệu  : {csv_path}")
    print(f"- Mô hình AI     : {model_key.upper()} ({model_name})")
    print(f"- Giới hạn nhiệt : Tối đa {max_temp}°C (Hiện tại: {cur_gpu_temp or 'N/A'}°C, nghỉ {delay}s/lô)")
    print(f"- Xử lý khi nóng : {'Dừng hẳn ngay lập tức' if stop_on_overheat else f'Tạm dừng chờ hạ dưới {max_temp-5}°C'}")
    print(f"- Lọc nhiễu      : {'BẬT (Khuyên dùng)' if filter_noise else 'TẮT (Log thô)'}")
    print(f"- Tự thẩm định   : {'BẬT (Vòng 2 Second Opinion)' if verify else 'TẮT'}")
    print(f"- Ollama API     : {OLLAMA_URL}")
    print(f"- Giới hạn test  : {limit if limit else 'Toàn bộ log'}")
    print("=" * 75)

    # 1. Load and batch events
    raw_events = load_csv_events(csv_path, limit=limit)
    if not raw_events:
        print("[!] Không có sự kiện nào để xử lý.")
        return

    # Lọc nhiễu tiến trình hệ thống nếu bật
    if filter_noise:
        events = [e for e in raw_events if not is_benign_noise(e)]
        dropped = len(raw_events) - len(events)
        print(f"[+] Lọc nhiễu: Đã tự động loại bỏ {dropped:,} sự kiện hệ thống nền lành tính (còn lại {len(events):,} sự kiện).")
    else:
        events = raw_events

    batches = create_event_batches(events, max_chars=max_batch_chars)
    total_batches = len(batches)
    print(f"[*] Đã chia thành {total_batches:,} lô (batches).")

    # Kiểm tra tiến trình cũ để tự động chạy tiếp (Resume)
    results = []
    alerts = []
    start_batch_idx = 1
    events_done = 0

    suffix = "_NHL_26112026"
    safe_key = re.sub(r'[^a-zA-Z0-9_\-]', '_', model_key)
    out_dir = BASE_DIR / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / f"scan_windows_log_{safe_key}{suffix}.json"

    if resume and json_path.is_file():
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                prev_data = json.load(f)
            prev_batches = prev_data.get("batches", [])
            if prev_batches and len(prev_batches) < total_batches:
                results = prev_batches
                alerts = [r for r in results if r.get("verdict", {}).get("label") == "ALERT"]
                start_batch_idx = len(results) + 1
                events_done = sum(r.get("event_count", 0) for r in results)
                print(f"[+] TỰ ĐỘNG CHẠY TIẾP: Đã có {len(results):,} lô ({events_done:,} sự kiện) từ lần chạy trước.")
                print(f"[+] Sẽ chạy tiếp tục từ Lô #{start_batch_idx} đến #{total_batches} (không quét lại từ đầu)!\n")
            else:
                print(f"[*] Bắt đầu quét từ Lô #1...\n")
        except Exception:
            print(f"[*] Bắt đầu quét từ Lô #1...\n")
    else:
        print(f"[*] Bắt đầu quét từ Lô #1...\n")

    # 2. Scanning loop
    start_time = time.time()

    try:
        for b_idx in range(start_batch_idx, total_batches + 1):
            batch = batches[b_idx - 1]
            t_batch_start = time.time()
            payload = build_batch_payload(batch)
            events_done += len(batch)

            try:
                raw_verdict = query_ollama(model_name, system_prompt, payload, schema)
                verdict = BatchVerdict.model_validate(raw_verdict)
                grounded = ground_verdict(verdict, batch)
                verdict_dict = grounded.model_dump()

                # Vòng 2: Tự thẩm định lại (Second Opinion) nếu AI phát hiện ALERT
                if verdict_dict.get("label") == "ALERT" and verify:
                    keep_alert, verify_reason = verify_alert(batch, verdict_dict, model_name)
                    if not keep_alert:
                        verdict_dict["label"] = "NORMAL"
                        verdict_dict["reason"] = f"[Tự thẩm định vòng 2 xác nhận bình thường]: {verify_reason}"
                        verdict_dict["confidence"] = 0
                        verdict_dict["detected_stages"] = []
                        verdict_dict["evidence_refs"] = []
                    else:
                        verdict_dict["reason"] += f" (Xác nhận vòng 2: {verify_reason})"

            except Exception as e:
                verdict_dict = {
                    "label": "ERROR",
                    "confidence": 0,
                    "detected_stages": [],
                    "evidence_refs": [],
                    "reason": f"Lỗi gọi AI: {e}",
                }

            batch_elapsed = time.time() - t_batch_start
            label = verdict_dict.get("label", "UNKNOWN")
            conf = verdict_dict.get("confidence", 0)

            # Store result
            batch_record = {
                "batch": b_idx,
                "event_count": len(batch),
                "first_ref": batch[0]["event_ref"],
                "last_ref": batch[-1]["event_ref"],
                "time_range": f"{batch[0]['time']} -> {batch[-1]['time']}",
                "elapsed": round(batch_elapsed, 2),
                "verdict": verdict_dict,
            }
            results.append(batch_record)

            # Live progress display & GPU Thermal Monitoring
            progress_pct = (b_idx / total_batches) * 100
            time_spent = time.time() - start_time
            processed_in_run = b_idx - start_batch_idx + 1
            avg_speed = time_spent / max(1, processed_in_run)
            eta_sec = avg_speed * (total_batches - b_idx)
            eta_str = time.strftime("%H:%M:%S", time.gmtime(eta_sec))

            gpu_temp = get_gpu_temperature()
            temp_str = f"GPU: {gpu_temp}°C" if gpu_temp is not None else "GPU: N/A"

            status_color = ""
            if label == "ALERT":
                alerts.append(batch_record)
                status_color = " [🚨 ALERT!]"
            elif label == "ERROR":
                status_color = " [⚠️ ERROR]"

            print(
                f"[{b_idx:4d}/{total_batches}] {progress_pct:5.1f}% | "
                f"{temp_str} | "
                f"Sự kiện: {events_done:5d}/{len(events)} | "
                f"Tốc độ: {batch_elapsed:4.1f}s/lô (ETA: {eta_str}) | "
                f"{label:6s} ({conf:2d}%){status_color}",
                flush=True
            )

            # Print ALERT details immediately to console
            if label == "ALERT":
                print("\n" + "-" * 75)
                print(f"🚨 PHÁT HIỆN HÀNH VI ĐÁNG NGỜ Ở LÔ {b_idx}:")
                print(f"   - Thời gian    : {batch_record['time_range']}")
                print(f"   - Kỹ thuật     : {', '.join(verdict_dict.get('detected_stages', [])) or 'Chưa phân loại'}")
                print(f"   - Bằng chứng   : {', '.join(verdict_dict.get('evidence_refs', []))}")
                print(f"   - Lý do từ AI  : {verdict_dict.get('reason', '')}")
                print("-" * 75 + "\n")

            # GPU Thermal Guard: Bảo vệ nhiệt độ GPU (mặc định giới hạn 75°C)
            if gpu_temp is not None and gpu_temp >= max_temp:
                print(f"\n[❄️ BẢO VỆ GPU] Nhiệt độ GPU đạt {gpu_temp}°C (ngưỡng giới hạn an toàn: {max_temp}°C).")
                if stop_on_overheat:
                    print(f"     [!] Đã đạt ngưỡng {max_temp}°C theo yêu cầu (--stop-now). Dừng chạy hoàn toàn và chốt xuất file CSV...", flush=True)
                    break
                else:
                    print(f"     Đang tạm dừng cho quạt tản nhiệt làm mát GPU xuống dưới {max_temp - 4}°C...", flush=True)
                    stop_flag = False
                    wait_count = 0
                    while True:
                        time.sleep(8)
                        wait_count += 1
                        cur_t = get_gpu_temperature()
                        if cur_t is None or cur_t <= (max_temp - 4):
                            print(f"     Nhiệt độ đã hạ xuống an toàn: {cur_t}°C. Tiếp tục quét...\n", flush=True)
                            break
                        if wait_count >= 8:  # Chờ hơn 1 phút mà nhiệt vẫn không hạ
                            print(f"     [!] GPU vẫn ở mức {cur_t}°C sau hơn 1 phút. Tự động dừng an toàn để bảo vệ phần cứng!", flush=True)
                            stop_flag = True
                            break
                        print(f"     Nhiệt độ hiện tại: {cur_t}°C, tiếp tục chờ quạt hạ nhiệt...", flush=True)
                    if stop_flag:
                        break
            elif delay > 0:
                time.sleep(delay)

    except KeyboardInterrupt:
        print("\n[!] Người dùng đã tạm dừng quét (Ctrl+C). Đang tổng hợp các kết quả đã chạy...")

    prior_elapsed = prev_data.get("elapsed_seconds", 0) if (start_batch_idx > 1 and "prev_data" in locals()) else 0
    total_time = prior_elapsed + (time.time() - start_time)
    total_time_str = time.strftime("%H:%M:%S", time.gmtime(total_time))

    # 3. Export Summary & Reports (JSON, CSV, Markdown)
    out_dir = BASE_DIR / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    suffix = "_NHL_26112026"
    safe_key = re.sub(r'[^a-zA-Z0-9_\-]', '_', model_key)
    json_path = out_dir / f"scan_windows_log_{safe_key}{suffix}.json"
    csv_path_out = out_dir / f"scan_windows_log_{safe_key}{suffix}.csv"
    alerts_csv_out = out_dir / f"scan_windows_log_{safe_key}_alerts{suffix}.csv"
    md_path = out_dir / f"SCAN_WINDOWS_LOG_{safe_key.upper()}_REPORT{suffix}.md"

    summary_data = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "model": model_name,
        "source_file": str(csv_path),
        "total_events_scanned": events_done,
        "total_batches_processed": len(results),
        "total_alerts": len(alerts),
        "elapsed_seconds": round(total_time, 2),
        "batches": results,
    }

    # 3.1 Ghi JSON
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(summary_data, f, ensure_ascii=False, indent=2)

    # 3.2 Ghi CSV toàn bộ các lô (UTF-8 BOM để Excel mở tiếng Việt không lỗi font)
    csv_fieldnames = [
        "Lô (Batch)", "Số sự kiện", "Thời gian sự kiện", "Sự kiện đầu", "Sự kiện cuối",
        "Kết luận AI", "Độ tin cậy (%)", "Kỹ thuật MITRE ATT&CK", "Mã bằng chứng",
        "Lập luận chi tiết của AI", "Thời gian xử lý (giây)"
    ]
    with open(csv_path_out, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(csv_fieldnames)
        for r in results:
            v = r["verdict"]
            writer.writerow([
                r["batch"],
                r["event_count"],
                r["time_range"],
                r["first_ref"],
                r["last_ref"],
                v.get("label", "UNKNOWN"),
                v.get("confidence", 0),
                "; ".join(v.get("detected_stages", [])),
                "; ".join(v.get("evidence_refs", [])),
                v.get("reason", "").replace("\r", " ").replace("\n", " "),
                r["elapsed"]
            ])

    # 3.3 Nếu có cảnh báo ALERT, xuất riêng một file CSV chứa danh sách mối nguy hại
    if alerts:
        with open(alerts_csv_out, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(csv_fieldnames)
            for r in alerts:
                v = r["verdict"]
                writer.writerow([
                    r["batch"],
                    r["event_count"],
                    r["time_range"],
                    r["first_ref"],
                    r["last_ref"],
                    v.get("label", "ALERT"),
                    v.get("confidence", 0),
                    "; ".join(v.get("detected_stages", [])),
                    "; ".join(v.get("evidence_refs", [])),
                    v.get("reason", "").replace("\r", " ").replace("\n", " "),
                    r["elapsed"]
                ])

    # Markdown Report
    md_lines = [
        f"# Báo cáo Quét Log Windows Thực Tế — Kịch Bản 3",
        f"- **Mô hình AI:** `{model_name}`",
        f"- **File nguồn:** `{csv_path.name}`",
        f"- **Tổng sự kiện quét:** {events_done:,} sự kiện ({len(results)} lô)",
        f"- **Thời gian chạy:** {total_time_str} ({round(total_time, 1)}s)",
        f"- **Tốc độ trung bình:** {round(total_time / max(1, len(results)), 2)} giây / lô",
        f"- **Số cảnh báo nguy hiểm (ALERT):** **{len(alerts)}** cảnh báo",
        "",
        "## 1. Danh sách các Cảnh báo Phát hiện (ALERTs)",
        "",
    ]

    if not alerts:
        md_lines.append("> ✅ Không phát hiện hành vi tấn công hoặc mã độc trong phạm vi log đã quét.\n")
    else:
        for idx, alt in enumerate(alerts, 1):
            v = alt["verdict"]
            md_lines.extend([
                f"### Cảnh báo #{idx} (Lô {alt['batch']})",
                f"- **Thời gian:** `{alt['time_range']}`",
                f"- **Mức độ tin cậy:** {v.get('confidence', 0)}%",
                f"- **Kỹ thuật phát hiện:** `{', '.join(v.get('detected_stages', []))}`",
                f"- **Bằng chứng (Event Ref):** `{', '.join(v.get('evidence_refs', []))}`",
                f"- **Nhận định từ AI:** {v.get('reason', '')}",
                "",
            ])

    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines))

    print("\n" + "=" * 75)
    print("                  TỔNG KẾT QUÉT TOÀN BỘ LOG")
    print("=" * 75)
    print(f"- Tổng thời gian : {total_time_str} ({round(total_time, 1)}s)")
    print(f"- Sự kiện đã quét: {events_done:,} / {len(events):,}")
    print(f"- Lô đã xử lý    : {len(results):,} / {total_batches:,}")
    print(f"- Cảnh báo ALERT : {len(alerts)} cảnh báo nguy hiểm phát hiện")
    print(f"- Báo cáo CSV    : {csv_path_out}")
    if alerts:
        print(f"- Báo cáo Alerts : {alerts_csv_out}")
    print(f"- Báo cáo Markdown: {md_path}")
    print(f"- Báo cáo JSON   : {json_path}")
    print("=" * 75 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Quét toàn bộ log Windows bằng AI Local SLM (Kịch bản 3)")
    parser.add_argument("--file", default="key",
                        help="'all': All_Security_PowerShell.csv; 'key': Key_Events.csv; hoặc đường dẫn file CSV bất kỳ")
    parser.add_argument("--model", default="qwen",
                        help="Mô hình AI: 'qwen', 'llama', hoặc tên model Ollama bất kỳ (vd: 'qwen2.5:3b')")
    parser.add_argument("--limit", type=int, default=None,
                        help="Giới hạn số sự kiện quét (vd: --limit 100 để test nhanh)")
    parser.add_argument("--batch-chars", type=int, default=MAX_BATCH_CHARS,
                        help=f"Ký tự tối đa mỗi lô gửi cho AI (mặc định {MAX_BATCH_CHARS})")
    parser.add_argument("--no-filter", action="store_true",
                        help="Tắt bộ lọc nhiễu hệ thống (mặc định: lọc nhiễu tự động)")
    parser.add_argument("--no-verify", action="store_true",
                        help="Tắt vòng tự thẩm định Second Opinion (mặc định: bật)")
    parser.add_argument("--max-temp", type=int, default=75,
                        help="Ngưỡng nhiệt độ GPU tối đa (°C), chạm ngưỡng này sẽ tạm dừng chờ mát (mặc định 75°C)")
    parser.add_argument("--stop-now", action="store_true",
                        help="Nếu chạm 75°C thì dừng chạy hoàn toàn và xuất file CSV ngay (không chờ nguội)")
    parser.add_argument("--delay", type=float, default=1.5,
                        help="Số giây nghỉ giữa mỗi lô để GPU giải nhiệt (mặc định 1.5s)")
    parser.add_argument("--no-resume", action="store_true",
                        help="Không tự động chạy tiếp từ checkpoint cũ, quét lại từ Lô #1")

    args = parser.parse_args()
    if args.file == "all":
        target_csv = DEFAULT_ALL_CSV
    elif args.file == "key":
        target_csv = DEFAULT_KEY_CSV
    else:
        target_csv = Path(args.file)

    if not target_csv.is_file():
        print(f"[!] Không tìm thấy file: {target_csv}")
        sys.exit(1)

    run_scanner(
        csv_path=target_csv,
        model_key=args.model,
        limit=args.limit,
        max_batch_chars=args.batch_chars,
        filter_noise=not args.no_filter,
        verify=not args.no_verify,
        max_temp=args.max_temp,
        delay=args.delay,
        stop_on_overheat=args.stop_now,
        resume=not args.no_resume,
    )
