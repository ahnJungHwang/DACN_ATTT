# Hướng dẫn sử dụng thư mục `core/`

Phần lõi của hệ thống: bộ phân tích log (luật tương quan + mô hình AI chạy local qua Ollama), công cụ đánh giá và các script sinh dữ liệu kiểm thử.
Các thư mục khác (`app/`, `web/backend/`, `blind_test/`, `eval_real/`) đều gọi vào `analyze.py` ở đây.

> Mọi lệnh bên dưới chạy từ **thư mục gốc `winlog-agent`**, không phải từ trong `core/`.
> Các script tự đọc/ghi dữ liệu ở thư mục gốc (`data/`, `data01/`, `data100/`, `results/`), dù file nằm trong `core/`.

## Các file

| File | Chức năng |
|---|---|
| `analyze.py` | Bộ phân tích chính. Đọc log XML của một ca, lọc nhiễu, chạy luật tương quan, rồi hỏi mô hình AI để ra kết luận `ALERT` / `NORMAL`. |
| `evaluate.py` | Chạy hàng loạt ca kiểm thử, so với nhãn đúng, tính Precision / Recall / F1 / độ trễ và so sánh các mô hình (qwen, llama). |
| `generate_datasets.py` | Sinh bộ ca kiểm thử cơ bản vào `data/`. |
| `generate_data01.py` | Sinh bộ chuẩn 40 ca vào `data01/` (10 lành tính, 10 tấn công đơn, 10 tấn công phức hợp, 10 ca biên). |
| `generate_data100.py` | Sinh ngẫu nhiên bộ lớn (mặc định 100 ca) vào `data100/`, bằng cách ghép các khối log có sẵn. |
| `alerting.py` | Server dùng khi chạy: **chống gửi trùng cảnh báo** (gom theo máy + kỹ thuật MITRE, cửa sổ `ALERT_DEDUP_MINUTES` phút) và **ghi độ trễ** từng lô vào `results/latency.csv`, `results/alerts_log.csv`. |
| `latency_report.py` | Tổng hợp độ trễ sự kiện → Telegram và hiệu quả chống trùng → `results/LATENCY_REPORT.md`, `latency_summary.csv`, `latency_alerts.csv`. |
| `build_labels.py` | Gộp nhãn mọi ca kiểm thử thành **một file CSV** → `labels/cases_labels.csv` + `labels/LABELS_SUMMARY.md` (tỉ lệ NORMAL/ALERT theo từng bộ). |
| `rule_baselines.py` | Baseline **không dùng AI**: `deepblue` / `sigma` / `non_ai_baseline`. Đây là bản **mô phỏng** luật DeepBlueCLI / SigmaHQ bằng regex, không phải chạy công cụ thật (DeepBlue thật: `eval_real/run_deepblue.ps1`). |
| `run_scenario_benchmark.py` | Đánh giá theo 3 bài trên benchmark 600 ca `data_benchmark/` → `results/benchmark600/`. |
| `build_600_cases.py` | Sinh lại benchmark 600 ca (log tổng hợp) vào `data_benchmark/`. Cần `--force` nếu đã có dữ liệu. |
| `event_store.py` | Cửa sổ sự kiện trượt bằng SQLite cho server (tắt mặc định, bật bằng `EVENT_WINDOW_SECONDS`). |

## Chỉ số vận hành và nhãn

```powershell
.venv\Scripts\python.exe core\latency_report.py      # sau mỗi lần demo: báo cáo độ trễ + chống trùng
.venv\Scripts\python.exe core\build_labels.py        # sau khi thêm/sửa ca: cập nhật CSV nhãn
.venv\Scripts\python.exe core\build_labels.py --datasets data01 data_normal   # chỉ một số bộ
```

- `labels/cases_labels.csv`: mỗi ca một dòng gồm `dataset, case_id, ground_truth, category, techniques, source_type, description`, số sự kiện Security/PowerShell/System, khung thời gian, `anonymized`, `files_present`, `path`.
- Nhãn lấy từ `manifest.json` của từng ca (`data`, `data01`, `data100`, `data_normal`) và từ `eval_real/labels.json`. Không gộp `blind_test/blind_set` (bản ẩn danh của data01) và `data/client_*_live` (log realtime chưa gán nhãn).
- Log bình thường thật được thu bằng [`ps1/export_normal_logs.ps1`](../ps1/HUONG_DAN_SU_DUNG_ps1.md).

## Yêu cầu

- Môi trường Python ảo `.venv` ở thư mục gốc đã cài `requirements.txt`.
- Ollama đang chạy và đã tải 2 mô hình:
  - `qwen` → `qwen2.5:3b-instruct-q4_K_M`
  - `llama` → `llama3.2:3b-instruct-q4_K_M`
- Biến môi trường (không bắt buộc, có thể đặt trong `.env`):
  - `OLLAMA_URL`: mặc định `http://127.0.0.1:11434/api/chat`.
  - `MAX_BATCH_CHARS`: số ký tự tối đa mỗi lô gửi cho AI, mặc định `15000`.

## Cấu trúc một ca kiểm thử

Mỗi ca là một thư mục, ví dụ `data01/case_attack_02_ps_c2_download/`, chứa:

- `security.xml`, `powershell.xml`, `system.xml`: log Windows dạng XML (file nào không có thì bỏ qua).
- `manifest.json`: nhãn đúng (`ALERT` / `NORMAL`) và mô tả. Chỉ `evaluate.py` dùng file này.

## `analyze.py` – phân tích một ca

```powershell
.venv\Scripts\python.exe core\analyze.py --case case_attack_02_ps_c2_download
.venv\Scripts\python.exe core\analyze.py --case case_attack_02_ps_c2_download --model llama
```

| Tham số | Ý nghĩa |
|---|---|
| `--case` | Tên ca (bắt buộc). Tìm trong `data01/` trước, không có thì tìm trong `data/`. |
| `--model` | `qwen` (mặc định) hoặc `llama`. |
| `--max-batch-chars` | Giới hạn ký tự mỗi lô gửi AI. |
| `--no-filter` | Không lọc các tiến trình hệ thống lành tính. |

Kết quả được lưu tại `results/<tên ca>/<model>_<thời gian>.json`.

**Cách hoạt động:**
1. Đọc sự kiện (`read_events`).
2. Bỏ nhiễu hệ thống (`is_benign_noise`).
3. Luật tương quan tìm các dấu hiệu rõ ràng (`correlate_security_events`): brute-force, tạo tài khoản backdoor, PowerShell tải mã độc, xóa nhật ký, cài service lạ, thêm vào nhóm quản trị, scheduled task đáng ngờ...
4. Chia lô và hỏi mô hình AI.
5. Kiểm tra lại kết luận của AI dựa trên chứng cứ trong log (`ground_verdict`, `verify_alert`).

## `evaluate.py` – đánh giá và so sánh mô hình

```powershell
.venv\Scripts\python.exe core\evaluate.py                       # toàn bộ ca, qwen + llama
.venv\Scripts\python.exe core\evaluate.py --quick               # chạy nhanh 4 ca mẫu
.venv\Scripts\python.exe core\evaluate.py --data-dir data100 --models qwen
```

| Tham số | Ý nghĩa |
|---|---|
| `--models` | Danh sách mô hình, cách nhau bằng dấu phẩy. Mặc định `qwen,llama`. |
| `--cases` | Chỉ chạy một số ca cụ thể. Để trống thì chạy hết. |
| `--quick` | Chỉ chạy 4 ca mẫu. |
| `--no-filter` | Không lọc nhiễu. |
| `--data-dir` | Thư mục ca. Mặc định `data01` nếu có, không thì `data`. |
| `--output-dir` | Nơi xuất báo cáo. Mặc định `results/`. |

Kết quả gồm bảng so sánh in ra màn hình, `results/comparison_details.csv` và báo cáo `results/COMPARISON_REPORT.md`.
Có thể chạy nhanh bằng [`bat/run_evaluation.bat`](../bat/run_evaluation.bat).

## Sinh dữ liệu kiểm thử

```powershell
.venv\Scripts\python.exe core\generate_datasets.py              # -> data/
.venv\Scripts\python.exe core\generate_data01.py                # -> data01/ (40 ca)
.venv\Scripts\python.exe core\generate_data100.py               # -> data100/ (100 ca, seed ngẫu nhiên)
.venv\Scripts\python.exe core\generate_data100.py --count 120 --seed 2026
```

- Cả 3 script đều có `--clean` để xóa dữ liệu đã sinh.
- `generate_data100.py` còn có các tham số:
  - `--count`: số ca cần sinh.
  - `--seed`: seed ngẫu nhiên. Seed luôn được ghi lại vào `data100/_generation_info.json`, nên có thể tạo lại đúng bộ cũ.
  - `--p-alert`: tỷ lệ ca tấn công, mặc định `0.5`.
  - `--out`: thư mục xuất.
- `generate_data100.py` cần có sẵn:
  - `data01/` (chạy `generate_data01.py` trước);
  - `data100_fragments/evtx/` (tạo bằng [`ps1/extract_evtx_fragments.ps1`](../ps1/extract_evtx_fragments.ps1)). Nếu thiếu, script chỉ dùng phần tấn công trong `data01/`.

## Lưu ý

- Không chạy script bằng cách `cd core` rồi gọi `python analyze.py`. Script vẫn chạy được, nhưng các đường dẫn tương đối truyền vào tham số sẽ khó đoán. Luôn đứng ở thư mục gốc.
- Nếu đổi tên mô hình trong Ollama, sửa từ điển `MODELS` ở đầu `analyze.py`.

## Gộp bản update 14/11/2026 (benchmark 600 ca, risk score)

Kiến trúc quyết định **giữ nguyên**: luật MẠNH luôn `ALERT` (lưới an toàn), còn lại AI quyết định, có kiểm chứng bằng chứng và vòng tự thẩm định. Những gì được bổ sung:

- **Brute force theo cửa sổ thời gian:** cùng tài khoản hoặc cùng IP, trong `CORRELATION_WINDOW_SECONDS` (mặc định 300 giây).
  - Đăng nhập mạng (LogonType 3/10) cần ≥ `NETWORK_BRUTE_FORCE_THRESHOLD` lần sai (mặc định 3).
  - Đăng nhập tại máy cần ≥ `INTERACTIVE_BRUTE_FORCE_THRESHOLD` lần sai (mặc định 5).
  - Có ≥ 3 lần sai nhưng không dồn dập thì chỉ là tín hiệu yếu `Multiple Failed Logons`.
- **Đăng nhập sau brute force (T1078):** phải khớp đúng tài khoản/IP và kiểu đăng nhập, trong vòng `POST_BRUTE_SUCCESS_WINDOW_SECONDS` (mặc định 600 giây).
- **16 nhóm chữ ký MITRE (luật mạnh)** thay cho một stage "Malware Execution" cũ: credential dumping, impair defenses, persistence, inhibit recovery, LOLBAS, certutil decode, lateral movement, ingress transfer, exfiltration, ransomware, UAC bypass...
  - Tải file từ URL nội bộ (IP private, `*.local`, `*.corp`...) **không** bị coi là C2.
  - Tên công cụ được so khớp cả khi có đuôi `.exe` (`wevtutil.exe cl`).
- **Event mới:** 4722 (bật tài khoản) và 4756 (thêm vào nhóm universal). `ps1/client_agent.ps1` đã thu thập thêm hai event này.
- **Kết quả (`verdict`) có thêm:**
  - `risk_score` (0–100, tham khảo), `confidence` (ước lượng theo nguồn quyết định), `detection_source` (bí danh của `decision_source`).
  - Nhãn `REVIEW`: thay cho `UNKNOWN` khi AI không kết luận được nhưng luật có tín hiệu yếu với điểm ≥ `REVIEW_RISK_THRESHOLD` (mặc định 40).
  - `ALERT` và `NORMAL` không bị đổi.
- `evaluate.py`:
  - Nhận thêm `--models deepblue,sigma,non_ai_baseline`.
  - Đọc được cấu trúc phân tầng `data_benchmark/bai_X/`.
  - Đếm `REVIEW` riêng: ca tấn công bị `REVIEW` vẫn tính là FN.
  - Có thêm các cột `category, mitre_technique, classification, risk_score`, thêm vào **cuối** `comparison_details.csv`.

```powershell
.venv\Scripts\python.exe core\run_scenario_benchmark.py --models deepblue,sigma          # vài giây
.venv\Scripts\python.exe core\run_scenario_benchmark.py --scenario 1 --models qwen --max-gpu-temp 75
.venv\Scripts\python.exe core\evaluate.py --data-dir data_benchmark --models qwen,deepblue
.venv\Scripts\python.exe -m unittest discover -s tests                                    # 25 test, không cần Ollama
```

- `run_scenario_benchmark.py` ghi vào `results/benchmark600/` và dùng file `comparison_details.csv` ở đó làm cache: ca nào đã chạy thì không chạy lại. Thêm `--force-rerun` để chạy lại toàn bộ.
- Cột "Độ trễ toàn trình" trong benchmark là **ước lượng**: thời gian phân tích + 3,68 giây cố định. Độ trễ đo thật nằm ở `results/latency.csv` → `latency_report.py`.
- `data_benchmark/` là **log tổng hợp** do `build_600_cases.py` sinh ra, không phải log thật. Khi viết báo cáo cần ghi rõ điều này.
- Server (`app/app.py`): đặt `EVENT_WINDOW_SECONDS=600` trong `.env` để mỗi lô được gộp với các sự kiện của 600 giây gần nhất (lưu ở `data/winlog_events.db`), giúp tương quan được brute force kéo dài qua nhiều lô gửi.
  - Mặc định là `0`, tức tắt: mỗi lô chỉ phân tích một lần như cũ.
  - Khi bật, cùng một sự kiện được phân tích lại ở nhiều lô. Chống trùng `ALERT_DEDUP_MINUTES` sẽ chặn việc gửi Telegram lặp, nhưng AI phải chạy nhiều hơn.
