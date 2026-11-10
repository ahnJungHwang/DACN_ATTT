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
