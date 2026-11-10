# Hướng dẫn sử dụng thư mục `blind_test/`

**Kiểm thử mù:** gửi các ca đã giấu nhãn từ máy ảo về server, rồi mới so với đáp án.
Cách này để đảm bảo kết quả đánh giá khách quan: AI không thể "đoán" nhờ tên thư mục, tên user hay tên file lộ đáp án.

## Các file

| File | Chạy ở đâu | Chức năng |
|---|---|---|
| `make_blind_set.py` | Máy server | Tạo bộ mù từ các ca có nhãn. |
| `blind_set/` | — | Bộ mù đã tạo: các ca `B001`, `B002`... không có `manifest.json`. **Chép thư mục này sang máy ảo.** |
| `answer_key.csv` | Máy server | Đáp án. **Không chép sang máy ảo.** |
| `anonymization_map.json` | Máy server | Bảng đổi tên khi ẩn danh, giữ lại để tra cứu. |
| `replay_blind.ps1` | Máy ảo | Gửi lần lượt từng ca trong bộ mù về server qua `/ingest`. |
| `score_blind.py` | Máy server | Chấm điểm sau khi đã gửi xong. |

## Quy trình 3 bước

### 1. Tạo bộ mù (trên máy server, đứng ở thư mục gốc `winlog-agent`)

```powershell
.venv\Scripts\python.exe blind_test\make_blind_set.py
.venv\Scripts\python.exe blind_test\make_blind_set.py --src data01 --seed 2026 --force
```

| Tham số | Ý nghĩa |
|---|---|
| `--src` | Thư mục ca có nhãn. Mặc định `data01`. |
| `--out` | Nơi xuất bộ mù. Mặc định `blind_test/blind_set`. |
| `--key` | Nơi ghi đáp án. Mặc định `blind_test/answer_key.csv`. |
| `--seed` | Seed xáo trộn thứ tự ca. |
| `--no-anonymize` | Không ẩn danh nội dung log. |
| `--force` | Ghi đè bộ mù cũ. |

Script đổi tên ca thành `B001..`, bỏ `manifest.json` và ẩn danh tên user, tên máy, tên miền C2, tên file lộ đáp án.
Script **không** sửa lệnh tấn công, và tự kiểm tra rằng luật tương quan cho kết quả y hệt trước và sau khi ẩn danh.

### 2. Gửi bộ mù từ máy ảo

Chép `blind_set\` và `replay_blind.ps1` sang máy ảo, cho vào cùng một thư mục, rồi chạy:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\replay_blind.ps1 -ServerUrl https://192.168.153.1:9443/ingest -Model qwen
powershell -NoProfile -ExecutionPolicy Bypass -File .\replay_blind.ps1 -DryRun     # chỉ thử, không gửi
```

| Tham số | Mặc định | Ý nghĩa |
|---|---|---|
| `-ServerUrl` | `https://192.168.153.1:9443/ingest` | Địa chỉ server. |
| `-Model` | `qwen` | Mô hình phân tích. |
| `-Prefix` | `blind_` | Tiền tố `client_id`. Ví dụ ca B001 được gửi với `client_id` là `blind_B001`. |
| `-DelaySeconds` | `2` | Số giây nghỉ giữa 2 ca. |
| `-TimeoutSeconds` | `600` | Thời gian chờ tối đa mỗi ca. |
| `-BlindDir`, `-OutCsv` | — | Đổi thư mục bộ mù / file kết quả. |

Server tự lưu kết quả vào `results\client_blind_B001_live\`. Máy ảo ghi lại phản hồi của server vào `replay_log.csv`.

### 3. Chấm điểm (trên máy server)

```powershell
.venv\Scripts\python.exe blind_test\score_blind.py --model qwen
.venv\Scripts\python.exe blind_test\score_blind.py --model qwen --replay-log blind_test\replay_log.csv
```

| Tham số | Ý nghĩa |
|---|---|
| `--model` | `qwen` / `llama`. |
| `--key` | File đáp án. |
| `--results` | Thư mục kết quả của server. |
| `--replay-log` | `replay_log.csv` chép về từ máy ảo. Dùng khi không có kết quả trong `results/`. |
| `--prefix` | Tiền tố `client_id`. Mặc định `blind_`. |
| `--since` | Chỉ tính kết quả từ một mốc thời gian (để bỏ các lần chạy cũ). |
| `--baseline` | File kết quả đánh giá thường để so sánh. Mặc định `results/comparison_details.csv`. |
| `--out` | File báo cáo. Mặc định `blind_test/BLIND_REPORT_<model>.md`. |

Ca nào không tìm thấy kết quả sẽ bị đánh dấu `MISSING` và không tính vào chỉ số.
