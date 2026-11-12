# Hướng dẫn sử dụng thư mục `eval_real/`

**Đánh giá hệ thống trên log tấn công THẬT**, lấy từ các bộ mẫu công khai DeepBlueCLI và EVTX-to-MITRE, thay vì log tự sinh.
Mục đích: kiểm tra hệ thống còn đúng không khi gặp dữ liệu ngoài đời.

## Các file

| File | Chức năng |
|---|---|
| `labels.json` | Nhãn đúng của từng ca, **chốt trước khi chạy mô hình**. Gồm nguồn file `.evtx`, nhãn `ALERT` / `NORMAL` và ca nào được tính điểm. |
| `build_cases.ps1` | Chuyển file `.evtx` thật thành các ca kiểm thử trong `cases/`. |
| `cases/` | Các ca đã tạo. Không có trong git; tạo lại bằng `build_cases.ps1`. |
| `run_eval.py` | Chạy đánh giá và tính chỉ số. |
| `real_log_results.csv` | Kết quả chi tiết từng ca. |
| `REAL_LOG_REPORT.md` | Báo cáo kết quả. |
| `PHAN_TICH_KET_QUA.md` | Phân tích, nhận xét kết quả. |
| `run_deepblue.ps1` | Chạy DeepBlueCLI (công cụ không dùng AI) trên cùng các file `.evtx`. Ghi `deepblue_results.csv`. |
| `compare_tools.py` | Chấm điểm và lập bảng so sánh DeepBlueCLI với hệ thống. Ghi `SO_SANH_CONG_CU.md`. |
| `normal_evtx/` | Các file `.evtx` xuất từ máy ảo trong lúc dùng bình thường. Mỗi file là một ca nhãn `NORMAL`, dùng để đo báo động giả. |
| `minh_chung/` | Ảnh chụp màn hình lúc chạy, làm minh chứng. |

## Quy trình 2 bước (đứng ở thư mục gốc `winlog-agent`)

### 1. Tạo ca kiểm thử từ EVTX thật

```powershell
powershell -ExecutionPolicy Bypass -File eval_real\build_cases.ps1
```

| Tham số | Mặc định | Ý nghĩa |
|---|---|---|
| `-LabelsPath` | `eval_real\labels.json` | File nhãn. |
| `-OutDir` | `eval_real\cases` | Nơi xuất các ca. |

- Chỉ lấy các sự kiện mà agent thật sự thu thập:
  - Security: 4624, 4625, 4648, 4688, 1102, 4720, 4728, 4732, 4698.
  - PowerShell: 4104.
  - System: 7045, 104.
- Bỏ sự kiện xóa nhật ký (1102/104) nếu nó là sự kiện **đầu tiên** của file. Đó là dấu vết người tạo mẫu dọn log trước khi ghi lại tấn công, không phải tấn công. Số sự kiện bị bỏ được ghi vào `manifest.json`.
- Script chỉ đọc log, không chạy nội dung nào trong log.
- Một số file có thể bị phần mềm diệt virus chặn. Những ca này bị đánh dấu "AV blocked" khi chạy đánh giá.

### 2. Chạy đánh giá

```powershell
.venv\Scripts\python.exe eval_real\run_eval.py --models qwen --repeats 3
.venv\Scripts\python.exe eval_real\run_eval.py --models qwen,llama --repeats 5
```

| Tham số | Mặc định | Ý nghĩa |
|---|---|---|
| `--models` | `qwen` | Danh sách mô hình, cách nhau bằng dấu phẩy. |
| `--repeats` | `3` | Số lần chạy lặp mỗi ca, để đo độ ổn định của mô hình. |

So sánh 3 cách phát hiện:
1. **Hệ thống**: luật mạnh + AI.
2. **Riêng AI**.
3. **Chỉ luật**: không dùng AI.

Mỗi chỉ số kèm khoảng tin cậy 95% (Wilson). Kết quả được ghi vào `real_log_results.csv` và `REAL_LOG_REPORT.md`.

### 3. So sánh với DeepBlueCLI

```powershell
powershell -ExecutionPolicy Bypass -File eval_realun_deepblue.ps1
.venv\Scripts\python.exe eval_real\compare_tools.py
```

- Tải `DeepBlue.ps1`, `regexes.txt`, `safelist.txt` từ <https://github.com/sans-blue-team/DeepBlueCLI> (đúng commit ghi trong `labels.json`) vào thư mục `tool` nằm cạnh thư mục `evtx` của DeepBlueCLI, hoặc chỉ đường dẫn bằng `-ToolDir`. Không đưa các file này vào repo (GPL-3.0).
- DeepBlueCLI được chạy trên cả các file trong `out_of_scope` của `labels.json`: đó là tấn công nằm ở loại log agent không thu.
- Một file có từ 1 phát hiện trở lên thì tính là `ALERT`. Ca mà mọi phát hiện chỉ là "Log Clear" thì tính là không bắt được, vì sự kiện xoá log trong bộ mẫu là dấu vết người tạo mẫu (hệ thống của nhóm cũng đã loại nó ở bước 1).
- Đo báo động giả: xuất log lúc dùng máy bình thường, ví dụ `wevtutil epl Security C:
ormal_session_01.evtx`, chép vào `eval_real
ormal_evtx\` rồi chạy lại 2 lệnh trên.

## Yêu cầu

- Ollama đang chạy với mô hình cần đánh giá.
- Có thư mục `dataset/` chứa các file `.evtx` gốc theo đường dẫn trong `labels.json`.
