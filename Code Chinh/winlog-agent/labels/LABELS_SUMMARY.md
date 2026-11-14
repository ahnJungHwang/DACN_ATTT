# Tổng hợp nhãn bộ đánh giá

> Tạo lúc 12/11/2026 01:00 bằng `core/build_labels.py`. Chi tiết từng ca: [`cases_labels.csv`](cases_labels.csv).

| Bộ dữ liệu | Loại nguồn | Số ca | NORMAL | ALERT | Không chấm điểm | **Tỉ lệ bình thường** | Cần thêm NORMAL để đạt 85% | Sự kiện Security / tổng |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| data | synthetic | 15 | 6 | 9 | 0 | **40%** | 45 | 259 / 292 |
| data01 | synthetic | 40 | 15 | 25 | 0 | **38%** | 127 | 123 / 144 |
| data100 | synthetic_mixed | 100 | 54 | 46 | 0 | **54%** | 207 | 919 / 1006 |
| eval_real | real_evtx | 23 | 0 | 21 | 2 | **0%** | 119 | 0 / 0 |
| **Tổng (có trùng lặp, chỉ để tham khảo)** | | **178** | 75 | 101 | 2 | 43% | | |

## Ghi chú

- Yêu cầu đánh giá: **phần lớn là log bình thường** (gần thực tế). Mục tiêu đề xuất: ≥ 85% NORMAL.
- Mỗi lần đánh giá dùng **từng bộ riêng** (hoặc một bộ ghép có chủ đích), không cộng dồn mọi bộ: `data100` được ghép từ fragment của `data01`, nên dòng Tổng có trùng lặp.
- Log bình thường thu thêm bằng `ps1/export_normal_logs.ps1` (lưu vào `data_normal/`), rồi chạy lại script này.
- **Không chấm điểm** = nhãn `UNKNOWN`: nguồn không mô tả nội dung (vd 2 ca `eval_real` loại `unlabeled`), cố ý không tính vào chỉ số.
- `source_type`: `synthetic` = log tự sinh; `synthetic_mixed` = ghép từ fragment thật/tự sinh; `real_pc` = log thật trên máy cá nhân; `real_evtx` = mẫu EVTX tấn công công khai.
- Không gộp `blind_test/blind_set` (bản ẩn danh của data01) và `data/client_*_live` (log realtime chưa gán nhãn).
- 23 ca chưa có file XML trên máy (vd `eval_real/cases`, tạo lại bằng `eval_real/build_cases.ps1`); vẫn giữ dòng nhãn trong CSV, cột `files_present` = False.
