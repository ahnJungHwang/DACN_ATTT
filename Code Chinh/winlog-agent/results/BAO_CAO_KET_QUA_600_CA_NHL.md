# Báo cáo kết quả đánh giá 600 ca (bộ số liệu mới)

> Lập ngày 18/11/2026. Số liệu lấy từ `results/benchmark600/` (CSV từng ca), chạy bằng code đã gộp bản update 14/11/2026.
> Báo cáo trình bày **lần chạy 2** (code đã gộp bản update). **Lần chạy 1** (code trước khi gộp) được giữ để đối chiếu ở phần 5.

## 1. Tóm tắt

- Trên 600 ca (150 tấn công, 450 bình thường), **Qwen 2.5 3B** có recall **48,0%**, F1 **0,640**, báo giả **3/450**.
- **Llama 3.2 3B**: recall 39,3%, F1 0,565, báo giả **0/450**, nhưng **146 ca** bị chuyển UNKNOWN (AI không đủ căn cứ để kết luận).
- Hai baseline luật (mô phỏng DeepBlueCLI và Sigma) chỉ đạt recall 15,3%, bằng nhau ở mọi bài.
- Cả hai mô hình AI đều hơn hẳn baseline luật về recall; Qwen nhỉnh hơn Llama. Điểm đáng lưu ý: **recall thấp hơn nhiều so với lần chạy 1** (83,2% xuống 48,0% với Qwen).

## 2. Dữ liệu và cách đánh giá

- **600 ca** chia ba bài, mỗi bài 200 ca (50 tấn công, 150 bình thường): Bài 1 sự kiện đơn lẻ và chữ ký tĩnh; Bài 2 chuỗi sự kiện liên hoàn; Bài 3 ca biên và hành vi quản trị dễ báo giả.
- **Dữ liệu tự sinh** bằng `core/build_600_cases.py`, không lấy từ EVTX-ATTACK-SAMPLES. Mỗi ca có `manifest.json` chứa nhãn chuẩn (`ground_truth`). Nhãn không được đưa vào đầu vào mô hình.
- **Hệ thống** là mô hình lai: luật tương quan mạnh luôn kích hoạt ALERT; tín hiệu yếu do AI quyết định; kết luận của AI được kiểm chứng với dữ liệu thật (hạ xuống UNKNOWN nếu AI không dẫn được mã sự kiện hợp lệ).
- **Môi trường:** Ollama chạy cục bộ, cùng lượng tử hóa Q4_K_M cho cả hai mô hình; GPU RTX 3050 Laptop 4 GB; nhiệt độ sinh 0, `num_ctx` 8192, tối đa 512 token đầu ra.
- **Cách tính:** UNKNOWN không được tính là cảnh báo. Ca tấn công mà hệ thống trả NORMAL hoặc UNKNOWN đều tính là bỏ sót (FN). Ca bình thường trả UNKNOWN không tính là báo giả.
- **DeepBlueCLI và Sigma trong bảng này là mô phỏng bằng regex** (`core/rule_baselines.py`), không phải công cụ thật. Kết quả công cụ thật nằm ở phần 6.

## 3. Kết quả tổng hợp 600 ca

| Chỉ số | Qwen 2.5 3B | Llama 3.2 3B | DeepBlueCLI (mô phỏng) | Sigma (mô phỏng) |
|---|---:|---:|---:|---:|
| Bắt trúng (TP) | 72 | 59 | 23 | 23 |
| Bỏ sót (FN) | 78 | 91 | 127 | 127 |
| Đúng bình thường (TN) | 446 | 365 | 450 | 450 |
| Báo giả (FP) | 3 | 0 | 0 | 0 |
| Chuyển UNKNOWN | 15 | 146 | 0 | 0 |
| Precision | 96,0% | 100,0% | 100,0% | 100,0% |
| **Recall** | 48,0% | 39,3% | 15,3% | 15,3% |
| **F1** | 0,640 | 0,565 | 0,266 | 0,266 |
| Accuracy | 86,3% | 70,7% | 78,8% | 78,8% |
| FPR | 0,7% | 0,0% | 0,0% | 0,0% |

**Khoảng tin cậy Wilson 95%** (xem các ca là độc lập; dữ liệu tự sinh nên có thể chưa hoàn toàn độc lập):

| Mô hình | Recall (TP/150) | Báo giả (FP/450) |
|---|---|---|
| Qwen 2.5 3B | 48,0% (40,2% đến 55,9%) | 3/450 (0,23% đến 1,94%) |
| Llama 3.2 3B | 39,3% (31,9% đến 47,3%) | 0/450 (0,00% đến 0,85%) |

## 4. Kết quả theo từng bài

### Bài 1

| Công cụ | TP | FN | TN | FP | UNKNOWN | Recall | Precision | F1 | Accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Qwen 2.5 3B | 30 | 20 | 150 | 0 | 0 | 60,0% | 100,0% | 0,750 | 90,0% |
| Llama 3.2 3B | 32 | 18 | 111 | 0 | 47 | 64,0% | 100,0% | 0,780 | 71,5% |
| DeepBlueCLI (mô phỏng) | 16 | 34 | 150 | 0 | 0 | 32,0% | 100,0% | 0,485 | 83,0% |
| Sigma (mô phỏng) | 16 | 34 | 150 | 0 | 0 | 32,0% | 100,0% | 0,485 | 83,0% |

### Bài 2

| Công cụ | TP | FN | TN | FP | UNKNOWN | Recall | Precision | F1 | Accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Qwen 2.5 3B | 28 | 22 | 150 | 0 | 0 | 56,0% | 100,0% | 0,718 | 89,0% |
| Llama 3.2 3B | 16 | 34 | 125 | 0 | 49 | 32,0% | 100,0% | 0,485 | 70,5% |
| DeepBlueCLI (mô phỏng) | 6 | 44 | 150 | 0 | 0 | 12,0% | 100,0% | 0,214 | 78,0% |
| Sigma (mô phỏng) | 6 | 44 | 150 | 0 | 0 | 12,0% | 100,0% | 0,214 | 78,0% |

### Bài 3

| Công cụ | TP | FN | TN | FP | UNKNOWN | Recall | Precision | F1 | Accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Qwen 2.5 3B | 14 | 36 | 146 | 3 | 15 | 28,0% | 82,4% | 0,418 | 80,0% |
| Llama 3.2 3B | 11 | 39 | 129 | 0 | 50 | 22,0% | 100,0% | 0,361 | 70,0% |
| DeepBlueCLI (mô phỏng) | 1 | 49 | 150 | 0 | 0 | 2,0% | 100,0% | 0,039 | 75,5% |
| Sigma (mô phỏng) | 1 | 49 | 150 | 0 | 0 | 2,0% | 100,0% | 0,039 | 75,5% |

### Ai quyết định cảnh báo đúng (TP theo nguồn)

| Mô hình | Chỉ luật | Luật và AI | Chỉ AI |
|---|---:|---:|---:|
| Qwen 2.5 3B | 28 | 21 | 23 |
| Llama 3.2 3B | 29 | 20 | 10 |

### Các ca bị chuyển UNKNOWN

| Mô hình | Ca tấn công trả UNKNOWN | Ca bình thường trả UNKNOWN |
|---|---:|---:|
| Qwen 2.5 3B | 14 | 1 |
| Llama 3.2 3B | 61 | 85 |

### Nhóm ca tấn công bị bỏ sót nhiều nhất (Qwen)

| Nhóm | Số ca | Bỏ sót |
|---|---:|---:|
| apt_chain_step | 35 | 17 |
| stealth_evasion_sample | 35 | 32 |
| khác | 80 | 29 |

**Báo giả của Qwen (3 ca):** `case_b3_norm_004_it_create_new_employee`; `case_b3_norm_034_it_create_new_employee`; `case_b3_norm_049_it_create_new_employee`. Cả ba là thao tác quản trị hợp lệ (IT tạo tài khoản nhân viên mới, Event 4720) mà luật và AI đều gắn ALERT. Đây là điểm yếu thật cần ghi nhận.

## 5. Lần chạy 1 và lần chạy 2

**Tổng hợp 600 ca.**

| | Lần chạy 1 (code cũ) | Lần chạy 2 (code mới) |
|---|---|---|
| Qwen 2.5 3B: recall | 83,2% (124/149) | 48,0% (72/150) |
| Qwen 2.5 3B: báo giả | 0/450 | 3/450 |
| Llama 3.2 3B: recall | 100,0% (149/149) | 39,3% (59/150) |
| Llama 3.2 3B: báo giả | 329/450 | 0/450 |


**Theo từng bài (recall / số báo giả trên 150 ca bình thường).**

| Bài | Qwen lần 1 | Qwen lần 2 | Llama lần 1 | Llama lần 2 |
|---|---|---|---|---|
| 1 | 61,2% / 0 | 60,0% / 0 | 100,0% / 102 | 64,0% / 0 |
| 2 | 96,0% / 0 | 56,0% / 0 | 100,0% / 100 | 32,0% / 0 |
| 3 | 92,0% / 0 | 28,0% / 3 | 100,0% / 127 | 22,0% / 0 |

Số liệu lần chạy 1 nằm ở `results/benchmark600_update_old/`.

Các điểm khác cần nói rõ:

- **Hai lần chạy dùng hai phiên bản code khác nhau.** Lần chạy 1 dùng code của bản update; lần chạy 2 dùng code đã gộp, trong đó không giữ lại các luật viết riêng cho bộ test.
- **Luật không phải nguyên nhân chính của chênh lệch.** Bộ luật code cũ chỉ bắn thêm được **1 trong 79** ca tấn công mà code mới bỏ sót (ca đó do một lỗi bỏ đuôi `.exe`, đã sửa). Nguyên nhân nhiều khả năng nằm ở lớp AI (prompt, kiểm chứng bằng chứng, xử lý tín hiệu yếu); điều này **chưa được thử nghiệm xác nhận**.
- **Mẫu số khác:** lần chạy 1 có 1 ca lỗi dữ liệu (ca 47 Bài 1) nên mẫu số là 599; lần chạy 2 chạy đủ 600 ca.
- **Llama đảo chiều:** lần chạy 1 ghi Llama bắt 100% nhưng báo giả 329/450; code mới chặn hết báo giả nhưng chuyển 146 ca sang UNKNOWN và bỏ sót nhiều hơn.

## 6. Công cụ không dùng AI thật: DeepBlueCLI

Ngoài bản mô phỏng ở trên, DeepBlueCLI **bản thật** đã được chạy trên log EVTX thật (không cùng dữ liệu 600 ca, vì 600 ca là file XML tự sinh):

| Bộ dữ liệu | Kết quả DeepBlueCLI thật |
|---|---|
| EVTX-ATTACK-SAMPLES, 278 file tấn công | bắt 43/278 = **15,5%** (độ nhạy) |
| Log Windows 10 bình thường, 351 file đã quét | 3 báo giả = **0,85%** |

Độ nhạy của DeepBlueCLI thật (15,5%) gần với bản mô phỏng (15,3%), nhưng đây là hai bộ dữ liệu khác nhau nên chỉ là trùng hợp, không chứng minh mô phỏng đúng. File: `eval_real/deepblue_attack_samples_NHL.csv`, `eval_real/deepblue_baseline_normal_NHL.csv`; so sánh trên 23 ca log thật: `eval_real/SO_SANH_CONG_CU.md`.

## 7. Độ trễ

- **Độ trễ đo thật** (từ lúc sinh sự kiện đến khi nhận cảnh báo Telegram), phiên đo ngày 11 đến 12/11 với Qwen: trung vị **23,7 giây** (P95 32,9 giây, tối đa 33,9 giây, 13 cảnh báo đã gửi). AI phân tích chiếm khoảng 58%, client gom và gửi khoảng 31%. Chi tiết: `results/LATENCY_REPORT.md`.
- **Cột "độ trễ toàn trình" trong bảng benchmark chỉ là ước lượng** (thời gian suy luận cộng hằng số 3,68 giây), không phải số đo. Không dùng để so với số đo thật.
- **Thời gian suy luận khi chạy benchmark** lần này (khoảng 9 đến 12 giây/ca) bị phình do GPU nóng và bị hạ xung nhịp; lúc GPU mát chỉ khoảng 4 giây/ca. Không dùng con số này để so tốc độ giữa các mô hình.
- Số đo độ trễ được thực hiện trước khi gộp code, mẫu còn nhỏ (13 cảnh báo, 1 máy client), nên cần đo lại.

## 8. Chống trùng cảnh báo và độ ổn định

- `core/alerting.py` gom cảnh báo theo (máy, mã MITRE cha) trong 10 phút. Trong phiên đo: 13 cảnh báo được gửi, 23 ALERT bị chặn vì trùng. Có test `tests/test_alerting.py`; toàn bộ 27 test đều OK.
- Agent giữ log khi server ngừng và gửi bù khi server chạy lại, không mất log (một lô chờ 378 giây).
- Chưa có phép thử chạy liên tục nhiều giờ, và chưa đo tỉ lệ chặn nhầm của cơ chế chống trùng.

## 9. Hạn chế

1. **Dữ liệu tự sinh và luật do cùng nhóm viết**, nên kết quả có thể không phản ánh log thật. Cần thêm đánh giá trên log thật (đã có một phần ở phần 6).
2. **Recall thấp:** Qwen 48,0%, Llama 39,3%. Bài 3 thấp nhất (Qwen 28,0%), tập trung ở nhóm `stealth_evasion_sample` và `apt_chain_step`.
3. **Chưa xác định nguyên nhân chênh lệch giữa hai lần chạy ở cấp lớp AI**; cần thí nghiệm riêng (ví dụ đổi prompt hoặc nới lớp kiểm chứng) và ghi rõ nếu có chỉnh theo bộ test.
4. **DeepBlueCLI và Sigma ở bảng 600 ca là mô phỏng**, chưa chạy công cụ thật trên cùng dữ liệu; Sigma chưa chạy thật ở bất kỳ bộ nào.
5. **Mỗi cấu hình chạy một lần** (nhiệt độ sinh 0), chưa lặp để đo độ biến thiên.

## 10. File dữ liệu trong repo

| File | Nội dung |
|---|---|
| `results/benchmark600/comparison_summary.csv` | Bảng tổng hợp theo bài và toàn bộ |
| `results/benchmark600/comparison_details.csv` | Kết quả từng ca, từng mô hình (nhãn chuẩn, dự đoán, nguồn quyết định, lý do) |
| `results/benchmark600/scenario_{1,2,3}_details.csv` | Chi tiết từng ca theo bài |
| `results/benchmark600_update_old/` | Số liệu lần chạy 1 (code cũ), giữ để đối chiếu |
| `labels/cases_labels.csv` | Nhãn từng ca của các bộ dữ liệu nhỏ |
| `data_benchmark/` | 600 ca (XML) và `manifest.json` nhãn chuẩn |
| `eval_real/*_NHL.csv` | Kết quả DeepBlueCLI thật |
| `core/run_scenario_benchmark.py`, `bat/run_scenarios.bat` | Chạy lại benchmark (có lưu sau từng ca, tiếp tục được khi bị ngắt) |

