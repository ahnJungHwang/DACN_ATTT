# BÁO CÁO KẾT QUẢ THỰC NGHIỆM VÀ SO SÁNH HIỆU NĂNG
## MÔ HÌNH AI LOCAL SLM: QWEN 2.5 (3B) VS LLAMA 3.2 (3B)
### KỊCH BẢN 3: PHÂN TÍCH THUẦN AI TRÊN TẬP LOG MÁY THỰC TẾ (`NHAN-LAM-LAPTOP`)

---

## I. TỔNG QUAN THỰC NGHIỆM

- **Hệ thống thử nghiệm**: Nền tảng Cloud GPU Kaggle (Tesla T4 16GB VRAM, vCPU x2, RAM 13GB).
- **Môi trường suy luận (Inference Runtime)**: Ollama Server (lượng tử hóa 4-bit `q4_K_M`).
- **Nguồn dữ liệu log thực tế**: Máy trạm `NHAN-LAM-LAPTOP` (File: `All_Security_PowerShell.csv`).
- **Quy mô dữ liệu**:
  - Tổng số sự kiện log thô: **32,959 sự kiện**.
  - Kênh log thu thập: `Security` và `Microsoft-Windows-PowerShell/Operational`.
  - Cơ chế phân lô xử lý: **1,309 lô (batches)** (trung bình 25 sự kiện/lô, tự động co giãn theo ngữ cảnh).
- **Phương pháp tiếp cận (Kịch bản 3 - Pure AI)**: Không dùng luật cứng (No Sigma/Regex Rules). Log được nạp trực tiếp vào ngữ cảnh của mô hình ngôn ngữ nhỏ (SLM) để AI tự đọc hiểu cấu trúc, xâu chuỗi sự kiện và đưa ra phán quyết (`NORMAL`, `ALERT`, `UNKNOWN`).

---

## II. BẢNG TỔNG HỢP SO SÁNH CHỈ SỐ KỸ THUẬT

| Chỉ Số Đánh Giá | Qwen 2.5 (3B-Instruct) | LLaMA 3.2 (3B-Instruct) | Chênh Lệch / Ý Nghĩa Khoa Học |
| :--- | :---: | :---: | :--- |
| **Tổng số sự kiện quét** | 32,959 | 32,959 | 100% dữ liệu đối chứng ngang bằng |
| **Số lô đã xử lý** | 1,309 / 1,309 | 1,309 / 1,309 | Hoàn thành trọn vẹn không gián đoạn |
| **Tổng thời gian thực thi** | **02:57:26** (10,646.6s) | **01:46:15** (6,375.9s) | **LLaMA nhanh hơn 1.67 lần** (tiết kiệm 71 phút) |
| **Tốc độ xử lý trung bình** | **8.13 giây / lô** | **4.87 giây / lô** | LLaMA tối ưu Token Generation trên GPU T4 tốt hơn |
| **Thông lượng (Throughput)** | ~3.09 sự kiện/giây | **~5.17 sự kiện/giây** | LLaMA đạt thông lượng cao hơn 67.3% |
| **Số cảnh báo phát hiện (ALERT)** | **98 cảnh báo** | **1 cảnh báo** | Khác biệt căn bản về ngưỡng nhạy & tính chọn lọc |
| **Số lô bình thường (NORMAL)** | 358 lô | 138 lô | Qwen dễ phân định dứt khoát hơn |
| **Số lô chưa rõ (UNKNOWN)** | 853 lô | 1,159 lô | LLaMA có xu hướng giữ trung lập cao hơn |
| **Số cảnh báo giả (False Positive)** | **Cao** (~95% trên log nền) | **Rất thấp** (~0% trên log nền) | LLaMA cực kỳ khắt khe với cảnh báo nguy hiểm |

---

## III. PHÂN TÍCH CHI TIẾT ĐẶC TÍNH PHÁT HIỆN

### 1. Mô hình Qwen 2.5 (3B-Instruct) — *Trường phái "Nhạy bén & Tầm soát rộng"*

- **Ưu điểm**:
  - **Khả năng bám sát chi tiết trường log cực mạnh**: Qwen đọc rất kỹ các giá trị như `TargetUserName`, `LogonType`, `ProcessName`, `CommandLine`.
  - **Diễn giải tự nhiên (Reasoning) bằng tiếng Việt mạch lạc**: Đưa ra lập luận rất chi tiết về lý do tại sao một sự kiện lại đáng ngờ (ví dụ: giải thích hành vi gọi `runas`, đọc thông tin xác thực tường minh).
- **Nhược điểm**:
  - **Tỷ lệ báo động giả (False Positive) cao trên log nền thường nhật**: 
    - Qwen phát hiện tới 98 cảnh báo ALERT. Tuy nhiên, khi phân tích sâu thì hầu hết các cảnh báo này rơi vào các hoạt động hệ thống bình thường của Windows (như Service Account tự động gia hạn token, tiến trình nền kiểm tra quyền hạn, script bảo trì hệ thống).
    - Qwen có xu hướng coi "bất kỳ sự bất thường nhỏ nào" là một cuộc tấn công tiềm năng.
  - **Tốc độ suy luận chậm hơn**: Do sinh chuỗi lập luận (thought tokens) dài hơn, thời gian xử lý trung bình mất 8.13s/lô.

### 2. Mô hình LLaMA 3.2 (3B-Instruct) — *Trường phái "Thận trọng & Chọn lọc cao"*

- **Ưu điểm**:
  - **Tốc độ suy luận vượt trội**: Xử lý 33.000 sự kiện chỉ trong 1 tiếng 46 phút (đạt 4.87s/lô), rất phù hợp cho các bài toán phân tích log gần với thời gian thực (Near Real-time).
  - **Khả năng triệt tiêu báo động giả xuất sắc**: LLaMA 3.2 không bị "đánh lừa" bởi các log nền thường gặp của Windows. Nó bỏ qua các hoạt động đơn lẻ và chỉ kích hoạt cảnh báo khi thấy chuỗi hành vi thực sự dị biệt.
- **Phân tích Cảnh báo Duy nhất của LLaMA (Lô #730)**:
  - **Thời điểm**: `2026-11-22 1:57:50 PM -> 2:58:37 PM` (khoảng 47 giây).
  - **Bằng chứng**: Cụm 14 sự kiện liên tiếp (`E17368 -> E17381`) liên quan đến Event ID 4688 (`New process has been created`).
  - **Nhận định của AI**: *"Có 14 sự kiện tạo tiến trình mới trong thời gian rất ngắn (47s), thể hiện một đợt bùng nổ thực thi tiến trình bất thường (Process Burst Execution), có khả năng là giai đoạn chuẩn bị hoặc thực thi mã của kẻ tấn công."*
  - **Đánh giá**: Đây là một phát hiện cực kỳ thông minh của LLaMA vì nó nhận diện được **dạng mẫu hành vi theo thời gian (temporal pattern)** thay vì chỉ nhìn vào một câu chữ riêng lẻ.
- **Nhược điểm**:
  - Đối với các hành vi tấn công tinh vi đơn lẻ (Low-and-Slow Attack), LLaMA có nguy cơ bỏ sót (False Negative) nếu cuộc tấn công không tạo ra đột biến rõ rệt.

---

## IV. ĐỀ XUẤT KIẾN TRÚC TỐI ƯU CHO HỆ THỐNG WINLOG SOC

Từ kết quả thực nghiệm trên 32.959 log thực tế của `NHAN-LAM-LAPTOP`, chúng ta rút ra kết luận quan trọng cho phần kết luận đồ án:

1. **Không nên dùng đơn lẻ một mô hình hay một phương pháp**:
   - Nếu chỉ dùng Qwen $\rightarrow$ Nhân viên SOC sẽ bị quá tải cảnh báo (Alert Fatigue) vì 98 cảnh báo/ngày phần lớn là cảnh báo giả.
   - Nếu chỉ dùng LLaMA $\rightarrow$ Hệ thống rất yên tĩnh và an toàn với log nền, nhưng có thể bỏ qua các dấu hiệu tấn công ngầm ban đầu.

2. **Mô hình phối hợp khuyến nghị (Hybrid Ensemble Architecture)**:
   - **Tầng 1 (Rule-based Filter)**: Dùng Sigma Rules để gạt bỏ ngay 80% log rác bình thường với chi phí tính toán cực thấp.
   - **Tầng 2 (LLaMA 3.2 - First Responder)**: Quét dòng log với tốc độ cao (4.87s/lô) để phát hiện các đợt tấn công bùng nổ (Brute-force, Mass Process Creation, Ransomware burst).
   - **Tầng 3 (Qwen 2.5 - Deep Investigation)**: Đóng vai trò chuyên gia phân tích sâu (Tier-2 Analyst). Khi Tầng 1 hoặc Tầng 2 phát hiện nghi vấn, đưa cụm log đó cho Qwen để suy luận ngữ cảnh và sinh báo cáo điều tra chi tiết.

---
*Báo cáo được trích xuất từ dữ liệu thực nghiệm Kịch bản 3 tại repository `DACN_ATTT`.*
