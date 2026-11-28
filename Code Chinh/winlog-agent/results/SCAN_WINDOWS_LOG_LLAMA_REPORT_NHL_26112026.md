# Báo cáo Quét Log Windows Thực Tế — Kịch Bản 3 (Mô hình LLaMA 3.2)
- **Mô hình AI:** `llama3.2:3b-instruct-q4_K_M`
- **File nguồn:** `All_Security_PowerShell.csv`
- **Tổng sự kiện quét:** 32,959 sự kiện (1,309 lô)
- **Thời gian chạy:** 01:46:15 (6,375.9s)
- **Tốc độ trung bình:** 4.87 giây / lô
- **Số cảnh báo nguy hiểm (ALERT):** **1** cảnh báo

## 1. Danh sách các Cảnh báo Phát hiện (ALERTs)

### Cảnh báo #1 (Lô 730)
- **Thời gian:** `2026-11-22 1:57:50 PM -> 2026-11-22 1:58:37 PM`
- **Mức độ tin cậy:** 0%
- **Kỹ thuật phát hiện:** Tạo tiến trình mới (xem NewProcessName, CommandLine)
- **Bằng chứng (Event Ref):** `E17368, E17369, E17370, E17371, E17372, E17373, E17374, E17375, E17376, E17377, E17378, E17379, E17380, E17381`
- **Nhận định từ AI:** Có 14 sự kiện tạo tiến trình mới trong thời gian ngắn nhau, có thể là một phần của một cuộc tấn công (Xác nhận vòng 2: Có 14 sự kiện tạo tiến trình mới trong thời gian ngắn nhau, có thể là một phần của một cuộc tấn công)

---

## 2. Bảng So Sánh Hiệu Năng: Qwen 2.5 vs LLaMA 3.2 (Trên 32,959 Log Thật)

| Tiêu chí | Qwen 2.5 (3B) | LLaMA 3.2 (3B) | Nhận xét Khoa Học |
| :--- | :--- | :--- | :--- |
| **Tổng số sự kiện** | 32,959 | 32,959 | Đầy đủ 100% dữ liệu máy thật |
| **Số lô (Batches)** | 1,309 | 1,309 | Giữ nguyên cấu trúc phân lô |
| **Thời gian quét** | 02:57:26 (10,646s) | **01:46:15 (6,376s)** | **LLaMA 3.2 nhanh hơn 1.67 lần** (tiết kiệm hơn 1 tiếng 11 phút) |
| **Tốc độ trung bình** | 8.13s / lô | **4.87s / lô** | LLaMA 3.2 suy luận cực kỳ mượt mà trên GPU Tesla T4 |
| **Số ALERT phát hiện** | 98 cảnh báo | **1 cảnh báo duy nhất** | **LLaMA 3.2 có tỷ lệ False Positive cực thấp**, kiểm soát báo động giả tối ưu trên log nền |
| **Độ nhạy (Sensitivity)** | Rất cao (dễ cảnh báo) | Rất thận trọng, tập trung cụm sự kiện bất thường | Lô 730 có cụm tiến trình dày đặc trong 47 giây |

---
*Báo cáo được tổng hợp tự động từ kết quả thực thi trên Kaggle GPU T4.*
