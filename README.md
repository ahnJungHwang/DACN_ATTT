# Đồ Án Chuyên Ngành: An Toàn Thông Tin (DACN_ATTT)

## 📌 Đề Tài
**Xây dựng AI Agent hỗ trợ tự động hóa phân tích hành vi nguy hiểm dựa trên Log Windows.**

---

## 📂 Cấu Trúc Thư Mục

```text
Demo/
├── Code Chinh/   # Mã nguồn chính thức đã hoàn thiện và chạy ổn định
├── Lam Code/     # Khu vực phát triển và viết mã nguồn của Lâm
├── Thang Code/   # Khu vực phát triển và viết mã nguồn của Thắng
├── NhatKyTuan/   # Nhật ký làm việc hàng tuần (Cả 2 cùng cập nhật)
└── README.md     # Tài liệu và quy định làm việc của nhóm
```

---

## 📋 Quy Định Phân Chia & Quy Trình Làm Việc

### 1. Phân chia thư mục phát triển
- **Lâm**: Thực hiện viết code và thử nghiệm bên trong thư mục `Lam Code/`.
- **Thắng**: Thực hiện viết code và thử nghiệm bên trong thư mục `Thang Code/`.
- Không chỉnh sửa trực tiếp mã nguồn trong thư mục code của nhau hoặc `Code Chinh/` trong giai đoạn đang phát triển/thử nghiệm.

### 2. Quy định thư mục Nhật Ký Tuần (`NhatKyTuan/`)
- **Quyền chỉnh sửa**: Cả 2 thành viên (Lâm và Thắng) đều có quyền cập nhật và chỉnh sửa trong thư mục này.
- **Quy tắc đặt tên file**: 
  - Đặt tên theo cú pháp: `TuanX.md` (với `X` là số thứ tự tuần thực hiện).
  - Ví dụ: `Tuan1.md`, `Tuan2.md`, `Tuan3.md`, ..., cho đến `Tuan10.md` là kết thúc (tổng cộng 10 tuần).
- **Nội dung ghi nhận**: Báo cáo mục tiêu, công việc chi tiết của từng người (Lâm / Thắng), kết quả đạt được, khó khăn gặp phải và kế hoạch tuần tiếp theo.

### 3. Quy trình Git & Đẩy code (Workflow)
- **Nhánh làm việc**:
  - Lâm làm việc và đẩy code lên nhánh: `Lam-Code`.
  - Thắng làm việc và đẩy code lên nhánh: `Thang-Code`.
- **Hợp nhất mã nguồn (`Code Chinh` & `main`)**:
  - Chỉ khi code của từng thành viên đã chạy ổn định, kiểm thử đạt yêu cầu mới chuyển mã nguồn sang thư mục `Code Chinh/`.
  - Tiến hành tạo Pull Request hoặc Merge từ nhánh cá nhân vào nhánh `main`.
