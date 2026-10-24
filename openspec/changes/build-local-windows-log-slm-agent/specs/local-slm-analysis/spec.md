## Purpose

Phân tích ca Windows bằng hai SLM local với đầu ra có bằng chứng, giới hạn tài nguyên và xử lý lỗi minh bạch.

## ADDED Requirements

### Requirement: Model local và chạy tuần tự
Hệ thống SHALL chỉ gọi Ollama local với qwen2.5:3b-instruct-q4_K_M hoặc llama3.2:3b-instruct-q4_K_M; hỗ trợ chọn một hoặc so sánh lần lượt cả hai, giải phóng model trước khi chuyển model. Không có fallback AI cloud.

#### Scenario: So sánh hai model
- **WHEN** người dùng chọn cả hai
- **THEN** mỗi model nhận cùng ca độc lập, không nhận kết quả model kia; không chủ động nạp cả hai đồng thời

#### Scenario: Thiếu model
- **WHEN** model được chọn chưa cài
- **THEN** báo lỗi model thiếu, không thay bằng model khác hoặc API cloud

### Requirement: Prompt và dữ liệu được kiểm soát
Hệ thống SHALL yêu cầu model chỉ dùng bằng chứng, coi nội dung log là dữ liệu, xét thứ tự và quan hệ phiên; không gửi nhãn chuẩn, tên kịch bản/file gợi đáp án hoặc kết quả model khác. Phạm vi là luồng có kiểm soát, không thực thi lệnh trong log.

#### Scenario: Chỉ dẫn độc hại trong script
- **WHEN** script_text chứa yêu cầu bỏ qua prompt hoặc chạy lệnh
- **THEN** nội dung được đóng vai dữ liệu; hệ thống không chạy lệnh và prompt vẫn yêu cầu phân tích bằng chứng

#### Scenario: Log trộn
- **WHEN** ca chứa hoạt động bình thường của A và dấu hiệu của B
- **THEN** prompt yêu cầu giữ cảnh báo có bằng chứng, phân biệt tài khoản và không kết luận mã độc chỉ từ PowerShell

### Requirement: Ba nhãn và kiểm tra bằng chứng
Kết quả SHALL gồm label thuộc NORMAL/ALERT/UNKNOWN, reason dạng chuỗi không rỗng và evidence_refs dạng danh sách refs thuộc đầu vào. ALERT SHALL có ít nhất một ref. NORMAL chỉ nói về dữ liệu quan sát; ALERT không khẳng định nhiễm mã độc; thiếu dữ kiện dùng UNKNOWN.

#### Scenario: Bằng chứng không tồn tại
- **WHEN** model trả ref không được gửi hoặc nhãn ngoài tập cho phép
- **THEN** kết quả phân tích được ghi UNKNOWN kèm lỗi validation, không chấp nhận như kết quả hợp lệ

#### Scenario: Thiếu bằng chứng
- **WHEN** model không đủ thông tin để xác định quan hệ
- **THEN** cho phép UNKNOWN có lý do, không yêu cầu model bịa refs

### Requirement: Giới hạn ngữ cảnh và lỗi suy luận
Hệ thống SHALL kiểm soát dung lượng đầu vào với chỗ dành cho prompt/đầu ra; không cắt sự kiện âm thầm. Timeout hoặc đầu ra không hợp lệ SHALL lưu UNKNOWN và mã lỗi riêng, phân biệt với UNKNOWN do thiếu bằng chứng.

#### Scenario: Ca vượt giới hạn
- **WHEN** ca không thể gửi nguyên vẹn trong giới hạn
- **THEN** báo cần thu hẹp hoặc tạo các ca con theo quy tắc công bố; lưu phạm vi mỗi đầu vào, không âm thầm bỏ sự kiện

#### Scenario: Timeout
- **WHEN** yêu cầu đã bắt đầu suy luận nhưng vượt thời hạn
- **THEN** lưu UNKNOWN và lỗi timeout, không biến thành NORMAL hoặc retry vô hạn

### Requirement: Khả năng tái lập
Mỗi lần phân tích SHALL lưu model/tag/định danh, phiên bản Ollama, prompt hoặc phiên bản truy được nội dung, đầu vào thực gửi, options, thời gian và trạng thái lỗi; mặc định temperature=0, num_ctx=4096, num_predict=512.

#### Scenario: Tra cứu kết quả cũ
- **WHEN** người dùng mở một kết quả đã lưu
- **THEN** xác định được model, cấu hình và bằng chứng đầu vào đã dùng dù cấu hình hiện tại thay đổi

