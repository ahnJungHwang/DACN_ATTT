## Purpose

Chuyển XML Windows thành dữ liệu sự kiện thống nhất, bảo toàn nguồn gốc và thông tin còn thiếu để phân tích và đối chiếu.

## ADDED Requirements

### Requirement: Đọc XML an toàn
Hệ thống SHALL nhận XML Events/Event có namespace, hỗ trợ UTF-8 có/không BOM và UTF-16 có BOM, áp dụng giới hạn kích thước công bố; không tải external entity, truy cập mạng hoặc thực thi nội dung log.

#### Scenario: XML hợp lệ
- **WHEN** hai file được mã hóa theo định dạng hỗ trợ và có namespace Windows
- **THEN** hệ thống đọc trường XML trực tiếp mà không phụ thuộc Message đã bản địa hóa

#### Scenario: XML không an toàn hoặc lỗi
- **WHEN** file chứa DTD/entity ngoài, XML hỏng hoặc vượt giới hạn
- **THEN** hệ thống từ chối file với lý do cụ thể, không công bố lần nhập hoàn chỉnh

### Requirement: Schema sự kiện thống nhất
Hệ thống SHALL xuất JSONL gồm event_ref, time, host, channel, event_id, event_record_id, user, logon_type, source_address, logon_id, process_id, command_line, script_text. Trường thiếu SHALL là null; thời gian hợp lệ chuẩn hóa UTC, giữ giá trị gốc.

#### Scenario: Sự kiện thiếu trường
- **WHEN** 4625 không có command_line hoặc địa chỉ nguồn hữu ích
- **THEN** trường tương ứng là null, không suy diễn IP hoặc script

#### Scenario: Thời gian không xác định
- **WHEN** bản ghi có thời gian không đọc được hoặc thiếu múi giờ
- **THEN** bản ghi được gắn lỗi chất lượng, không tự gán múi giờ rồi đưa vào ghép thời gian

### Requirement: Truy xuất bằng chứng gốc
Mỗi event_ref SHALL xác định được file nhập và sự kiện XML gốc; hệ thống SHALL giữ bản gốc và tránh va chạm giữa máy, channel hoặc lần thu.

#### Scenario: Trùng EventRecordID
- **WHEN** hai nguồn có cùng EventRecordID
- **THEN** chúng có event_ref khác nhau và mở đúng XML tương ứng

### Requirement: Giữ vai trò tài khoản và tiến trình
Hệ thống SHALL giữ các trường Subject/Target gốc, xác định user theo loại sự kiện, phân biệt NewProcessId và PID tiến trình tạo trong 4688; chuẩn hóa PID để so sánh mà không mất biểu diễn gốc.

#### Scenario: Tiến trình chạy khác người tạo
- **WHEN** 4688 có Creator Subject và Target Subject khác nhau
- **THEN** hệ thống lưu cả hai vai trò, không gán tài khoản tạo làm tài khoản chạy chỉ vì trường xuất hiện trước

#### Scenario: PID khác cơ số
- **WHEN** hai bản ghi dùng hex và decimal cho cùng PID
- **THEN** giá trị so sánh bằng nhau, nguồn gốc vẫn được giữ

### Requirement: Ghép mảnh script block
Hệ thống SHALL ghép 4104 theo ScriptBlockId trong ngữ cảnh máy/tiến trình và thứ tự mảnh; giữ refs từng mảnh và đánh dấu thiếu hoặc xung đột.

#### Scenario: Thiếu mảnh
- **WHEN** có mảnh 1 và 3 trong tổng 3 mảnh
- **THEN** nội dung không được ghi là script đầy đủ; báo thiếu mảnh 2

#### Scenario: Đủ mảnh
- **WHEN** các mảnh đầy đủ đến không đúng thứ tự
- **THEN** script được dựng đúng thứ tự và truy được mọi mảnh gốc

