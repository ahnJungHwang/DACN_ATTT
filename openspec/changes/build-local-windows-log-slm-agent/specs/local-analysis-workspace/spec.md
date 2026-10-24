## Purpose

Cho người dùng thao tác phân tích tại máy thật và kiểm chứng kết luận qua dữ liệu gốc trong một giao diện local.

## ADDED Requirements

### Requirement: Nhập và xem chất lượng dữ liệu
Giao diện SHALL cho nhập XML, xem số sự kiện theo ID, khoảng thời gian và lỗi/thiếu trường; cho biết lần nhập đầy đủ hay một phần trước khi phân tích.

#### Scenario: Nguồn PowerShell thiếu
- **WHEN** người dùng nhập Security nhưng thiếu PowerShell
- **THEN** giao diện nêu nguồn thiếu, không hiển thị đã đủ bốn loại sự kiện

#### Scenario: File lỗi
- **WHEN** file XML bị từ chối
- **THEN** hiển thị lỗi cụ thể, không tạo ca giả để thay thế

### Requirement: Chọn ca model và trạng thái
Giao diện SHALL cho xem ca, chọn một model hoặc hai model chạy lần lượt, bắt đầu phân tích và phân biệt chưa chạy, đang chạy, hoàn tất, lỗi; không hiển thị nhãn trước khi có kết quả.

#### Scenario: Chưa phân tích
- **WHEN** ca vừa tạo
- **THEN** giao diện ghi chưa phân tích, không hiển thị NORMAL mặc định

#### Scenario: So sánh
- **WHEN** hai model hoàn tất cùng một ca
- **THEN** kết quả được tách theo model và lần chạy, không trộn lý do hoặc evidence_refs

### Requirement: Xem bằng chứng và xuất kết quả
Giao diện SHALL hiển thị nhãn, reason, thời gian, lỗi và bằng chứng có thể mở đúng sự kiện XML gốc; hỗ trợ xuất JSONL/CSV và phân biệt dữ liệu mẫu với thật.

#### Scenario: Mở bằng chứng
- **WHEN** người dùng chọn event_ref trong kết quả
- **THEN** hiển thị đúng sự kiện nguồn và thông tin truy xuất

#### Scenario: Xuất CSV
- **WHEN** nội dung log bắt đầu bằng ký tự công thức bảng tính
- **THEN** bản CSV xử lý an toàn để không kích hoạt công thức khi mở; bản JSONL giữ nguyên dữ liệu

#### Scenario: Dữ liệu mẫu
- **WHEN** người dùng xem ca minh họa
- **THEN** giao diện đánh dấu mẫu, không đưa số liệu mẫu vào báo cáo thực nghiệm thật

### Requirement: Hiển thị dữ liệu không thực thi
Giao diện SHALL hiển thị nội dung log dưới dạng văn bản an toàn, không thực thi HTML/script/lệnh chứa trong log; mọi xử lý và lưu trữ log SHALL nằm local.

#### Scenario: Log chứa HTML
- **WHEN** script_text chứa thẻ script hoặc markup
- **THEN** giao diện hiển thị như văn bản, không chạy script trong trình duyệt

