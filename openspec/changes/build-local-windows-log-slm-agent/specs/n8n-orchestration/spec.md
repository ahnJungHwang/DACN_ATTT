## Purpose

Điều phối phân tích local từ n8n với workflow có thể nhập và có nhánh rõ ràng cho nhãn phân tích lẫn lỗi kỹ thuật.

## ADDED Requirements

### Requirement: Workflow import và kết nối local
Bàn giao SHALL có JSON workflow phù hợp phiên bản n8n ghi trong hướng dẫn, gồm Manual Trigger, Edit Fields case_id/model, HTTP Request POST /analyze và rẽ nhánh; Docker Desktop dùng host.docker.internal:8000 để gọi Python.

#### Scenario: Nhập workflow
- **WHEN** import JSON vào phiên bản được hỗ trợ và cấu hình ca/model
- **THEN** workflow không chứa node thiếu cấu hình bắt buộc chưa được hướng dẫn; gửi đúng payload tới dịch vụ local

#### Scenario: Chưa kiểm chứng thực thi
- **WHEN** môi trường không cho phép thử import/chạy
- **THEN** hướng dẫn ghi rõ phần chưa kiểm chứng, không tuyên bố đã chạy thành công

### Requirement: Phân nhánh đầy đủ
Workflow SHALL có đường xử lý riêng cho NORMAL, ALERT, UNKNOWN, lỗi HTTP và lỗi cấu trúc response; UNKNOWN có lỗi kỹ thuật SHALL được hiển thị rõ nguyên nhân.

#### Scenario: UNKNOWN
- **WHEN** API trả UNKNOWN hợp lệ
- **THEN** đi nhánh UNKNOWN, không rơi vào nhánh an toàn

#### Scenario: Response lỗi
- **WHEN** HTTP thành công nhưng thiếu label hoặc label không hợp lệ
- **THEN** đi nhánh lỗi cấu trúc, không mặc định NORMAL

#### Scenario: ALERT
- **WHEN** API trả ALERT hợp lệ
- **THEN** hiển thị cảnh báo cùng result_id và bằng chứng, không tự phản ứng lên hệ điều hành

### Requirement: Timeout retry và riêng tư
Workflow SHALL có timeout cấu hình phù hợp CPU, không retry vô hạn; nếu gửi lại phải giữ định danh yêu cầu. Không hard-code bí mật hoặc gửi dữ liệu/cảnh báo tới dịch vụ ngoài.

#### Scenario: Hết thời gian chờ
- **WHEN** HTTP Request timeout
- **THEN** nhánh lỗi giải thích trạng thái chưa biết và cách tra cứu yêu cầu; không tự tạo yêu cầu mới liên tục

#### Scenario: Kiểm tra bản bàn giao
- **WHEN** người dùng xem JSON và hướng dẫn
- **THEN** có cách import, chạy, xem ba nhãn và xử lý lỗi, không có credential thật hoặc node gửi ra ngoài

