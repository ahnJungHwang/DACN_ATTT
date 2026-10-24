## Purpose

Cung cấp hợp đồng API local cho giao diện và n8n để truy cập ca, chạy phân tích và lấy kết quả theo định danh.

## ADDED Requirements

### Requirement: Trạng thái và danh sách
Dịch vụ SHALL cung cấp GET /health, /models, /cases và /cases/{case_id}; phân biệt trạng thái API với khả năng kết nối Ollama, model được phép và model đã cài.

#### Scenario: Ollama dừng
- **WHEN** API vẫn chạy nhưng Ollama không truy cập được
- **THEN** health/models thể hiện trạng thái suy giảm hoặc lỗi phụ thuộc, không báo AI sẵn sàng

#### Scenario: Ca không tồn tại
- **WHEN** truy vấn case_id chưa đăng ký
- **THEN** trả 404 với lỗi có cấu trúc

### Requirement: Yêu cầu và kết quả phân tích
POST /analyze SHALL nhận case_id và model hợp lệ; lần phân tích hoàn tất trả result_id, label, reason, evidence_refs và thông tin lỗi nếu có. GET /results/{result_id} SHALL truy xuất đúng kết quả đã lưu.

#### Scenario: Phân tích thành công
- **WHEN** ca và model sẵn sàng
- **THEN** kết quả có định danh và truy lại được qua endpoint results

#### Scenario: Lỗi trong suy luận
- **WHEN** lần phân tích đã tạo kết quả UNKNOWN do timeout
- **THEN** response và bản lưu giữ mã lỗi kỹ thuật, khác UNKNOWN thiếu bằng chứng

### Requirement: Đầu vào và lỗi dịch vụ
Dịch vụ SHALL từ chối model ngoài danh sách, đường dẫn tùy ý và request sai schema; phân biệt lỗi 4xx với lỗi phụ thuộc 5xx trước khi tạo kết quả. Không dùng phản hồi lỗi như nhãn NORMAL.

#### Scenario: Đọc file tùy ý
- **WHEN** request truyền case_id chứa đường dẫn thay vì mã đã đăng ký
- **THEN** request bị từ chối, không mở file theo đường dẫn đó

#### Scenario: Model không sẵn sàng
- **WHEN** Ollama không truy cập được trước khi bắt đầu phân tích
- **THEN** trả lỗi phụ thuộc có cấu trúc để n8n xử lý lỗi HTTP

### Requirement: Tránh chạy trùng và giới hạn truy cập
Dịch vụ SHALL hỗ trợ định danh yêu cầu để cùng một lần gửi lại không tạo nhiều phân tích; cùng định danh với payload khác SHALL bị từ chối. Hướng dẫn SHALL giới hạn truy cập máy thật/Docker và không công khai dịch vụ.

#### Scenario: Gửi lại cùng yêu cầu
- **WHEN** client gửi lại cùng định danh và payload
- **THEN** nhận trạng thái/kết quả của yêu cầu đó, không phát sinh suy luận trùng

#### Scenario: Định danh xung đột
- **WHEN** cùng định danh nhưng model hoặc ca khác
- **THEN** trả lỗi xung đột thay vì tái sử dụng kết quả sai

