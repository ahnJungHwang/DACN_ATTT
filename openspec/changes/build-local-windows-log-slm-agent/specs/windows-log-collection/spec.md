## Purpose

Thu thập bằng chứng từ máy ảo Windows 10 theo từng lần thực nghiệm, giữ nguyên nội dung và báo rõ mức độ đầy đủ của dữ liệu.

## ADDED Requirements

### Requirement: Hướng dẫn môi trường lab
Tài liệu SHALL hướng dẫn bằng tiếng Việt, phân biệt máy ảo và máy thật, nêu phiên bản Windows hỗ trợ công cụ cấu hình, bật Audit Logon Success/Failure, Audit Process Creation Success, command line và Script Block Logging cho Windows PowerShell 5.1.

#### Scenario: Cấu hình máy ảo
- **WHEN** người dùng chuẩn bị VM Windows 10
- **THEN** hướng dẫn có bước cập nhật policy, mở phiên PowerShell mới, kiểm tra bốn Event ID và ghi thời gian, múi giờ, tài khoản, thao tác; yêu cầu kiểm tra chính sách khóa tài khoản trước khi thử

#### Scenario: Thiếu công cụ policy
- **WHEN** Windows không có gpedit.msc hoặc secpol.msc
- **THEN** hướng dẫn nêu cách cấu hình tương đương được hỗ trợ hoặc yêu cầu edition phù hợp; không khẳng định đã bật audit

### Requirement: Xuất sự kiện theo khoảng thời gian
Công cụ SHALL chạy trên Windows PowerShell 5.1, xuất Security 4624/4625/4688 và PowerShell Operational 4104 thành hai XML gốc Events/Event trong thư mục riêng từng lần; không xóa log hoặc cắt số bản ghi âm thầm.

#### Scenario: Xuất đủ khoảng thu
- **WHEN** người dùng cung cấp thời điểm bắt đầu và kết thúc hợp lệ
- **THEN** tất cả sự kiện phù hợp trong khoảng được xuất; báo đường dẫn, khoảng thu và số bản ghi từng nguồn

#### Scenario: Khoảng thu không hợp lệ
- **WHEN** thời điểm bắt đầu lớn hơn kết thúc
- **THEN** công cụ báo lỗi đầu vào và không báo xuất thành công

### Requirement: Báo trạng thái thu thập
Công cụ SHALL phân biệt thành công, không có sự kiện, thiếu quyền và lỗi đọc/ghi; dữ liệu một phần không được báo là lần thu đầy đủ.

#### Scenario: Một nguồn không đọc được
- **WHEN** Security xuất được nhưng nguồn PowerShell lỗi quyền
- **THEN** giữ phần đã xuất, báo nguồn lỗi và đánh dấu lần thu không đầy đủ

#### Scenario: Không có sự kiện
- **WHEN** truy vấn hợp lệ không có bản ghi phù hợp
- **THEN** báo số lượng bằng không, không tạo bằng chứng giả và không coi đây là ca NORMAL

