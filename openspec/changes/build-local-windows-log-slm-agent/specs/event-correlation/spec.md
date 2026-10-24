## Purpose

Tạo các ca phân tích từ quan hệ sự kiện có bằng chứng, tránh gán nhầm tài khoản hoặc phiên khi dữ liệu bị trộn.

## ADDED Requirements

### Requirement: Gom đăng nhập thất bại
Hệ thống SHALL gom 4625 theo máy, tài khoản có domain khi có, loại đăng nhập, nguồn khi có trong cửa sổ mặc định 60 giây; ngưỡng số lần và cửa sổ SHALL cấu hình và được lưu cùng ca.

#### Scenario: Hai tài khoản gần nhau
- **WHEN** A và B cùng thất bại trong 60 giây
- **THEN** hệ thống tạo nhóm riêng, không cộng số lần của hai tài khoản

#### Scenario: Nguồn bị thiếu
- **WHEN** một bản ghi không có nguồn và có nhiều nhóm nguồn khả dĩ
- **THEN** hệ thống ghi liên kết chưa xác định thay vì hợp nhất mọi nhóm

### Requirement: Liên kết đăng nhập thành công
Hệ thống SHALL tìm 4624 tương thích trong tối đa 5 phút sau thất bại cuối của nhóm, xét máy, tài khoản, loại đăng nhập và nguồn nếu có. Ngưỡng SHALL cấu hình được; không dùng SubjectLogonId của 4625 làm phiên thành công.

#### Scenario: Thành công liên quan
- **WHEN** 4624 phù hợp xuất hiện trong cửa sổ
- **THEN** ca giữ refs thất bại và thành công, dùng TargetLogonId của 4624 cho đối chiếu phiên

#### Scenario: Thành công ngoài cửa sổ
- **WHEN** 4624 xuất hiện sau giới hạn cấu hình
- **THEN** không liên kết tự động như thành công của nhóm

### Requirement: Liên kết hoạt động sau đăng nhập
Hệ thống SHALL đối chiếu 4688 theo tài khoản chạy, mã phiên phù hợp, máy và thời gian; 4104 theo máy, PID và thời gian. PID tái sử dụng hoặc nhiều ứng viên SHALL được ghi nhận là mơ hồ.

#### Scenario: PID được tái sử dụng
- **WHEN** hai tiến trình khác phiên có cùng PID và không đủ dữ liệu phân biệt
- **THEN** không gán chắc chắn script cho một phiên

#### Scenario: Khác phiên
- **WHEN** log của A nằm gần chuỗi đăng nhập của B
- **THEN** hoạt động A không được làm bằng chứng hành vi sau đăng nhập của B

### Requirement: Ca và chất lượng bằng chứng
Hệ thống SHALL giữ thứ tự thời gian, event_refs và cảnh báo chất lượng; giữ các ca bình thường/thiếu dữ kiện cho phân tích, không chỉ tạo ca đạt ngưỡng đáng ngờ. Gom nhóm SHALL không tự tạo nhãn chuẩn hay thay thế kết luận SLM.

#### Scenario: Mẫu đối chứng
- **WHEN** chỉ có đăng nhập đúng và PowerShell bình thường
- **THEN** vẫn tạo được ca phân tích mà không gắn sẵn đáp án cho model

#### Scenario: Quan hệ không đủ
- **WHEN** thiếu trường phiên cần thiết
- **THEN** ca nêu dữ kiện thiếu và quan hệ chưa xác định

