## Purpose

So sánh khả năng phát hiện và chi phí chạy hai SLM bằng dữ liệu lab có nhãn, tái lập được và không rò rỉ đáp án.

## ADDED Requirements

### Requirement: Bộ dữ liệu và nhãn chuẩn
Bộ đánh giá SHALL hướng tới 50 ca gồm 10 ca phát triển và 40 ca đánh giá với bốn nhóm 10 ca: bình thường, dò mật khẩu, trộn cùng phiên, trộn khác phiên/tài khoản. Nhãn SHALL đối chiếu thao tác và log; tách theo lần thực nghiệm độc lập.

#### Scenario: Rò rỉ phiên
- **WHEN** hai ca chồng lặp của một phiên bị chia vào phát triển và đánh giá
- **THEN** kiểm tra tập dữ liệu báo lỗi và không công bố đánh giá độc lập

#### Scenario: Chưa đủ dữ liệu
- **WHEN** chỉ có 8 ca thật
- **THEN** báo số lượng và nhóm còn thiếu, không tạo ca hoặc số đo giả để đủ 50

### Requirement: So sánh công bằng
Hai model SHALL nhận cùng tập, prompt, schema và options trong mỗi chế độ đọc riêng lẻ/đọc nhóm; chạy tuần tự. Payload SHALL loại nhãn chuẩn, tên gợi đáp án và kết quả model kia.

#### Scenario: Chạy đối chứng
- **WHEN** cả hai model được đánh giá
- **THEN** mỗi ca có kết quả tách theo model/chế độ và metadata so sánh được

#### Scenario: Cấu hình khác nhau
- **WHEN** options giữa hai model khác trong cùng phép so sánh
- **THEN** báo cấu hình không đồng nhất, không công bố như đối chứng cùng điều kiện

### Requirement: Tổng hợp nhãn đọc riêng lẻ
Nhãn lô SHALL là ALERT nếu bất kỳ sự kiện ra ALERT; nếu không ALERT nhưng có UNKNOWN/lỗi thì UNKNOWN; chỉ NORMAL khi mọi sự kiện hợp lệ đều NORMAL. Lô rỗng SHALL không được coi là NORMAL.

#### Scenario: ALERT trong nhiều NORMAL
- **WHEN** một sự kiện ALERT và nhiều sự kiện NORMAL
- **THEN** nhãn lô là ALERT

#### Scenario: UNKNOWN không ALERT
- **WHEN** một sự kiện UNKNOWN và các sự kiện khác NORMAL
- **THEN** nhãn lô là UNKNOWN

### Requirement: Chỉ số phát hiện minh bạch
Báo cáo SHALL tách model/chế độ, nêu TP/FP/FN và Precision/Recall/F1 của ALERT; ca tấn công không ra ALERT tính FN, UNKNOWN không tính đúng. Báo riêng cảnh báo nhầm, UNKNOWN/lỗi, JSON hợp lệ và gán nhầm tài khoản/phiên.

#### Scenario: UNKNOWN trên ca tấn công
- **WHEN** nhãn chuẩn là ALERT nhưng dự đoán UNKNOWN
- **THEN** tăng FN và UNKNOWN, không ghi nhận đúng

#### Scenario: Không có dự đoán ALERT
- **WHEN** TP+FP bằng không
- **THEN** Precision ghi không xác định kèm mẫu số; Recall=TP/(TP+FN), F1=2TP/(2TP+FP+FN) nếu mẫu số khác không; không tự ghi 100%

#### Scenario: Chấm gán nhầm phiên
- **WHEN** có nhãn đối chiếu tài khoản/phiên và bằng chứng
- **THEN** báo tử số, mẫu số và quy trình chấm; nếu chưa chấm thì ghi chưa có dữ liệu

### Requirement: Đo thời gian tài nguyên và nguồn gốc
Đánh giá SHALL chạy lặp 3 lần lấy trung vị thời gian sau nạp, ghi riêng lần nạp đầu và RAM/VRAM nếu đo được; lưu cấu hình máy, Ollama, định danh model, prompt/options, thời điểm và tập dữ liệu.

#### Scenario: Không đo được GPU
- **WHEN** máy không có GPU hoặc công cụ đo không sẵn sàng
- **THEN** VRAM ghi không có dữ liệu cùng lý do, không ghi số 0 như phép đo

#### Scenario: Lần chạy lỗi
- **WHEN** một trong ba lần timeout
- **THEN** giữ lỗi và số mẫu thành công, không báo trung vị đủ ba lần; số liệu nạp và suy luận không bị trộn

### Requirement: Báo cáo và chọn model
Hệ thống SHALL xuất kết quả chi tiết JSONL và comparison.csv, bảo toàn UNKNOWN/lỗi; đề xuất model mặc định dựa trên phát hiện và tài nguyên đo được, nêu giới hạn bộ dữ liệu. Không suy ra độ đúng chỉ từ JSON hợp lệ.

#### Scenario: Hoàn tất đánh giá
- **WHEN** có số liệu thật cho hai model
- **THEN** báo cáo giải thích đánh đổi chất lượng/tài nguyên và không khẳng định model thắng ở mọi tình huống

#### Scenario: Kết quả chưa đủ
- **WHEN** một model chưa chạy xong
- **THEN** báo cáo ghi chưa đủ cơ sở so sánh thay vì tuyên bố model còn lại tốt nhất

