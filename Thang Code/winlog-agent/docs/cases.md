# Tạo ca phân tích

Sau khi nhập XML, lấy import_id từ báo cáo. Chạy tại winlog-agent:

```powershell
.\.venv\Scripts\python.exe -m app.cases IMPORT_ID --data-root data/local
```

Mỗi nhóm trở thành snapshot bất biến có case_id mới. Ca giữ danh sách event_refs theo giờ UTC rồi ref, cấu hình ghép, liên kết, cảnh báo chất lượng và group_id. Chưa phân tích nghĩa chưa có nhãn; bộ ghép không gán NORMAL/ALERT hay nhãn chuẩn.

4625 cùng lần nhập/máy/tài khoản/loại/nguồn được gom trong 60 giây neo tại bản ghi đầu. Đủ 5 lần chỉ là metadata ứng viên. Nhóm ít hơn vẫn giữ. Nguồn thiếu là một giá trị riêng, không đại diện mọi nguồn.

4624 được xét trong 300 giây sau thất bại cuối. Thành công đầu phù hợp đóng nhóm; nhiều khả năng không phân biệt được ghi ambiguous. Dùng TargetLogonId thành công để liên kết 4688; không lấy SubjectLogonId thất bại làm phiên. Nếu cả hai có SID thì đối chiếu SID; nếu thiếu một SID thì đối chiếu tên/domain, không hợp nhất SID khác nhau chỉ vì trùng tên.

4688 phải khớp máy/lần nhập/tài khoản/phiên và nằm trong 300 giây sau đăng nhập. 4104 cần một 4688 cùng PID, có quan hệ phiên hỗ trợ và còn trong cửa sổ đó. Lần tạo PID tiếp theo chặn việc gán script vào tiến trình trước; nhiều ứng viên hoặc thiếu thời gian giữ sự kiện chưa gán. Quan hệ được hỗ trợ bởi log quan sát được, không chứng minh không có khoảng trống thu thập.

## Chọn phạm vi và lô trộn

```powershell
.\.venv\Scripts\python.exe -m app.cases IMPORT_ID --data-root data/local --user 'TEN_VM\lab_demo' --start '2026-10-24T10:00:00+07:00' --end '2026-10-24T10:05:00+07:00'
.\.venv\Scripts\python.exe -m app.cases IMPORT_ID --data-root data/local --group-id GROUP_1 --group-id GROUP_2 --mixed
```

Bộ lọc **chọn nguyên nhóm có sự kiện khớp**, giữ các sự kiện liên quan ngoài điểm lọc và ghi lựa chọn này trong snapshot. Bộ ghép luôn xét toàn lần nhập trước khi lọc để không che mất bằng chứng PID tái sử dụng. Muốn giới hạn toàn bộ log trong khoảng hẹp, xuất và nhập một lần thu mới. Lô mixed chứa nhiều nhóm có group_id riêng, không trộn danh tính/phiên. Không có nhóm phù hợp thì danh sách ca rỗng; không tạo ca giả.

Ví dụ tái lập: `tests/test_cases.py` tạo dữ liệu tổng hợp gồm đăng nhập đúng + tiến trình, một thất bại tài khoản khác và tiến trình thiếu tài khoản. Kiểm thử tạo ba ca, trộn thành một snapshot vẫn giữ ba group_id, lọc tài khoản và đổi cấu hình không sửa ca cũ. `tests/test_correlation.py` kiểm tra biên, nguồn thiếu, phiên mơ hồ và tái sử dụng PID.

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_correlation.py tests/test_cases.py -q
```

Các ví dụ này không phải đo chất lượng model. Đối chiếu thủ công các quan hệ với XML trước khi dùng để gán nhãn đánh giá.
