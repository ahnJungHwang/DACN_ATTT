# Demo thu log trong VM

Chạy trên VM Windows thử nghiệm đã chụp snapshot, bằng **Windows PowerShell 5.1 64-bit, quyền Administrator**. Copy cả thư mục scripts, gồm Collection.psm1; không chỉ copy run_demo.ps1.

## Kịch bản mới

1. Kiểm tra quyền và từ chối nếu lab_demo đã tồn tại; không thay mật khẩu hoặc xóa tài khoản có sẵn.
2. Bật audit Logon/Process Creation bằng GUID và ScriptBlockLogging; kiểm tra mã thoát từng lệnh.
3. Tạo lab_demo với mật khẩu ngẫu nhiên, chỉ thêm vào nhóm Users.
4. Thử sai mật khẩu 5 lần bằng Start-Process -Credential. Chỉ ghi nhận thất bại mật khẩu khi Windows trả mã 1326. Account lockout, thiếu quyền đăng nhập hoặc lỗi khác sẽ dừng kịch bản, không giả vờ đã sinh đủ log.
5. Dùng credential đúng để mở một PowerShell cha dưới lab_demo. Kiểm tra SID thực tế của tiến trình; whoami /all và /logonid chạy trong ngữ cảnh này, không chạy trong phiên Admin điều phối.
6. Kiểm tra exit code và marker hoàn thành trong stdout; lỗi được ghi stderr và nhật ký.
7. Xuất XML/manifest/hash qua Collection.psm1 trong khoảng thời gian đóng; giữ bằng chứng kể cả khi kịch bản lỗi.
8. Chỉ xóa tài khoản do lượt chạy tạo, sau khi kiểm SID vẫn khớp.

Demo không còn tạo hacker, thêm Administrators, tải/chạy payload bên ngoài hoặc ghi Run key. Đó không phải hoạt động có thể coi là tiếp nối hợp lệ của user thường lab_demo. Kịch bản hiện tập trung vào dò mật khẩu → đăng nhập đúng → hoạt động cùng ngữ cảnh tài khoản; không đại diện cho một chuỗi leo thang quyền đầy đủ.

## Chạy

Từ thư mục scripts/lab trên VM:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\run_demo.ps1 -OutputRoot C:\demo
```

Mỗi lượt tạo C:\demo\scenario-UUID, gồm:
- scenario-journal.json: trạng thái, thời gian, SID, mã lỗi, PID và đường dẫn lần xuất.
- activity.stdout.txt / activity.stderr.txt: bằng chứng thực thi và lỗi của tiến trình lab_demo.
- Thư mục con lần thu: security.xml, powershell.xml và manifest.json có hash.

Mã thoát: 0 = thực thi đã kiểm tra và xuất không partial; 2 = thực thi đạt nhưng xuất partial; 1 = lỗi thực thi/xuất/dọn dẹp. Không xóa dữ liệu partial.

## Xác nhận log thật

Exit code 0 không chứng minh audit ghi đủ. Trạng thái vẫn là execution_completed_pending_log_review và log_correlation_verified=false. Trước khi gán nhãn:
- Kiểm đủ 5 sự kiện 4625 của lab_demo trong thời gian thử; nếu VM khóa tài khoản, khôi phục snapshot/chính sách lab phù hợp, không tắt chính sách máy thật.
- Đối chiếu Target SID của 4624 với SID nhật ký.
- Đối chiếu Logon ID của tiến trình 4688 với phiên đăng nhập, và PID của 4104; không ghép theo tên user đơn thuần.
- Kiểm stdout whoami /logonid và nhật ký thao tác; không suy ra thành công chỉ từ dòng thông báo.
- Chạy app.verify_collection trên thư mục có manifest để kiểm hash/đếm/thời gian.

Chính sách audit thay đổi được giữ lại trong VM; dùng snapshot để hoàn nguyên. Tài khoản mới không thay thế việc kiểm chứng audit policy và Secondary Logon của VM.

## Phạm vi kiểm thử bản sửa

Bộ luật đã có test lệnh net/net1, đuôi .exe, đường dẫn có dấu ngoặc kép, khoảng trắng/tab và cmd /c; có test chống khớp nhầm echo, internet.exe và /address. Parser chỉ hỗ trợ lệnh trực tiếp hoặc một lớp cmd /c, /k (tùy chọn /d), không phải trình phân tích mọi cú pháp shell.

Script demo đã được kiểm tra cú pháp PowerShell và helper kiểm mã thoát. Chưa chạy thao tác tạo tài khoản/đăng nhập trên VM ở lượt sửa này; cần thực hiện luồng trên trước khi chốt nghiệm thu log.

Kiểm thử bổ sung: `tests/lab-demo.tests.ps1` mô phỏng cmdlet tài khoản, xác nhận không xóa tài khoản không thuộc lượt chạy, từ chối SID đã đổi và chỉ xóa SID sở hữu. Helper xuất log được kiểm tra truyền nguyên Start/End tới `Export-LabLogs`; `tests/collection.tests.ps1` kiểm tra exporter dùng khoảng đóng, hash và trạng thái partial bằng sự kiện tổng hợp. Các kiểm thử không tạo/xóa tài khoản thật và không thay audit policy máy chạy test.
