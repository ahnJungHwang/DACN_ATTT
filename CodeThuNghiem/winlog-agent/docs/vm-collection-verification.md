# Kiểm chứng lần thu VMware Windows 10 — 2026-10-27 (task 3.4)

Lần thu thật đầu tiên trên VM `D:\machine\win10` (ComputerName `WIN10`, múi giờ SE Asia Standard Time, +07:00). Người dùng tự đăng nhập VM, bật policy, làm kịch bản và chạy script; Claude chỉ bật VM bằng vmrun, sửa script và kiểm tra file trên máy thật. Thư mục lần thu nằm trong `Thang Code/log-test/` (bị Git ignore), không sửa hai XML cũ ngày 2026-10-24 trong cùng thư mục.

## Lần thu được dùng

`log-test/20261027-080146-a36f29e9-3c80-40fe-8e9a-4fdb144da2b8`, run_id `a36f29e9-3c80-40fe-8e9a-4fdb144da2b8`.

- Khoảng thu đóng: 2026-10-27T07:21:09.0984461+07:00 → 07:39:22.7923166+07:00. `$start` được đặt lại theo 4625 RecordId 7678 trừ 1 phút vì biến trong phiên PowerShell bị mất; `$end` là giờ người dùng ghi sau khi xong kịch bản.
- Manifest `complete`. Security `success`, 73 sự kiện (4624: 3, 4625: 6, 4688: 64). PowerShell/Operational `success`, 84 sự kiện 4104.
- SHA256 trong manifest được tính trong VM và khớp với file trên máy thật:
  - security.xml `82CE6AF65C5D66F8DF892BD90B6142AC3620E057203461264E1C481CF3A5EB6E`
  - powershell.xml `29D2A22312C0A3717763327034688A67F1E48CB370A22D4E42F5ECE40C6751DF`
- `app.verify_collection`: mã thoát 0, `integrity_ok=true`, `collection_complete=true`, `ready_for_manual_review=true`, không có warning.
- Parser của ứng dụng (`app.xml_logs.read_xml`, cấu hình mặc định) đọc được cả hai file.

## Đối chiếu nội dung với kịch bản

- 6 × 4625 tài khoản `WIN10\lab_demo`, LogonType 2, SubStatus `0xC000006A` (sai mật khẩu), 07:22:09 → 07:22:50, RecordId 7678–7690. 6 lần trong 41 giây, dưới ngưỡng khóa.
- 4624 `lab_demo` lúc 07:23:04, TargetLogonId `0x762f8a`. 4688 cùng phiên: `powershell.exe -NoProfile` (target `0x762f8a`), `whoami.exe` × 2, `notepad.exe` với SubjectLogonId `0x762f8a`.
- Có thêm 4624 `lab_demo` lúc 07:24:11, phiên `0x76bb32`, chỉ mở powershell/conhost: lần `runas` thứ hai. Cần ghi vào nhật ký thao tác.
- 4104 của SID `...-1002` (lab_demo) chứa `whoami`, `Get-Date`, `Get-Process`, `Start-Process notepad.exe`. 4104 của SID `...-1001` (tài khoản quản trị) là lệnh `runas` và các thao tác thu log trong cùng khoảng.
- 4624 của SYSTEM lúc 07:37:36 (LogonType 5) là hoạt động nền của Windows.

Đối chiếu trên xác nhận lần thu có đủ bằng chứng cho kịch bản; chưa phải nhãn chuẩn. Gán nhãn và đối chiếu kết quả model thuộc task 11.1/11.4.

## Các lần xuất lỗi được giữ lại

- `20261027-074832-57f600d2…`: partial. Security `read_error` do cửa sổ PowerShell không có quyền admin; PowerShell `no_events`.
- `20261027-075557-c81eae84…`: `complete` nhưng cả hai nguồn 0 sự kiện do lỗi script: `Collection.psm1` truyền mốc UTC cho Get-WinEvent, PowerShell 5.1 đọc lại như giờ máy nên khoảng lọc lùi 7 giờ. Đã sửa ngày 2026-10-27 và thêm kiểm tra trong `tests/collection.tests.ps1`: bản cũ không qua test mới, bản mới đạt. Trên máy thật, cùng khoảng 3 phút có 4104, bản cũ trả 0 và bản mới trả 1.

Không dùng hai thư mục này làm bằng chứng.

## Giới hạn và việc còn thiếu

- Chưa ghi edition/build Windows của VM và kết quả `auditpol` vào nhật ký; cần bổ sung vào nhật ký lần thu (`lab-journal-template.md`).
- 4104 của tài khoản quản trị ghi lại nguyên dòng lệnh đã gõ, kể cả chuỗi gõ thêm sau lệnh `runas` (RecordId 307–322). Coi powershell.xml là dữ liệu nhạy cảm, chỉ lưu local; nếu chuỗi nào trong đó là mật khẩu thật, đổi mật khẩu tài khoản lab.
- Kiểm tra hash/manifest không chứng minh nguồn gốc VM; nguồn gốc dựa trên việc người dùng thực hiện và nhật ký thao tác.
