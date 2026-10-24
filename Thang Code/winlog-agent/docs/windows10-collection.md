# Thu log Windows 10 cho đồ án

Các bước bật audit và sinh sự kiện dưới đây chạy **trong máy ảo Windows 10 lab**. Máy thật chỉ nhận bản sao XML và chạy ứng dụng/Ollama/n8n. Chưa có bằng chứng script đã chạy trên VM của Thắng; kiểm thử hiện tại là dữ liệu tổng hợp trên Windows PowerShell 5.1 máy thật.

## 1. Ghi môi trường trước khi thu

Trong VM, mở Windows PowerShell bằng Run as administrator (powershell.exe, không phải pwsh.exe), chạy:

```powershell
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber
$PSVersionTable.PSVersion
hostname
whoami
Get-Date -Format o
Get-TimeZone
net accounts
```

Ghi kết quả vào nhật ký thực nghiệm, không ghi mật khẩu. Dùng Windows 10 Pro/Enterprise có `gpedit.msc` và `secpol.msc`. Nếu thiếu các công cụ này, chuyển sang VM edition phù hợp trước khi theo hướng dẫn, không cài tiện ích giả lập policy editor.

Đọc Lockout threshold/duration/reset window trong `net accounts` hoặc Account Policies → Account Lockout Policy ở `secpol.msc`. Chỉ thử tài khoản lab được phép; không lặp sai mật khẩu đến mức khóa tài khoản đang dùng. Không tự đổi chính sách khóa để có đủ số log. Nếu ngưỡng không cho phép kịch bản, ghi lại và điều chỉnh kế hoạch thực nghiệm với người phụ trách.

## 2. Bật ghi nhận bốn Event ID

Mở `gpedit.msc`, dưới Computer Configuration:

1. Windows Settings → Security Settings → Advanced Audit Policy Configuration → System Audit Policies → Logon/Logoff → **Audit Logon**: chọn Success và Failure. Nguồn Security sẽ có 4624 và 4625 khi phát sinh thao tác tương ứng. [Microsoft Audit Logon](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-logon).
2. Cùng cây Advanced Audit Policy → Detailed Tracking → **Audit Process Creation**: chọn Success để ghi 4688. [Microsoft Audit Process Creation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-process-creation).
3. Administrative Templates → System → Audit Process Creation → **Include command line in process creation events**: Enabled. Thao tác này bổ sung dòng lệnh; bật Audit Process Creation riêng chưa đủ. [Microsoft hướng dẫn command line](https://devblogs.microsoft.com/commandline/how-to-determine-what-just-ran-on-windows-console/).
4. Administrative Templates → Windows Components → Windows PowerShell → **Turn on PowerShell Script Block Logging**: Enabled. Event 4104 nằm trong Microsoft-Windows-PowerShell/Operational. Mở phiên PowerShell mới sau cập nhật policy. [Microsoft PowerShell 5.1 Logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1).

Áp dụng và kiểm tra, không suy ra policy đã hiệu lực chỉ từ màn hình cấu hình:

```powershell
gpupdate /force
auditpol /get /category:*
Get-WinEvent -ListLog 'Microsoft-Windows-PowerShell/Operational' | Select-Object LogName, IsEnabled
```

Nếu kênh Operational bị tắt, bật Enable Log trong Event Viewer. Đóng PowerShell cũ, mở Windows PowerShell mới. Việc bật policy không tạo lại log quá khứ. Log có thể chứa dòng lệnh nhạy cảm; chỉ dùng tài khoản và nội dung lab.

## 3. Tạo và đối chiếu sự kiện mới

Ghi giờ bắt đầu ngay trước thao tác, trong cửa sổ PowerShell admin dùng để thu:

```powershell
$start = [DateTimeOffset]::Now.ToString('o')
```

Ở cửa sổ khác, dùng tài khoản lab đã có để đăng nhập/thử sai có kiểm soát theo kịch bản được phép. Với runas, tên máy và mật khẩu phải thuộc tài khoản lab **trong VM**, không phải PIN hoặc mật khẩu máy thật:

```powershell
runas /user:TEN_MAY_AO\lab_demo "powershell.exe -NoProfile"
```

Trong phiên mới, chạy thao tác minh họa vô hại như `Get-Date` và mở `notepad.exe`, rồi đóng Notepad. Ghi từng thao tác, tài khoản, giờ, kết quả đúng/sai thực tế; không coi một Event ID riêng lẻ là bằng chứng tấn công.

Kiểm tra Event Viewer → Windows Logs → Security: lọc 4624, 4625, 4688; và Applications and Services Logs → Microsoft → Windows → PowerShell → Operational: lọc 4104. Mở Details → XML, đối chiếu thời gian/máy/tài khoản; 4688 kiểm tra CommandLine, 4104 kiểm tra ScriptBlockText. Thiếu ID thì kiểm tra policy và thao tác vừa làm, không tự điền sự kiện giả. Kết thúc trong cửa sổ thu ban đầu:

```powershell
$end = [DateTimeOffset]::Now.ToString('o')
```

## 4. Xuất hai XML và manifest

Chép **cả** `Export-WindowsLogs.ps1` và `Collection.psm1` từ thư mục scripts trên máy thật vào cùng thư mục `C:\LabTools` trong VM. Đọc script trước khi chạy; script không thay audit policy và không xóa event log.

Từ cửa sổ admin đang giữ `$start` và `$end`:

```powershell
& C:\LabTools\Export-WindowsLogs.ps1 -StartTime $start -EndTime $end -OutputRoot C:\Lab
```

Nếu đã đóng cửa sổ, nhập giờ thật theo nhật ký, bắt buộc có múi giờ; ví dụ định dạng:

```powershell
& C:\LabTools\Export-WindowsLogs.ps1 -StartTime '2026-10-24T10:00:00+07:00' -EndTime '2026-10-24T10:05:00+07:00' -OutputRoot C:\Lab
```

Nếu Windows chặn script, kiểm tra `Get-ExecutionPolicy -List`. Với VM cá nhân lab được phép chạy script này, có thể chỉ cho phép trong lần gọi dưới đây, không thay policy lưu lâu dài. Nếu MachinePolicy/UserPolicy do quản trị đặt thì làm theo quản trị, không vượt policy:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\LabTools\Export-WindowsLogs.ps1 -StartTime $start -EndTime $end -OutputRoot C:\Lab
```

Đầu ra ở `C:\Lab\<timestamp>-<UUID>` gồm security.xml, powershell.xml, manifest.json. Khoảng thu đóng gồm cả start/end; script không giới hạn ngầm số sự kiện. Nên thu khoảng ngắn đúng kịch bản; không xóa log để giảm dung lượng. Nếu file vượt giới hạn nhập 50 MiB sau này, thu lại khoảng hẹp hơn và ghi rõ phạm vi.

`success`: đọc/ghi nguồn thành công. `no_events`: truy vấn được nhưng 0 bản ghi, XML Events rỗng, **không phải NORMAL**. `permission_denied`, `read_error`, `write_error`: lần thu là `partial`, giữ nguồn đã thành công. `complete` chỉ có nghĩa hoàn tất thao tác xuất cả hai nguồn, không bảo đảm đủ bốn ID hoặc đủ bằng chứng kịch bản. Manifest có count/counts_by_id để kiểm tra. Entry script trả mã 2 cho partial; lỗi thời gian/thư mục/manifest không được báo thành công. File `.part` do ghi dở phải giữ để kiểm tra, không nhập như file hoàn chỉnh.

## 5. Chép về máy thật và kiểm chứng

Chép toàn bộ thư mục lần thu qua Shared Folder của phần mềm máy ảo hoặc USB lab sang máy thật, ví dụ `D:\DACN_ATTT\Thang Code\winlog-agent\data\incoming\<run-id>`. Không chép vào Git hoặc ghi đè log-test cũ. Thư mục data bị ignore.

Trong VM và máy thật, thay đường dẫn đúng rồi so SHA256:

```powershell
Get-FileHash -LiteralPath 'C:\Lab\THU_MUC_LAN_THU\security.xml' -Algorithm SHA256
Get-FileHash -LiteralPath 'C:\Lab\THU_MUC_LAN_THU\powershell.xml' -Algorithm SHA256
```

Hash hai phía phải bằng nhau và khớp manifest. Kiểm tra số bản ghi XML bằng parser của ứng dụng khi phần nhập hoàn thành; trước đó đối chiếu XML/manifest và Event Viewer. Lưu cùng nhật ký: edition/build, policy thực tế, múi giờ, start/end, từng thao tác, số bản ghi, lỗi từng nguồn, hash trước/sau chép. Không đánh dấu task 3.4 hoàn thành chỉ bằng log cũ thiếu manifest hoặc kiểm thử tổng hợp.
