# Nhật ký lần thu VMware Windows 10

Điền theo thao tác thực tế; không điền trước kết quả mong muốn thành kết quả đã xảy ra. Không ghi mật khẩu/PIN/token. Giữ file này cùng manifest và hai XML ngoài Git.

- Người thực hiện:
- Tên VM / ComputerName:
- Windows edition / build:
- Múi giờ VM:
- Mốc khởi động VM / boot identifier nếu đã ghi nhận:
- Tài khoản lab và domain/máy:
- Kết quả kiểm tra audit: Logon Success/Failure, Process Creation, command line, Script Block Logging:
- Chính sách khóa tài khoản đã kiểm tra:
- Thời gian bắt đầu có offset:
- Thời gian kết thúc có offset:
- Run ID trong manifest:
PS C:\Windows\system32> Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, LastBootUpTime

Caption                  Version    BuildNumber LastBootUpTime
-------                  -------    ----------- --------------
Microsoft Windows 10 Pro 10.0.19045 19045       10/19/2026 12:41:32 PM


PS C:\Windows\system32> $PSVersionTable.PSVersion

Major  Minor  Build  Revision
-----  -----  -----  --------
5      1      19041  2673


PS C:\Windows\system32> hostname
Win10
PS C:\Windows\system32> whoami
win10\admin
PS C:\Windows\system32> Get-Date -Format o
2026-10-27T07:03:31.2554494+07:00
PS C:\Windows\system32> Get-TimeZone


Id                         : SE Asia Standard Time
DisplayName                : (UTC+07:00) Bangkok, Hanoi, Jakarta
StandardName               : SE Asia Standard Time
DaylightName               : SE Asia Daylight Time
BaseUtcOffset              : 07:00:00
SupportsDaylightSavingTime : False



PS C:\Windows\system32> net accounts
Force user logoff how long after time expires?:       Never
Minimum password age (days):                          0
Maximum password age (days):                          42
Minimum password length:                              0
Length of password history maintained:                None
Lockout threshold:                                    10
Lockout duration (minutes):                           10
Lockout observation window (minutes):                 10
Computer role:                                        WORKSTATION
The command completed successfully.

## Thao tác

Mỗi dòng ghi: thời gian có offset; tài khoản/phiên đang dùng; thao tác; kết quả quan sát thực tế; Event ID/RecordID hoặc refs đã đối chiếu. Với lần nhập mật khẩu sai chỉ ghi đúng/sai và số lượt, không ghi nội dung mật khẩu.

1. …
2. …
3. …

## Đối chiếu lần thu

- Thư mục xuất trong VM:
- Trạng thái từng nguồn trong manifest:
- Số sự kiện từng nguồn và từng Event ID:
- Event ID thiếu / lỗi chất lượng / quan hệ phiên chưa xác định:
- Hash XML trong VM và sau chép về máy thật có khớp không:
- Kết quả app.verify_collection:
- Case ID sau khi nhập và tạo ca:
- Nhãn do người thực hiện đối chiếu và lý do, hoặc ghi chưa đủ dữ liệu:

## Kiểm chứng phân tích sau khi thu

- Model / digest / result_id (tách hai model):
- Bằng chứng XML đã đối chiếu với lý do model:
- Workflow n8n execution / request_id:
- Kết luận còn sai hoặc chưa xác minh:

Một nhật ký/lần thu không tự đủ cho tập 10 development + 40 evaluation. Giữ các lần thu/phiên độc lập khi chia tập.
