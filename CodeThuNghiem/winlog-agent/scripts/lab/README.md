# Script lab (chọn lọc từ Lam-Code)

Chỉ chạy trong VM thử nghiệm đã chụp snapshot, bằng quyền Administrator.

| File | Việc làm |
|---|---|
| `setup_client.bat` | Bật Audit Logon (thành công/thất bại), Process Creation kèm CommandLine và PowerShell Script Block Logging, rồi `gpupdate /force`. |
| `run_demo.bat` → `run_demo.ps1` | Kịch bản ALERT tổng hợp: tạo `lab_demo`, sai mật khẩu 5 lần rồi đăng nhập đúng, `whoami`, tạo user `hacker` và thêm vào Administrators, chạy PowerShell `-EncodedCommand` (download cradle + Run key). Xuất `security.xml`, `powershell.xml`, `manifest.json` vào `C:\demo`. |

## Giới hạn cần biết

- Đăng nhập dùng `net use \\127.0.0.1` nên 4624/4625 là LogonType 3, còn `whoami`/`net user` chạy trong phiên Administrator chứ không phải phiên `lab_demo`. Vì vậy ca này không chứng minh quan hệ phiên. Kịch bản chính (dò mật khẩu → phiên `lab_demo`) làm thủ công bằng `runas` theo [windows10-collection.md](../../docs/windows10-collection.md).
- Script xuất log từ 5 phút trước khi chạy, không có hash. Ca đưa vào bộ đánh giá phải xuất bằng `scripts/Export-WindowsLogs.ps1` để có manifest và hash.
- `manifest.json` của script có `ground_truth`. Đây chỉ là nhật ký thao tác; không đưa vào payload model.
- Script xóa `lab_demo` và `hacker` khi xong nhưng **không xóa Run key**. Dọn tay trong phiên Administrator:
  `Remove-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name Updater`

## Sau khi xuất

```powershell
.\.venv\Scripts\python.exe -m app.import_logs --data-root data/local --security C:\LabExport\security.xml --powershell C:\LabExport\powershell.xml
.\.venv\Scripts\python.exe -m app.cases IMPORT_ID --data-root data/local
.\.venv\Scripts\python.exe -m app.baseline_rules IMPORT_ID --data-root data/local
```
