# 🎯 THƯ MỤC KỊCH BẢN DEMO THỰC CHIẾN (AI SOC LIVE DEMOS)

Thư mục này chứa toàn bộ các kịch bản mô phỏng tấn công và thử nghiệm lành tính phục vụ trình diễn trước Hội đồng và khách hàng.

---

## 📋 Danh sách các kịch bản:

| File thực thi | Tên kịch bản | Kỹ thuật MITRE ATT&CK | Hành vi mô phỏng | Phản ứng AI SOC |
| :--- | :--- | :--- | :--- | :--- |
| **`demo0_normal_benign.bat`** | Tác vụ Văn phòng Lành tính | Benign Activity | Mở Notepad, ping Gateway, gõ nhầm pass 1 lần | Phán quyết **NORMAL**, không báo Telegram (Triệt tiêu báo động giả) |
| **`demo1_bruteforce.bat`** | Dò quét Mật khẩu | T1110 (Brute Force) | 5 lần đăng nhập sai tài khoản admin trong 2 giây | Phán quyết **ALERT**, cảnh báo tấn công dò mật khẩu |
| **`demo2_powershell_c2.bat`** | PowerShell C2 Cradle | T1059.001 (PowerShell) | PowerShell tải payload từ xa qua WebClient / IEX | Phán quyết **ALERT**, trích xuất dòng lệnh độc hại |
| **`demo3_mimikatz.bat`** | Trích xuất Mật khẩu LSASS | T1003 (Credential Dumping) | Thực thi lệnh Sekurlsa::logonpasswords | Phán quyết **ALERT**, gán nhãn Đánh cắp thông tin xác thực |
| **`demo4_backdoor_admin.bat`** | Tạo Backdoor & Leo quyền | T1136 / T1098 | Tạo user lạ `support_backdoor` và add vào nhóm Administrators | Phán quyết **ALERT**, phát hiện leo thang đặc quyền |
| **`demo5_registry_persistence.bat`** | Duy trì Xâm nhập Run Key | T1547.001 (Registry Run) | Ghi đè khóa `HKCU\...\CurrentVersion\Run` | Phán quyết **ALERT**, phát hiện cơ chế Persistence |
| **`demo6_full_killchain.bat`** | Chuỗi Tấn công Tổng hợp APT | Full Cyber Kill Chain | Brute-force -> C2 -> Mimikatz -> Backdoor -> Registry Persistence | Phán quyết **ALERT**, tổng hợp chuỗi tấn công liên hoàn |

---

## 🛠️ Công cụ hỗ trợ:
- **`simulate_attack.bat`**: Giao diện dòng lệnh tùy biến nâng cao (chọn kịch bản, số lần lặp, độ trễ).
- **`simulate_attack.ps1`**: PowerShell Engine cốt lõi sinh sự kiện Windows an toàn (không gây hại hệ điều hành).

> 💡 **Mẹo:** Bạn có thể chạy từng file `.bat` độc lập tại đây hoặc chạy menu tổng hợp `run_demo.bat` tại thư mục gốc.

