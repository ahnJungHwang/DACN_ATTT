# So sánh công cụ trên log Windows thật
**Lập lúc:** `2026-11-12 18:38` · sinh tự động bởi `eval_real/compare_tools.py`, không sửa tay.

- **DeepBlueCLI**: công cụ dò theo luật, không dùng AI. Đọc **toàn bộ** file `.evtx`.
- **Hệ thống của nhóm**: chỉ đọc các mã sự kiện agent thu (tối đa 300 sự kiện mỗi ca); kết quả mỗi ca lấy theo đa số các lượt chạy.
- Ký hiệu `-`: ca không chạy được (file XML bị Microsoft Defender cách ly, hoặc log nằm ngoài phạm vi agent thu).
- Hai nguồn mẫu chỉ có log tấn công. Báo động giả chỉ đo được khi có file trong `eval_real/normal_evtx/`.

## 1. Tổng hợp

| Nhóm ca | DeepBlueCLI | DeepBlueCLI (thô, tính cả xoá log) | llama: hệ thống | llama: riêng AI | llama: chỉ luật | qwen: hệ thống | qwen: riêng AI | qwen: chỉ luật |
|---|---|---|---|---|---|---|---|---|
| Tấn công thật, có dấu vết trong log agent thu (bắt được) | 13/16 = 81% | 14/16 = 88% | 10/14 = 71% | 9/14 = 64% | 5/14 = 36% | 9/14 = 64% | 8/14 = 57% | 5/14 = 36% |
| Độ phủ mới (7045 / 4720 / 4728 / 4732) (bắt được) | 3/3 = 100% | 3/3 = 100% | 2/2 = 100% | 0/2 = 0% | 2/2 = 100% | 2/2 = 100% | 2/2 = 100% | 2/2 = 100% |
| Tấn công nằm ở log agent KHÔNG thu (bắt được) | 6/6 = 100% | 6/6 = 100% | chưa có dữ liệu | chưa có dữ liệu | chưa có dữ liệu | chưa có dữ liệu | chưa có dữ liệu | chưa có dữ liệu |
| Phiên hoạt động bình thường (đo báo động giả) (đúng NORMAL) | chưa có dữ liệu | chưa có dữ liệu | chưa có dữ liệu | chưa có dữ liệu | chưa có dữ liệu | chưa có dữ liệu | chưa có dữ liệu | chưa có dữ liệu |

Chỉ tính 16 ca tấn công mà cả DeepBlueCLI và `llama` cùng chạy được: DeepBlueCLI 13/16 = 81%, hệ thống 12/16 = 75%, riêng AI 9/16 = 56%, chỉ luật 7/16 = 44%.

Chỉ tính 16 ca tấn công mà cả DeepBlueCLI và `qwen` cùng chạy được: DeepBlueCLI 13/16 = 81%, hệ thống 11/16 = 69%, riêng AI 10/16 = 62%, chỉ luật 7/16 = 44%.

## 2. Thời gian xử lý mỗi ca

| Công cụ | Trung vị (s) | Lớn nhất (s) |
|---|---:|---:|
| DeepBlueCLI | 0.2 | 136.7 |
| llama (hệ thống) | 12.7 | 942.8 |
| qwen (hệ thống) | 11.5 | 715.8 |

Thời gian của hệ thống gồm cả lúc chờ GPU nguội nếu chạy có giới hạn nhiệt, nên chỉ để tham khảo; độ trễ từ lúc sinh sự kiện tới lúc nhận Telegram xem `results/LATENCY_REPORT.md`.

## 3. Chi tiết từng ca

| Ca | Nhóm | Nhãn | DeepBlueCLI | Số phát hiện | llama: hệ thống | llama: riêng AI | llama: chỉ luật | qwen: hệ thống | qwen: riêng AI | qwen: chỉ luật | DeepBlueCLI thấy gì |
|---|---|:---:|:---:|---:|:---:|:---:|:---:|:---:|:---:|:---:|---|
| `dbc_metasploit_psexec_native` | scored | ALERT | ALERT | 2 | UNKNOWN | UNKNOWN | NORMAL | NORMAL | NORMAL | NORMAL | Suspicious Command Line; Audit Log Clear |
| `dbc_metasploit_psexec_powershell` | scored | ALERT | ALERT | 5 | ALERT | ALERT | NORMAL | NORMAL | NORMAL | NORMAL | Suspicious Command Line; Audit Log Clear |
| `dbc_password_spray` | scored | ALERT | ALERT | 2 | ALERT | ALERT | NORMAL | ALERT | ALERT | NORMAL | Distributed Account Explicit Credential Use (Password Spray Attack); Audit Log Clear |
| `dbc_obfuscation_encoding` | scored | ALERT | ALERT | 11 | - | - | - | - | - | - | Suspicious Command Line |
| `dbc_obfuscation_many` | scored | ALERT | ALERT | 11 | - | - | - | - | - | - | Suspicious Command Line |
| `dbc_obfuscation_string` | scored | ALERT | ALERT | 4 | ALERT | ALERT | ALERT | ALERT | NORMAL | ALERT | Suspicious Command Line |
| `dbc_powersploit_security` | scored | ALERT | ALERT | 3 | ALERT | ALERT | NORMAL | ALERT | ALERT | NORMAL | Suspicious Command Line; Audit Log Clear |
| `dbc_powersploit_system` | scored | ALERT | ALERT | 3 | ALERT | ALERT | NORMAL | ALERT | ALERT | NORMAL | Suspicious Command Line; Audit Log Clear |
| `dbc_psattack` | scored | ALERT | ALERT | 9 | NORMAL | NORMAL | NORMAL | ALERT | ALERT | NORMAL | Suspicious Command Line; Audit Log Clear |
| `dbc_sliver_c2` | scored | ALERT | ALERT | 5 | UNKNOWN | UNKNOWN | NORMAL | NORMAL | NORMAL | NORMAL | Suspicious Command Line; Multiple admin logons for one account |
| `dbc_smb_password_guessing` | scored | ALERT | ALERT | 2 | ALERT | UNKNOWN | ALERT | ALERT | ALERT | ALERT | High number of total logon failures for multiple accounts |
| `e2m_local_bruteforce` | scored | ALERT | ALERT | 3 | ALERT | ALERT | ALERT | ALERT | ALERT | ALERT | High number of total logon failures for multiple accounts |
| `e2m_openssh_bruteforce_nonexist` | scored | ALERT | NORMAL (chỉ xoá log) | 1 | ALERT | ALERT | ALERT | ALERT | ALERT | ALERT | Audit Log Clear |
| `e2m_openssh_bruteforce_valid` | scored | ALERT | NORMAL | 0 | ALERT | ALERT | ALERT | ALERT | ALERT | ALERT |  |
| `e2m_openssh_install` | scored | ALERT | NORMAL | 0 | UNKNOWN | UNKNOWN | NORMAL | NORMAL | NORMAL | NORMAL |  |
| `e2m_openssh_activation` | scored | ALERT | ALERT | 97 | ALERT | ALERT | NORMAL | UNKNOWN | UNKNOWN | NORMAL | Suspicious Command Line |
| `dbc_metasploit_pwshpayload` | insufficient_evidence | ALERT | NORMAL (chỉ xoá log) | 1 | NORMAL | NORMAL | NORMAL | NORMAL | NORMAL | NORMAL | Audit Log Clear |
| `dbc_mimikatz_tokenelevate` | insufficient_evidence | ALERT | NORMAL (chỉ xoá log) | 1 | NORMAL | NORMAL | NORMAL | NORMAL | NORMAL | NORMAL | Audit Log Clear |
| `dbc_many_events_security` | unlabeled | UNKNOWN | ALERT | 86 | ALERT | ALERT | ALERT | ALERT | NORMAL | ALERT | Suspicious Command Line; User added to local Administrators group; New User Created; Multiple admin logons for one account |
| `dbc_metasploit_psexec_native_system` | coverage | ALERT | ALERT | 6 | ALERT | UNKNOWN | ALERT | ALERT | ALERT | ALERT | Suspicious Service Command; Suspicious Service Name; System Log Clear |
| `dbc_metasploit_psexec_powershell_system` | coverage | ALERT | ALERT | 4 | - | - | - | - | - | - | Suspicious Service Command; System Log Clear |
| `dbc_new_user_admin_group` | coverage | ALERT | ALERT | 2 | ALERT | UNKNOWN | ALERT | ALERT | ALERT | ALERT | User added to local Administrators group; New User Created |
| `dbc_many_events_system` | unlabeled | UNKNOWN | ALERT | 57 | - | - | - | - | - | - | Suspicious Service Command; Suspicious Service Name |
| `oos_disablestop-eventlog` | out_of_scope | ALERT | ALERT | 3 | - | - | - | - | - | - | Event Log Service Started; Event Log Service Stopped; System Log Clear |
| `oos_eventlog-dac` | out_of_scope | ALERT | ALERT | 5 | - | - | - | - | - | - | Sensitive Privilege Use Exceeds Threshold; Possible Hidden Service Attempt; Audit Log Clear |
| `oos_metasploit-sysmon` | out_of_scope | ALERT | ALERT | 13 | - | - | - | - | - | - | Suspicious remote thread; Suspicious Command Line |
| `oos_mimikatz-privesc-hashdump` | out_of_scope | ALERT | ALERT | 2 | - | - | - | - | - | - | Sensitive Privilege Use Exceeds Threshold; Audit Log Clear |
| `oos_sliver-sysmon` | out_of_scope | ALERT | ALERT | 4 | - | - | - | - | - | - | Suspicious remote thread; Suspicious Command Line |
| `oos_wmi-event-filter-persistance` | out_of_scope | ALERT | ALERT | 1 | - | - | - | - | - | - | Suspicous WMI Event Filter |
| `oos_many-events-application` | out_of_scope | UNKNOWN | NORMAL | 0 | - | - | - | - | - | - |  |
| `oos_many-events-system` | out_of_scope | UNKNOWN | ALERT | 57 | - | - | - | - | - | - | Suspicious Service Command; Suspicious Service Name |
