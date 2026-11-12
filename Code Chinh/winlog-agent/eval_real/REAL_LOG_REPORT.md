# Đánh giá trên log Windows THẬT (DeepBlueCLI + EVTX-to-MITRE)
**Thời gian:** `2026-11-12 18:38:17` · **Số lần lặp mỗi ca:** 3 · **Nhãn:** `eval_real/labels.json` (chốt trước khi chạy model, theo mô tả của nguồn)

## 1. Phạm vi dữ liệu

| Nhóm | Số ca | Ghi chú |
|---|:---:|---|
| Tính điểm (`scored`) | 16 | Tấn công thật, có dấu vết trong log agent thu (4624/4625/4648/4688/4104) |
| Độ phủ mới (`coverage`) | 3 | Trước đây ngoài phạm vi; nay agent thu 7045 / 4720 / 4728 / 4732 |
| Không đủ bằng chứng | 2 | Nguồn nói là tấn công nhưng phần log agent thu chỉ có vài 4624 |
| Không có nhãn | 2 | Nguồn không mô tả; chỉ quan sát |
| **Ngoài phạm vi agent** | 8 | Tấn công chỉ để lại dấu vết ở log agent KHÔNG thu |
| Bị antivirus chặn | 4 | `dbc_obfuscation_encoding`, `dbc_obfuscation_many`, `dbc_metasploit_psexec_powershell_system`, `dbc_many_events_system` — Microsoft Defender cách ly file XML chứa mã độc thật; không tắt Defender, loại khỏi điểm |

**Lưu ý quan trọng:** cả hai nguồn chỉ chứa log TẤN CÔNG, nên bộ này đo được **Recall (khả năng bắt tấn công)** nhưng **không đo được báo động giả**. Báo động giả phải đo bằng log hoạt động bình thường thu từ máy thật (bước 2).

## 2. Kết quả — `llama` (llama3.2:3b-instruct-q4_K_M)

### Ca tấn công thật (bộ gốc 14 ca)

Recall tính theo từng lượt chạy:

| Cách phát hiện | Recall | 
|---|---|
| **Hệ thống** (luật mạnh + AI + tự thẩm định) | 71.4% (30/42; KTC95% 56%–83%) |
| Riêng AI | 61.9% (26/42; KTC95% 47%–75%) |
| Chỉ luật (mọi tín hiệu) | 35.7% (15/42; KTC95% 23%–51%) |
| Chỉ luật mạnh | 35.7% (15/42; KTC95% 23%–51%) |

- Theo ca (đa số phiếu 3 lần): hệ thống bắt được **71.4% (10/14; KTC95% 45%–88%)**.
- **Độ ổn định:** 13/14 ca cho cùng một kết quả (hệ thống và AI) ở mọi lần chạy.
- Lỗi kỹ thuật: 0 lượt.
- Thời gian trung vị mỗi ca: 16.3s.

Chi tiết từng ca:

| Ca | Kỹ thuật | Sự kiện | Hệ thống | Riêng AI | Chỉ luật | Nguồn quyết định | TG TB (s) |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|
| `dbc_metasploit_psexec_native` | T1569.002 Service Execution (Metasploit PsExec) | 3 | UNKNOWN×3 | UNKNOWN×3 | NORMAL | ai×3 | 8.6 |
| `dbc_metasploit_psexec_powershell` | T1569.002 / T1059.001 (Metasploit PsExec PowerShell) | 7 | ALERT×3 | ALERT×3 | NORMAL | ai×3 | 20.0 |
| `dbc_password_spray` | T1110.003 Password Spraying | 294 | ALERT×3 | ALERT×3 | NORMAL | ai×3 | 232.0 |
| `dbc_obfuscation_string` | T1027 Obfuscated Files / T1059.001 | 4 | ALERT×3 | ALERT×2, UNKNOWN×1 | ALERT | rule+ai×2, rule×1 | 8.7 |
| `dbc_powersploit_security` | T1059.001 PowerSploit | 26 | ALERT×3 | ALERT×3 | NORMAL | ai×3 | 18.6 |
| `dbc_powersploit_system` | T1059.001 PowerSploit | 3 | ALERT×3 | ALERT×3 | NORMAL | ai×3 | 15.4 |
| `dbc_psattack` | T1059.001 PSAttack | 23 | NORMAL×3 | NORMAL×3 | NORMAL | ai×3 | 17.4 |
| `dbc_sliver_c2` | T1071 C2 (Sliver) | 38 | UNKNOWN×3 | UNKNOWN×3 | NORMAL | ai×3 | 18.4 |
| `dbc_smb_password_guessing` | T1110.001 Password Guessing | 300 (cắt 300) | ALERT×3 | UNKNOWN×3 | ALERT | rule×3 | 156.1 |
| `e2m_local_bruteforce` | T1110 Brute Force | 16 | ALERT×3 | ALERT×3 | ALERT | rule+ai×3 | 12.3 |
| `e2m_openssh_bruteforce_nonexist` | T1110 Brute Force (OpenSSH) | 9 | ALERT×3 | ALERT×3 | ALERT | rule+ai×3 | 9.4 |
| `e2m_openssh_bruteforce_valid` | T1110 Brute Force (OpenSSH) | 11 | ALERT×3 | ALERT×3 | ALERT | rule+ai×3 | 9.7 |
| `e2m_openssh_install` ⚠️dual-use | T1021.004 Remote Services: SSH | 4 | UNKNOWN×3 | UNKNOWN×3 | NORMAL | ai×3 | 9.1 |
| `e2m_openssh_activation` ⚠️dual-use | T1021.004 Remote Services: SSH | 103 | ALERT×3 | ALERT×3 | NORMAL | ai×3 | 808.1 |

### Ca độ phủ mới (sau khi mở rộng thu thập)

Recall tính theo từng lượt chạy:

| Cách phát hiện | Recall | 
|---|---|
| **Hệ thống** (luật mạnh + AI + tự thẩm định) | 100.0% (6/6; KTC95% 61%–100%) |
| Riêng AI | 0.0% (0/6; KTC95% 0%–39%) |
| Chỉ luật (mọi tín hiệu) | 100.0% (6/6; KTC95% 61%–100%) |
| Chỉ luật mạnh | 100.0% (6/6; KTC95% 61%–100%) |

- Theo ca (đa số phiếu 3 lần): hệ thống bắt được **100.0% (2/2; KTC95% 34%–100%)**.
- **Độ ổn định:** 2/2 ca cho cùng một kết quả (hệ thống và AI) ở mọi lần chạy.
- Lỗi kỹ thuật: 0 lượt.
- Thời gian trung vị mỗi ca: 10.6s.

Chi tiết từng ca:

| Ca | Kỹ thuật | Sự kiện | Hệ thống | Riêng AI | Chỉ luật | Nguồn quyết định | TG TB (s) |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|
| `dbc_metasploit_psexec_native_system` | T1569.002 / T1543.003 PsExec (service) | 2 | ALERT×3 | UNKNOWN×3 | ALERT | rule×3 | 10.1 |
| `dbc_new_user_admin_group` | T1136.001 Create Account + T1098 Add to Administrators | 4 | ALERT×3 | UNKNOWN×3 | ALERT | rule×3 | 10.9 |

### Ca không tính điểm (quan sát)

| Ca | Nhóm | Sự kiện | Hệ thống | Riêng AI | Chỉ luật |
|---|---|:---:|:---:|:---:|:---:|
| `dbc_metasploit_pwshpayload` | insufficient_evidence | 1 | NORMAL | NORMAL | NORMAL |
| `dbc_mimikatz_tokenelevate` | insufficient_evidence | 2 | NORMAL | NORMAL | NORMAL |
| `dbc_many_events_security` | unlabeled | 300 | ALERT | ALERT | ALERT |

## 2. Kết quả — `qwen` (qwen2.5:3b-instruct-q4_K_M)

### Ca tấn công thật (bộ gốc 14 ca)

Recall tính theo từng lượt chạy:

| Cách phát hiện | Recall | 
|---|---|
| **Hệ thống** (luật mạnh + AI + tự thẩm định) | 61.9% (26/42; KTC95% 47%–75%) |
| Riêng AI | 54.8% (23/42; KTC95% 40%–69%) |
| Chỉ luật (mọi tín hiệu) | 35.7% (15/42; KTC95% 23%–51%) |
| Chỉ luật mạnh | 35.7% (15/42; KTC95% 23%–51%) |

- Theo ca (đa số phiếu 3 lần): hệ thống bắt được **64.3% (9/14; KTC95% 39%–84%)**.
- **Độ ổn định:** 13/14 ca cho cùng một kết quả (hệ thống và AI) ở mọi lần chạy.
- Lỗi kỹ thuật: 0 lượt.
- Thời gian trung vị mỗi ca: 12.2s.

Chi tiết từng ca:

| Ca | Kỹ thuật | Sự kiện | Hệ thống | Riêng AI | Chỉ luật | Nguồn quyết định | TG TB (s) |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|
| `dbc_metasploit_psexec_native` | T1569.002 Service Execution (Metasploit PsExec) | 3 | NORMAL×3 | NORMAL×3 | NORMAL | ai×3 | 8.5 |
| `dbc_metasploit_psexec_powershell` | T1569.002 / T1059.001 (Metasploit PsExec PowerShell) | 7 | NORMAL×3 | NORMAL×3 | NORMAL | ai×3 | 9.5 |
| `dbc_password_spray` | T1110.003 Password Spraying | 294 | ALERT×3 | ALERT×3 | NORMAL | ai×3 | 132.1 |
| `dbc_obfuscation_string` | T1027 Obfuscated Files / T1059.001 | 4 | ALERT×3 | NORMAL×3 | ALERT | rule×3 | 8.8 |
| `dbc_powersploit_security` | T1059.001 PowerSploit | 26 | ALERT×2, NORMAL×1 | ALERT×2, NORMAL×1 | NORMAL | ai×3 | 15.7 |
| `dbc_powersploit_system` | T1059.001 PowerSploit | 3 | ALERT×3 | ALERT×3 | NORMAL | ai×3 | 13.3 |
| `dbc_psattack` | T1059.001 PSAttack | 23 | ALERT×3 | ALERT×3 | NORMAL | ai×3 | 19.0 |
| `dbc_sliver_c2` | T1071 C2 (Sliver) | 38 | NORMAL×3 | NORMAL×3 | NORMAL | ai×3 | 19.9 |
| `dbc_smb_password_guessing` | T1110.001 Password Guessing | 300 (cắt 300) | ALERT×3 | ALERT×3 | ALERT | rule+ai×3 | 158.2 |
| `e2m_local_bruteforce` | T1110 Brute Force | 16 | ALERT×3 | ALERT×3 | ALERT | rule+ai×3 | 12.1 |
| `e2m_openssh_bruteforce_nonexist` | T1110 Brute Force (OpenSSH) | 9 | ALERT×3 | ALERT×3 | ALERT | rule+ai×3 | 10.3 |
| `e2m_openssh_bruteforce_valid` | T1110 Brute Force (OpenSSH) | 11 | ALERT×3 | ALERT×3 | ALERT | rule+ai×3 | 10.2 |
| `e2m_openssh_install` ⚠️dual-use | T1021.004 Remote Services: SSH | 4 | NORMAL×3 | NORMAL×3 | NORMAL | ai×3 | 8.7 |
| `e2m_openssh_activation` ⚠️dual-use | T1021.004 Remote Services: SSH | 103 | UNKNOWN×3 | UNKNOWN×3 | NORMAL | ai×3 | 702.6 |

### Ca độ phủ mới (sau khi mở rộng thu thập)

Recall tính theo từng lượt chạy:

| Cách phát hiện | Recall | 
|---|---|
| **Hệ thống** (luật mạnh + AI + tự thẩm định) | 100.0% (6/6; KTC95% 61%–100%) |
| Riêng AI | 100.0% (6/6; KTC95% 61%–100%) |
| Chỉ luật (mọi tín hiệu) | 100.0% (6/6; KTC95% 61%–100%) |
| Chỉ luật mạnh | 100.0% (6/6; KTC95% 61%–100%) |

- Theo ca (đa số phiếu 3 lần): hệ thống bắt được **100.0% (2/2; KTC95% 34%–100%)**.
- **Độ ổn định:** 2/2 ca cho cùng một kết quả (hệ thống và AI) ở mọi lần chạy.
- Lỗi kỹ thuật: 0 lượt.
- Thời gian trung vị mỗi ca: 9.1s.

Chi tiết từng ca:

| Ca | Kỹ thuật | Sự kiện | Hệ thống | Riêng AI | Chỉ luật | Nguồn quyết định | TG TB (s) |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|
| `dbc_metasploit_psexec_native_system` | T1569.002 / T1543.003 PsExec (service) | 2 | ALERT×3 | ALERT×3 | ALERT | rule+ai×3 | 8.8 |
| `dbc_new_user_admin_group` | T1136.001 Create Account + T1098 Add to Administrators | 4 | ALERT×3 | ALERT×3 | ALERT | rule+ai×3 | 9.4 |

### Ca không tính điểm (quan sát)

| Ca | Nhóm | Sự kiện | Hệ thống | Riêng AI | Chỉ luật |
|---|---|:---:|:---:|:---:|:---:|
| `dbc_metasploit_pwshpayload` | insufficient_evidence | 1 | NORMAL | NORMAL | NORMAL |
| `dbc_mimikatz_tokenelevate` | insufficient_evidence | 2 | NORMAL | NORMAL | NORMAL |
| `dbc_many_events_security` | unlabeled | 300 | ALERT | NORMAL | ALERT |

## 3. Tấn công nằm ngoài phạm vi thu thập của agent

Các mẫu dưới đây là tấn công thật nhưng agent hiện **không thể phát hiện** vì không thu loại log tương ứng:

| File | Kỹ thuật | Cần thu thêm |
|---|---|---|
| `disablestop-eventlog.evtx` | T1562.002 Dung dich vu Event Log | System 7035/7036/7040 (su kien 104/1102 trong mau la dau vet chuan bi, da loai) |
| `eventlog-dac.evtx` | T1070.001 Xoa/sua quyen nhat ky | Security 1102, 4673 (su kien 104/1102 trong mau la dau vet chuan bi, da loai) |
| `metasploit-sysmon.evtx` | Metasploit | Sysmon |
| `mimikatz-privesc-hashdump.evtx` | T1003.002 Mimikatz lsadump::sam | Security 4673/4674 |
| `sliver-sysmon.evtx` | Sliver C2 | Sysmon |
| `wmi-event-filter-persistance.evtx` | T1546.003 WMI Event Subscription | WMI-Activity / Sysmon 19-21 |
| `many-events-application.evtx` | (khong mo ta) | Application |
| `many-events-system.evtx` | (khong mo ta) | System |

CSV chi tiết từng lượt: `eval_real/real_log_results.csv`.
