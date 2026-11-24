# So sánh công cụ trên bộ log thật gộp (25/11/2026)

- **Tấn công:** ca có nhãn trong `labels.json` (DeepBlueCLI + EVTX-to-MITRE). `scored` = có dấu vết trong log agent thu; `coverage` = dịch vụ / tài khoản mới (7045, 4720, 4728, 4732).
- **Bình thường:** log laptop thật của một thành viên (Security + PowerShell/Operational, 21–24/11/2026), cắt cửa sổ 10 phút (`build_normal_cases.ps1`), ẩn danh tên máy / email / thư mục hồ sơ.
- Ca DeepBlueCLI chỉ phát hiện "Log Clear" được tính là NORMAL (dấu vết người tạo mẫu). Sigma ở đây là bản **mô phỏng bằng regex** (`core/rule_baselines.py`), không phải engine Sigma thật.
- UNKNOWN / REVIEW: với ca tấn công tính là bỏ sót; với ca bình thường không tính là báo nhầm (ghi riêng).
- DeepBlueCLI và Hayabusa đọc **toàn bộ** file evtx (cả sự kiện agent không thu); Qwen / Llama / luật nhóm chỉ thấy sự kiện agent thu (4624/4625/4648/4688/1102/4720/4728/4732/4698/4104/7045/104).
- Mọi công cụ được chấm trên cùng tập ca. Loại 8 ca có công cụ lỗi / bị antivirus chặn: `dbc_metasploit_psexec_powershell_system`, `dbc_obfuscation_encoding`, `dbc_obfuscation_many`, `lam_normal_20261123_0820`, `lam_normal_20261123_0830`, `lam_normal_20261123_1110`, `lam_normal_20261123_1830`, `lam_normal_20261123_1840`

## 1. Tổng hợp

| Công cụ | Bắt tấn công `scored` | Bắt `coverage` | Báo nhầm trên ca bình thường | REVIEW/UNKNOWN (bình thường) | Precision | F1 | TG trung vị/ca |
|---|---|---|---|:---:|:---:|:---:|:---:|
| Qwen 2.5 3B (luật + AI) | 71.4% (10/14; KTC95% 45%–88%) | 2/2 | 2.8% (3/107; KTC95% 1%–8%) | 2 | 80.0% | 0.774 | 11.18s |
| Llama 3.2 3B (luật + AI) | 78.6% (11/14; KTC95% 52%–92%) | 2/2 | 0.9% (1/107; KTC95% 0%–5%) | 6 | 92.9% | 0.867 | 11.86s |
| Luật của nhóm (không AI) | 57.1% (8/14; KTC95% 33%–79%) | 2/2 | 0.0% (0/107; KTC95% 0%–3%) | 0 | 100.0% | 0.769 | 0.00s |
| DeepBlueCLI (công cụ thật) | 78.6% (11/14; KTC95% 52%–92%) | 2/2 | 18.7% (20/107; KTC95% 12%–27%) | 0 | 39.4% | 0.531 | 0.17s |
| Hayabusa + Sigma (công cụ thật, mức >= medium) | 78.6% (11/14; KTC95% 52%–92%) | 2/2 | 12.1% (13/107; KTC95% 7%–20%) | 0 | 50.0% | 0.619 | 5.90s |
| Sigma mô phỏng (regex) | 50.0% (7/14; KTC95% 27%–73%) | 1/2 | 0.9% (1/107; KTC95% 0%–5%) | 0 | 88.9% | 0.640 | 0.00s |

## 2. Ca bình thường bị báo nhầm

**Qwen 2.5 3B (luật + AI):** `lam_normal_20261121_1910`, `lam_normal_20261123_0730`, `lam_normal_20261124_1910`
  - `lam_normal_20261121_1910`: 
  - `lam_normal_20261123_0730`: 
  - `lam_normal_20261124_1910`: 

**Llama 3.2 3B (luật + AI):** `lam_normal_20261122_1940`
  - `lam_normal_20261122_1940`: 

**Luật của nhóm (không AI):** không có

**DeepBlueCLI (công cụ thật):** `lam_normal_20261121_1040`, `lam_normal_20261121_1420`, `lam_normal_20261121_1550`, `lam_normal_20261121_1910`, `lam_normal_20261121_2140`, `lam_normal_20261121_2210`, `lam_normal_20261121_2310`, `lam_normal_20261122_1350`, `lam_normal_20261122_1400`, `lam_normal_20261122_1450`, `lam_normal_20261122_1940`, `lam_normal_20261123_0730`, `lam_normal_20261123_0740`, `lam_normal_20261123_0900`, `lam_normal_20261123_0940`, `lam_normal_20261123_0950`, `lam_normal_20261123_1820`, `lam_normal_20261124_1910`, `lam_normal_20261124_1920`, `lam_normal_20261124_1930`
  - `lam_normal_20261121_1040`: Multiple admin logons for one account
  - `lam_normal_20261121_1420`: Multiple admin logons for one account
  - `lam_normal_20261121_1550`: Multiple admin logons for one account
  - `lam_normal_20261121_1910`: Multiple admin logons for one account
  - `lam_normal_20261121_2140`: Suspicious Command Line
  - `lam_normal_20261121_2210`: Suspicious Command Line
  - `lam_normal_20261121_2310`: Suspicious Command Line
  - `lam_normal_20261122_1350`: Suspicious Command Line; Multiple admin logons for one account
  - `lam_normal_20261122_1400`: Suspicious Command Line; Multiple admin logons for one account
  - `lam_normal_20261122_1450`: Multiple admin logons for one account
  - `lam_normal_20261122_1940`: Suspicious Command Line; Multiple admin logons for one account
  - `lam_normal_20261123_0730`: Suspicious Command Line; Multiple admin logons for one account
  - `lam_normal_20261123_0740`: Multiple admin logons for one account
  - `lam_normal_20261123_0900`: Multiple admin logons for one account
  - `lam_normal_20261123_0940`: Multiple admin logons for one account

**Hayabusa + Sigma (công cụ thật, mức >= medium):** `lam_normal_20261121_2140`, `lam_normal_20261121_2210`, `lam_normal_20261121_2220`, `lam_normal_20261121_2310`, `lam_normal_20261122_1350`, `lam_normal_20261122_1400`, `lam_normal_20261122_1940`, `lam_normal_20261123_0730`, `lam_normal_20261123_0810`, `lam_normal_20261123_1820`, `lam_normal_20261123_1900`, `lam_normal_20261124_1920`, `lam_normal_20261124_1930`
  - `lam_normal_20261121_2140`: [med] Potentially Malicious PwSh
  - `lam_normal_20261121_2210`: [med] Potentially Malicious PwSh
  - `lam_normal_20261121_2220`: [med] Potentially Malicious PwSh
  - `lam_normal_20261121_2310`: [med] Potentially Malicious PwSh
  - `lam_normal_20261122_1350`: [med] Potentially Malicious PwSh
  - `lam_normal_20261122_1400`: [med] Potentially Malicious PwSh
  - `lam_normal_20261122_1940`: [med] Potentially Malicious PwSh
  - `lam_normal_20261123_0730`: [med] Potentially Malicious PwSh
  - `lam_normal_20261123_0810`: [med] Potentially Malicious PwSh
  - `lam_normal_20261123_1820`: [med] Potentially Malicious PwSh
  - `lam_normal_20261123_1900`: [med] Potentially Malicious PwSh
  - `lam_normal_20261124_1920`: [med] Potentially Malicious PwSh
  - `lam_normal_20261124_1930`: [med] Potentially Malicious PwSh

**Sigma mô phỏng (regex):** `lam_normal_20261124_1930`
  - `lam_normal_20261124_1930`: Sigma [proc_creation_win_schtasks_persistence]: Scheduled Task Persistence

## 3. Từng ca tấn công

| Ca | Nhóm | Qwen 2.5 3B (luật + AI) | Llama 3.2 3B (luật + AI) | Luật của nhóm (không AI) | DeepBlueCLI (công cụ thật) | Hayabusa + Sigma (công cụ thật, mức >= medium) | Sigma mô phỏng (regex) |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|
| `dbc_metasploit_psexec_native` | scored | NORMAL | NORMAL | NORMAL | ALERT | ALERT | NORMAL |
| `dbc_metasploit_psexec_powershell` | scored | ALERT | NORMAL | NORMAL | ALERT | ALERT | NORMAL |
| `dbc_password_spray` | scored | NORMAL | ALERT | NORMAL | ALERT | ALERT | NORMAL |
| `dbc_obfuscation_string` | scored | ALERT | ALERT | ALERT | ALERT | ALERT | ALERT |
| `dbc_powersploit_security` | scored | ALERT | ALERT | ALERT | ALERT | ALERT | ALERT |
| `dbc_powersploit_system` | scored | ALERT | ALERT | ALERT | ALERT | ALERT | ALERT |
| `dbc_psattack` | scored | ALERT | NORMAL | NORMAL | ALERT | ALERT | NORMAL |
| `dbc_sliver_c2` | scored | ALERT | ALERT | ALERT | ALERT | ALERT | NORMAL |
| `dbc_smb_password_guessing` | scored | ALERT | ALERT | ALERT | ALERT | ALERT | ALERT |
| `e2m_local_bruteforce` | scored | ALERT | ALERT | ALERT | ALERT | NORMAL | ALERT |
| `e2m_openssh_bruteforce_nonexist` | scored | ALERT | ALERT | ALERT | NORMAL | NORMAL | ALERT |
| `e2m_openssh_bruteforce_valid` | scored | ALERT | ALERT | ALERT | NORMAL | NORMAL | ALERT |
| `e2m_openssh_install` | scored | NORMAL | ALERT | NORMAL | NORMAL | ALERT | NORMAL |
| `e2m_openssh_activation` | scored | UNKNOWN | ALERT | NORMAL | ALERT | ALERT | NORMAL |
| `dbc_metasploit_psexec_native_system` | coverage | ALERT | ALERT | ALERT | ALERT | ALERT | NORMAL |
| `dbc_new_user_admin_group` | coverage | ALERT | ALERT | ALERT | ALERT | ALERT | ALERT |

## 4. Nhiệt độ GPU khi chạy mô hình

- Mẫu mỗi giây: 12047 · cao nhất **73.26°C** · trung bình 55.2°C · số giây >= 60°C: 2984
