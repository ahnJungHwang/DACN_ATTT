# Test toàn bộ log máy thật, có hướng dẫn nhận biết nhiễu (25/11/2026)

- Thiết kế: `md/THIET_KE_TEST_TOAN_BO_LOG_25112026.md`. Hướng dẫn nhiễu chỉnh trên log **trước 22/11**, khoá, rồi mới chạy phần **kiểm tra 22–24/11** dưới đây.
- **Tấn công:** ca `labels.json` dựng lại với cả Event ID mới (bản `_full`). **Bình thường:** log laptop thật của một thành viên, cửa sổ 10 phút, đã ẩn danh.
- Qwen / Llama / luật nhóm thấy 12 ID agent thu + nhóm ID mới (4798/4799/4672/5382/4797/4738/4647/4616/1100/4719/4103/400/800); ID chỉ toàn nhiễu bị bỏ ở mức code. DeepBlueCLI và Hayabusa đọc **toàn bộ** evtx của cùng cửa sổ (DeepBlueCLI không đọc được log "Windows PowerShell" cổ điển).
- Ca DeepBlueCLI / Hayabusa chỉ phát hiện "Log Clear" tính là NORMAL. Sigma mô phỏng = regex trong `core/rule_baselines.py`.
- UNKNOWN / REVIEW: với ca tấn công tính là bỏ sót; với ca bình thường không tính là báo nhầm (ghi riêng).
- Đối chứng (`NOISE_GUIDANCE=0`) chỉ bỏ cột "hoạt động bình thường" của nhóm ID mới. Cột dấu hiệu tấn công vẫn giữ các điều kiện đã chỉnh trên phần dev (4798/4799 chỉ là đọc; -w hidden / -ExecutionPolicy Bypass chỉ đáng ngờ khi đi cùng dấu hiệu khác; 4647 tự nó không phải tấn công) -> đây không phải lượt "không có hướng dẫn".
- Ca bình thường chỉ toàn nhiễu (không gọi mô hình, không tính cho công cụ nào): 11. Ca tấn công bị bộ lọc nhiễu bỏ hết sự kiện (giữ lại, tính là bỏ sót nếu được chấm): `dbc_mimikatz_tokenelevate`.
- Bảng chính chấm trên ca có kết quả của mọi công cụ; công cụ lỗi trên ca nào thì tính là công cụ đó không báo (cột "Lỗi"). Thiếu 4 ca không dựng được (antivirus chặn / công cụ không có dữ liệu): `dbc_metasploit_psexec_powershell`, `dbc_metasploit_psexec_powershell_system`, `dbc_obfuscation_encoding`, `dbc_obfuscation_many`.
- Bảng phụ (cuối mục 1) bỏ thêm 0 ca có công cụ lỗi: không có.

## 0. Phễu số liệu và prompt đã khoá

- Nguồn: Security.evtx 28,343, Microsoft-Windows-PowerShell_Operational.evtx 1,121, Windows PowerShell.evtx 3,553 (mốc chia 2026-11-22 00:00).

| | Phần chỉnh (dev) | Phần kiểm tra (test) |
|---|---:|---:|
| Tổng sự kiện | 10,340 | 22,677 |
| Sự kiện thuộc ID được đọc (trước bộ lọc nhiễu) | 1,440 | 2,959 |
| Còn lại sau bộ lọc nhiễu (luật / AI thấy) | 659 | 1,299 |
| Cửa sổ 10 phút (= số ca) | 98 | 62 |

- Prompt khoá lúc 2026-11-25T05:16:01+00:00 (commit `e9e3c8b`, sha tính trên bản checkout Windows CRLF): SHA-256 `analyze.py` `97582d4c557fb035a53301cfecc29fcdf7b41106ab59aa2ce4cb1f7b19f75b6c`, prompt `97393994e65506db2b79787c7aaf31606ed1c8873d364b80bfe2b6d41b9d8637`, prompt đối chứng `e196f062e8286e5ec3b54547c2d472b332dfa6f1827304d90d92e3005a553636`; Ollama 0.40.18, GPU Tesla T4.

## 1. Tổng hợp (phần kiểm tra)

| Công cụ | Bắt tấn công `scored` | Bắt `coverage` | Báo nhầm trên ca bình thường | REVIEW/UNKNOWN (bình thường) | Lỗi | Precision | F1 | TG trung vị/ca |
|---|---|---|---|:---:|:---:|:---:|:---:|:---:|
| Qwen 2.5 3B (luật + AI) | 69.2% (9/13; KTC95% 42%–87%) | 2/2 | 19.6% (10/51; KTC95% 11%–32%) | 1 | 0 | 52.4% | 0.611 | 8.95s |
| Llama 3.2 3B (luật + AI) | 69.2% (9/13; KTC95% 42%–87%) | 2/2 | 33.3% (17/51; KTC95% 22%–47%) | 10 | 0 | 39.3% | 0.512 | 11.97s |
| Qwen 2.5 3B — đối chứng (bỏ cột bình thường) | 69.2% (9/13; KTC95% 42%–87%) | 2/2 | 19.6% (10/51; KTC95% 11%–32%) | 3 | 0 | 52.4% | 0.611 | 9.06s |
| Llama 3.2 3B — đối chứng (bỏ cột bình thường) | 76.9% (10/13; KTC95% 50%–92%) | 2/2 | 27.5% (14/51; KTC95% 17%–41%) | 13 | 0 | 46.2% | 0.585 | 14.48s |
| Luật của nhóm (không AI) | 61.5% (8/13; KTC95% 36%–82%) | 2/2 | 0.0% (0/51; KTC95% 0%–7%) | 0 | 0 | 100.0% | 0.800 | 0.01s |
| DeepBlueCLI (công cụ thật) | 76.9% (10/13; KTC95% 50%–92%) | 2/2 | 35.3% (18/51; KTC95% 24%–49%) | 0 | 0 | 40.0% | 0.533 | 0.23s |
| Hayabusa + Sigma (công cụ thật, mức >= medium) | 76.9% (10/13; KTC95% 50%–92%) | 2/2 | 29.4% (15/51; KTC95% 19%–43%) | 0 | 0 | 44.4% | 0.571 | 0.16s |
| Sigma mô phỏng (regex) | 53.8% (7/13; KTC95% 29%–77%) | 1/2 | 11.8% (6/51; KTC95% 6%–23%) | 0 | 0 | 57.1% | 0.552 | 0.01s |

**Bảng phụ: chỉ ca mọi công cụ chạy không lỗi** (cách chấm của các báo cáo trước)

| Công cụ | Bắt tấn công `scored` | Bắt `coverage` | Báo nhầm trên ca bình thường | REVIEW/UNKNOWN (bình thường) | Lỗi | Precision | F1 | TG trung vị/ca |
|---|---|---|---|:---:|:---:|:---:|:---:|:---:|
| Qwen 2.5 3B (luật + AI) | 69.2% (9/13; KTC95% 42%–87%) | 2/2 | 19.6% (10/51; KTC95% 11%–32%) | 1 | 0 | 52.4% | 0.611 | 8.95s |
| Llama 3.2 3B (luật + AI) | 69.2% (9/13; KTC95% 42%–87%) | 2/2 | 33.3% (17/51; KTC95% 22%–47%) | 10 | 0 | 39.3% | 0.512 | 11.97s |
| Qwen 2.5 3B — đối chứng (bỏ cột bình thường) | 69.2% (9/13; KTC95% 42%–87%) | 2/2 | 19.6% (10/51; KTC95% 11%–32%) | 3 | 0 | 52.4% | 0.611 | 9.06s |
| Llama 3.2 3B — đối chứng (bỏ cột bình thường) | 76.9% (10/13; KTC95% 50%–92%) | 2/2 | 27.5% (14/51; KTC95% 17%–41%) | 13 | 0 | 46.2% | 0.585 | 14.48s |
| Luật của nhóm (không AI) | 61.5% (8/13; KTC95% 36%–82%) | 2/2 | 0.0% (0/51; KTC95% 0%–7%) | 0 | 0 | 100.0% | 0.800 | 0.01s |
| DeepBlueCLI (công cụ thật) | 76.9% (10/13; KTC95% 50%–92%) | 2/2 | 35.3% (18/51; KTC95% 24%–49%) | 0 | 0 | 40.0% | 0.533 | 0.23s |
| Hayabusa + Sigma (công cụ thật, mức >= medium) | 76.9% (10/13; KTC95% 50%–92%) | 2/2 | 29.4% (15/51; KTC95% 19%–43%) | 0 | 0 | 44.4% | 0.571 | 0.16s |
| Sigma mô phỏng (regex) | 53.8% (7/13; KTC95% 29%–77%) | 1/2 | 11.8% (6/51; KTC95% 6%–23%) | 0 | 0 | 57.1% | 0.552 | 0.01s |

## 2. Ca bình thường bị báo nhầm

**Qwen 2.5 3B (luật + AI):** `lam_full_20261122_1350`, `lam_full_20261122_1410`, `lam_full_20261122_2050`, `lam_full_20261123_0730`, `lam_full_20261123_1110`, `lam_full_20261123_1820`, `lam_full_20261123_1830`, `lam_full_20261123_1840`, `lam_full_20261124_1910`, `lam_full_20261124_1920`
  - `lam_full_20261122_1350`: Credential Access Attempt; Privilege Escalation; Persistence Mechanism Creation
  - `lam_full_20261122_1410`: 
  - `lam_full_20261122_2050`: 
  - `lam_full_20261123_0730`: OS Credential Dumping
  - `lam_full_20261123_1110`: Privilege Escalation; Persistence; PowerShell ScriptBlock Execution
  - `lam_full_20261123_1820`: 
  - `lam_full_20261123_1830`: PowerShell ScriptBlock Execution
  - `lam_full_20261123_1840`: NORMAL; PowerShell ScriptBlock Execution
  - `lam_full_20261124_1910`: 
  - `lam_full_20261124_1920`: OS Credential Dumping

**Llama 3.2 3B (luật + AI):** `lam_full_20261122_1340`, `lam_full_20261122_1420`, `lam_full_20261122_1450`, `lam_full_20261123_0730`, `lam_full_20261123_0800`, `lam_full_20261123_0820`, `lam_full_20261123_0830`, `lam_full_20261123_0840`, `lam_full_20261123_0850`, `lam_full_20261123_0920`, `lam_full_20261123_0950`, `lam_full_20261123_1810`, `lam_full_20261123_1820`, `lam_full_20261123_1830`, `lam_full_20261123_1840`, `lam_full_20261123_1850`, `lam_full_20261124_1910`
  - `lam_full_20261122_1340`: 
  - `lam_full_20261122_1420`: 
  - `lam_full_20261122_1450`: 
  - `lam_full_20261123_0730`: 
  - `lam_full_20261123_0800`: 
  - `lam_full_20261123_0820`: 
  - `lam_full_20261123_0830`: 
  - `lam_full_20261123_0840`: 
  - `lam_full_20261123_0850`: 
  - `lam_full_20261123_0920`: 
  - `lam_full_20261123_0950`: 
  - `lam_full_20261123_1810`: 
  - `lam_full_20261123_1820`: 
  - `lam_full_20261123_1830`: 
  - `lam_full_20261123_1840`: 

**Qwen 2.5 3B — đối chứng (bỏ cột bình thường):** `lam_full_20261122_1350`, `lam_full_20261122_2050`, `lam_full_20261123_0730`, `lam_full_20261123_0820`, `lam_full_20261123_1000`, `lam_full_20261123_1110`, `lam_full_20261123_1820`, `lam_full_20261123_1830`, `lam_full_20261124_1910`, `lam_full_20261124_1920`
  - `lam_full_20261122_1350`: Credential Access Attempt; Privilege Escalation; Persistence Mechanism Creation
  - `lam_full_20261122_2050`: 
  - `lam_full_20261123_0730`: OS Credential Dumping
  - `lam_full_20261123_0820`: Persistence
  - `lam_full_20261123_1000`: 
  - `lam_full_20261123_1110`: Persistence; PowerShell Execution
  - `lam_full_20261123_1820`: OS Credential Dumping
  - `lam_full_20261123_1830`: PowerShell ScriptBlock Execution
  - `lam_full_20261124_1910`: 
  - `lam_full_20261124_1920`: OS Credential Dumping; Malware Execution

**Llama 3.2 3B — đối chứng (bỏ cột bình thường):** `lam_full_20261122_1340`, `lam_full_20261122_1400`, `lam_full_20261122_1450`, `lam_full_20261122_1940`, `lam_full_20261123_0730`, `lam_full_20261123_0820`, `lam_full_20261123_0830`, `lam_full_20261123_0840`, `lam_full_20261123_0850`, `lam_full_20261123_1000`, `lam_full_20261123_1100`, `lam_full_20261123_1110`, `lam_full_20261123_1810`, `lam_full_20261124_1910`
  - `lam_full_20261122_1340`: 
  - `lam_full_20261122_1400`: 
  - `lam_full_20261122_1450`: 
  - `lam_full_20261122_1940`: 
  - `lam_full_20261123_0730`: 
  - `lam_full_20261123_0820`: 
  - `lam_full_20261123_0830`: 
  - `lam_full_20261123_0840`: 
  - `lam_full_20261123_0850`: 
  - `lam_full_20261123_1000`: 
  - `lam_full_20261123_1100`: 
  - `lam_full_20261123_1110`: 
  - `lam_full_20261123_1810`: 
  - `lam_full_20261124_1910`: 

**Luật của nhóm (không AI):** không có

**DeepBlueCLI (công cụ thật):** `lam_full_20261122_1350`, `lam_full_20261122_1400`, `lam_full_20261122_1450`, `lam_full_20261122_1940`, `lam_full_20261123_0730`, `lam_full_20261123_0740`, `lam_full_20261123_0820`, `lam_full_20261123_0830`, `lam_full_20261123_0900`, `lam_full_20261123_0940`, `lam_full_20261123_0950`, `lam_full_20261123_1110`, `lam_full_20261123_1820`, `lam_full_20261123_1830`, `lam_full_20261123_1840`, `lam_full_20261124_1910`, `lam_full_20261124_1920`, `lam_full_20261124_1930`
  - `lam_full_20261122_1350`: Suspicious Command Line; Multiple admin logons for one account
  - `lam_full_20261122_1400`: Suspicious Command Line; Multiple admin logons for one account
  - `lam_full_20261122_1450`: Multiple admin logons for one account
  - `lam_full_20261122_1940`: Suspicious Command Line; Multiple admin logons for one account
  - `lam_full_20261123_0730`: Suspicious Command Line; Multiple admin logons for one account
  - `lam_full_20261123_0740`: Multiple admin logons for one account
  - `lam_full_20261123_0820`: Suspicious Command Line
  - `lam_full_20261123_0830`: Suspicious Command Line
  - `lam_full_20261123_0900`: Multiple admin logons for one account
  - `lam_full_20261123_0940`: Multiple admin logons for one account
  - `lam_full_20261123_0950`: Multiple admin logons for one account
  - `lam_full_20261123_1110`: Suspicious Command Line
  - `lam_full_20261123_1820`: Suspicious Command Line; Multiple admin logons for one account
  - `lam_full_20261123_1830`: Suspicious Command Line
  - `lam_full_20261123_1840`: Suspicious Command Line

**Hayabusa + Sigma (công cụ thật, mức >= medium):** `lam_full_20261122_1350`, `lam_full_20261122_1400`, `lam_full_20261122_1410`, `lam_full_20261122_1940`, `lam_full_20261123_0730`, `lam_full_20261123_0810`, `lam_full_20261123_0820`, `lam_full_20261123_0830`, `lam_full_20261123_1110`, `lam_full_20261123_1820`, `lam_full_20261123_1830`, `lam_full_20261123_1840`, `lam_full_20261123_1900`, `lam_full_20261124_1920`, `lam_full_20261124_1930`
  - `lam_full_20261122_1350`: [med] Potentially Malicious PwSh
  - `lam_full_20261122_1400`: [med] Potentially Malicious PwSh
  - `lam_full_20261122_1410`: [med] Suspicious Non PowerShell WSMAN COM Provider; [med] Uncommon PowerShell Hosts
  - `lam_full_20261122_1940`: [med] Potentially Malicious PwSh
  - `lam_full_20261123_0730`: [med] Potentially Malicious PwSh
  - `lam_full_20261123_0810`: [med] Potentially Malicious PwSh
  - `lam_full_20261123_0820`: [med] Potentially Malicious PwSh
  - `lam_full_20261123_0830`: [med] Potentially Malicious PwSh
  - `lam_full_20261123_1110`: [med] Potentially Malicious PwSh
  - `lam_full_20261123_1820`: [med] Potentially Malicious PwSh
  - `lam_full_20261123_1830`: [med] Potentially Malicious PwSh
  - `lam_full_20261123_1840`: [med] Potentially Malicious PwSh
  - `lam_full_20261123_1900`: [med] Potentially Malicious PwSh
  - `lam_full_20261124_1920`: [med] Potentially Malicious PwSh
  - `lam_full_20261124_1930`: [med] Potentially Malicious PwSh

**Sigma mô phỏng (regex):** `lam_full_20261123_0820`, `lam_full_20261123_0830`, `lam_full_20261123_1110`, `lam_full_20261123_1830`, `lam_full_20261123_1840`, `lam_full_20261124_1930`
  - `lam_full_20261123_0820`: Sigma [proc_creation_win_powershell_encoded]: Encoded PowerShell Command Line
  - `lam_full_20261123_0830`: Sigma [proc_creation_win_powershell_encoded]: Encoded PowerShell Command Line
  - `lam_full_20261123_1110`: Sigma [proc_creation_win_powershell_encoded]: Encoded PowerShell Command Line
  - `lam_full_20261123_1830`: Sigma [proc_creation_win_powershell_encoded]: Encoded PowerShell Command Line
  - `lam_full_20261123_1840`: Sigma [proc_creation_win_powershell_encoded]: Encoded PowerShell Command Line
  - `lam_full_20261124_1930`: Sigma [proc_creation_win_schtasks_persistence]: Scheduled Task Persistence

## 3. Từng ca tấn công

| Ca | Nhóm | Qwen 2.5 3B (luật + AI) | Llama 3.2 3B (luật + AI) | Qwen 2.5 3B — đối chứng (bỏ cột bình thường) | Llama 3.2 3B — đối chứng (bỏ cột bình thường) | Luật của nhóm (không AI) | DeepBlueCLI (công cụ thật) | Hayabusa + Sigma (công cụ thật, mức >= medium) | Sigma mô phỏng (regex) |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `dbc_metasploit_psexec_native` | scored | NORMAL | NORMAL | NORMAL | NORMAL | NORMAL | ALERT | ALERT | NORMAL |
| `dbc_password_spray` | scored | NORMAL | ALERT | NORMAL | ALERT | NORMAL | ALERT | ALERT | NORMAL |
| `dbc_obfuscation_string` | scored | ALERT | ALERT | ALERT | ALERT | ALERT | ALERT | ALERT | ALERT |
| `dbc_powersploit_security` | scored | ALERT | ALERT | ALERT | ALERT | ALERT | ALERT | ALERT | ALERT |
| `dbc_powersploit_system` | scored | ALERT | ALERT | ALERT | ALERT | ALERT | ALERT | ALERT | ALERT |
| `dbc_psattack` | scored | ALERT | NORMAL | ALERT | NORMAL | NORMAL | ALERT | ALERT | NORMAL |
| `dbc_sliver_c2` | scored | ALERT | ALERT | ALERT | ALERT | ALERT | ALERT | ALERT | NORMAL |
| `dbc_smb_password_guessing` | scored | ALERT | ALERT | ALERT | ALERT | ALERT | ALERT | ALERT | ALERT |
| `e2m_local_bruteforce` | scored | ALERT | ALERT | ALERT | ALERT | ALERT | ALERT | NORMAL | ALERT |
| `e2m_openssh_bruteforce_nonexist` | scored | ALERT | ALERT | ALERT | ALERT | ALERT | NORMAL | NORMAL | ALERT |
| `e2m_openssh_bruteforce_valid` | scored | ALERT | ALERT | ALERT | ALERT | ALERT | NORMAL | NORMAL | ALERT |
| `e2m_openssh_install` | scored | NORMAL | UNKNOWN | NORMAL | UNKNOWN | NORMAL | NORMAL | ALERT | NORMAL |
| `e2m_openssh_activation` | scored | NORMAL | UNKNOWN | NORMAL | ALERT | NORMAL | ALERT | ALERT | NORMAL |
| `dbc_metasploit_psexec_native_system` | coverage | ALERT | ALERT | ALERT | ALERT | ALERT | ALERT | ALERT | NORMAL |
| `dbc_new_user_admin_group` | coverage | ALERT | ALERT | ALERT | ALERT | ALERT | ALERT | ALERT | ALERT |

## 3b. Ca không chấm điểm (insufficient_evidence / unlabeled)

Không tính vào bảng trên: log agent thu không đủ dấu vết để gán nhãn chắc (`insufficient_evidence`) hoặc chưa gán nhãn (`unlabeled`). `–` = công cụ không có kết quả cho ca này.

| Ca | Nhóm | Nhãn | Qwen 2.5 3B (luật + AI) | Llama 3.2 3B (luật + AI) | Qwen 2.5 3B — đối chứng (bỏ cột bình thường) | Llama 3.2 3B — đối chứng (bỏ cột bình thường) | Luật của nhóm (không AI) | DeepBlueCLI (công cụ thật) | Hayabusa + Sigma (công cụ thật, mức >= medium) | Sigma mô phỏng (regex) |
|---|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `dbc_metasploit_pwshpayload` | insufficient_evidence | ALERT | NORMAL | NORMAL | NORMAL | NORMAL | NORMAL | NORMAL | NORMAL | NORMAL |
| `dbc_mimikatz_tokenelevate` | insufficient_evidence | ALERT | NOISE_ONLY | NOISE_ONLY | NOISE_ONLY | NOISE_ONLY | NOISE_ONLY | NORMAL | NORMAL | NOISE_ONLY |
| `dbc_many_events_security` | unlabeled | UNKNOWN | ALERT | ALERT | ALERT | ALERT | ALERT | ALERT | ALERT | ALERT |
| `dbc_many_events_system` | unlabeled | UNKNOWN | – | – | – | – | – | ALERT | ALERT | – |

<!-- VIET_TAY: phần từ dòng này trở xuống viết tay, chạy lại --report vẫn giữ nguyên -->

## 4. Nhận xét (viết tay; `--report` giữ nguyên mục 4–6)

**Bỏ cột "hoạt động bình thường" không làm kết quả khác đi.**
- Qwen: báo nhầm 10/51 ở cả hai lượt (UNKNOWN 1 so với 3).
- Llama: báo nhầm 17/51 khi có cột này, 14/51 khi bỏ; bắt tấn công 9/13 so với 10/13.
- Chênh của Llama (3/51) chỉ hơi lớn hơn mức dao động khi chạy lại (khoảng 1/24, mục 5), và lại theo hướng bỏ cột thì báo nhầm ít hơn. Chưa đủ để nói cột này có tác dụng.
- Lượt đối chứng vẫn giữ các điều kiện lọc đã chỉnh trên dev trong cột dấu hiệu tấn công (xem đầu báo cáo). Vì vậy kết quả chỉ nói được: phần mô tả "hoạt động bình thường" không có tác dụng thêm. Chưa đo prompt hoàn toàn không có hướng dẫn.

**Cách chấm mục 1 đã sửa (26/11).** Báo cáo cũ bỏ 5 cửa sổ bình thường có nhiều PowerShell mã hoá vì DeepBlueCLI "lỗi". Thật ra script chạy thử của nhóm (`run_deepblue.ps1`) đã dừng DeepBlueCLI ngay ở lỗi giải mã base64 đầu tiên; chạy đúng cách thì DeepBlueCLI báo ALERT cả 5 cửa sổ. Sau khi sửa, mọi công cụ chạy được trên đủ 51 cửa sổ nên bảng chính và bảng phụ giống nhau. Báo nhầm của DeepBlueCLI là 18/51, cao nhất trong các công cụ; 5 cửa sổ này cũng chứa nhiều báo nhầm của AI, Hayabusa và Sigma mô phỏng.

**Thêm nhóm Event ID mới làm báo nhầm tăng mạnh.** So với lượt 24/11 (chỉ 12 ID agent thu, chạy trên laptop) trên đúng 55 cửa sổ 10 phút có ở cả hai lượt (22–24/11, đã bỏ 5 ca công cụ lỗi):

| Báo nhầm trên 55 cửa sổ chung | 24/11, 12 ID | 25/11, có cột bình thường | 25/11, đối chứng |
|---|:---:|:---:|:---:|
| Qwen 2.5 3B | 2 | 7 | 7 |
| Llama 3.2 3B | 1 | 12 | 11 |

- Luật của nhóm vẫn 0 báo nhầm ở cả hai lượt.
- Bắt tấn công (13 ca chấm) so với 24/11: Qwen 9/13 → 9/13; Llama 11/13 → 9/13 (mất `e2m_openssh_install`, `e2m_openssh_activation`: ALERT → UNKNOWN). Không bắt thêm ca nào.
- Hai lượt còn khác nhau ở máy chạy và ở bước ẩn danh tên tài khoản (mục 6), nên mức tăng không hoàn toàn do bộ ID.
- Ở phần chỉnh (dev), lý do báo nhầm là: liệt kê nhóm / tài khoản chỉ để đọc (4798/4799), đặc quyền khi đăng nhập dịch vụ (4672), đọc kho Windows Hello (5382), PowerShell 400 có `-ExecutionPolicy Bypass`. Phần kiểm tra chưa đọc lời giải thích từng ca.
- Qwen chép nguyên câu trong hướng dẫn vào ô giai đoạn tấn công (`dbc_sliver_c2_full`): hướng dẫn dài làm mô hình 3B lẫn hướng dẫn với dữ liệu.

**Kết luận cho hệ thống:** giữ agent thu 12 ID như hiện tại, không đưa nhóm ID mới vào prompt. Viết thêm mô tả vào prompt chưa cho thấy tác dụng với mô hình 3B → bước tiếp theo là fine-tune (chốt 25/11): chỉ huấn luyện trên ca trước 22/11, phần kiểm tra này chỉ dùng để đo lần cuối.

## 5. Độ dao động khi chạy lại (12 ca kiểm tra × 2 mô hình, cùng Colab T4)

| Cách chạy lại, so với lượt trên | Thời gian | Nhãn đổi | Lời giải thích từng lô giống hệt |
|---|:---:|:---:|:---:|
| Y cách cũ (lần lượt, nhả model sau mỗi lô) | ~10 phút | 1/24 | 19/24 |
| 2 mô hình song song | ~9 phút | 2/24 | 13/24 |
| Song song + giữ mô hình trong VRAM 30 phút | ~8 phút | 3/24 | 7/24 |

- Nhiệt độ 0 vẫn không tái lập tuyệt đối: chạy lại y hệt vẫn lệch 1/24 nhãn (`lam_full_20261122_1940`, Llama UNKNOWN ↔ NORMAL). Số liệu một lần chạy có thể lệch khoảng 1 ca/24.
- Song song / giữ mô hình làm lệch nhiều hơn mà chỉ nhanh hơn 10–25% (T4 đã chạy ~100% với một mô hình) → không dùng cho số liệu. Công cụ so: `eval_real/compare_runs.py`.

## 6. Hạn chế

Khi đọc số liệu ở trên cần nhớ các điểm sau. Cột cuối là cách sửa đã chốt ngày 25/11.

| # | Hạn chế | Ảnh hưởng tới kết luận | Cách sửa |
|---|---|---|---|
| 1 | Người viết hướng dẫn đã xem thống kê tổng của cả 4 ngày (số lượng theo Event ID, tiến trình gọi 4798/4799) trước khi chia dev / test. | Phần kiểm tra không hoàn toàn "chưa nhìn thấy". Danh sách nhiễu viết theo tài liệu Microsoft / MITRE nên ảnh hưởng nhỏ, nhưng không loại trừ được. | Lượt sau thu log **sau** khi khoá prompt, từ máy khác (laptop thành viên khác hoặc máy ảo lab). |
| 2 | Lượt đối chứng chỉ bỏ cột "hoạt động bình thường"; cột dấu hiệu tấn công vẫn giữ điều kiện đã chỉnh trên dev. | Chỉ kết luận được: cột "bình thường" không có tác dụng thêm. Chưa đo prompt hoàn toàn không có hướng dẫn. | Thêm nhánh bỏ hẳn hướng dẫn của nhóm ID mới, khoá lại, chạy cùng lượt bản gốc của đợt fine-tune. |
| 3 | Log bình thường của một máy, một người, 4 ngày; chỉ 13 ca tấn công được chấm điểm. | Khoảng tin cậy rộng (bắt tấn công 42–87%). Chênh 1–2 ca giữa hai công cụ không có ý nghĩa. | Kiểm tra thêm trên EVTX-ATTACK-SAMPLES (chưa dùng lần nào); thu khoảng 10 phiên log bình thường trên máy ảo. |
| 4 | So với lượt 24/11 đổi cùng lúc 3 thứ: bộ Event ID, máy chạy (Colab T4 thay laptop), tên tài khoản (`USERxx` thay tên thật). | Mức tăng báo nhầm (55 cửa sổ chung: Qwen 2 → 7, Llama 1 → 12) không gán hết được cho bộ ID, dù lớn hơn nhiều so với dao động khi chạy lại (1/24). | Chạy bản 12 ID trên Colab T4 với cùng ca đã ẩn danh, để chỉ còn khác bộ ID. Từ lần đóng gói sau, `colab_pack.py` dùng tên giả giống thật (tài khoản dịch vụ thành `svcappNN`). |
| 5 | Mỗi cấu hình chạy một lần. Chạy lại y hệt vẫn lệch khoảng 1/24 nhãn (mục 5). | Mỗi con số có sai số khoảng ±1 ca trên 24. | Lượt so sánh cuối của đợt fine-tune chạy 3 lần, báo trung bình và khoảng dao động. |
| 6 | Agent thật chỉ thu 12 ID; nhóm ID mới mới có trong thí nghiệm offline. | Kết quả chưa phản ánh hệ thống đang chạy. | Giữ agent 12 ID. Chỉ khi bản fine-tune đọc ID mới mà không tăng báo nhầm thì mới bàn với Lâm sửa `client_agent.ps1`. |
| 7 | Bỏ 5379 (đọc Credential Manager) vì quá nhiều và không có tên tiến trình, chỉ có PID. | Không thấy được kiểu đánh cắp Credential Manager chỉ để lại 5379. | Ghép 5379 với 4688 cùng PID để biết tên tiến trình; coi nhiều 5379 trong thời gian ngắn do tiến trình lạ là tín hiệu yếu (REVIEW). Cần dữ liệu tấn công thật để kiểm. |
| 8 | Chỉ 4/19 ca tấn công có sự kiện thuộc nhóm ID mới (4672 ở `dbc_sliver_c2`, `e2m_openssh_bruteforce_nonexist`; 4103 ở hai ca OpenSSH). Không ca nào có 4798/4799, 400/800, 4738, 4797, 5382, 4616, 1100, 4719. | Thí nghiệm chỉ đo được tác động của nhóm ID mới lên báo nhầm, **không kiểm được** chúng có giúp bắt tấn công hay không. Riêng 2 ca OpenSSH bị ngập 4103 làm Llama chuyển ALERT → UNKNOWN. | Kiểm tra trên EVTX-ATTACK-SAMPLES / Mordor, chọn ca có những ID này (trinh sát nhóm → 4798/4799, đổi chính sách audit → 4719, đổi giờ hệ thống → 4616), chốt nhãn trước khi chạy. |

**Thay đổi sau lượt này.** Số liệu ở trên là của bản khoá (commit `e9e3c8b`); các thay đổi dưới đây không làm đổi số đó.
- `analyze.py`: bộ lọc 4798/4799 chỉ tin file nằm ngay trong System32 / SysWOW64; ID mới chỉ đọc từ đúng kênh log; hướng dẫn coi `net localgroup administrators` đứng một mình là trinh sát. Trên 308 ca, phần luật / AI thấy không đổi, chỉ câu chữ hướng dẫn 4798/4799 khác.
- Báo cáo: bảng chính chấm đủ 51 cửa sổ (công cụ lỗi tính là không báo); bảng phụ giữ cách chấm cũ (46 cửa sổ).
- `run_deepblue.ps1` (26/11): không bọc DeepBlueCLI trong `try` + `Stop` nữa. Chạy lại DeepBlueCLI trên máy: 5 cửa sổ trước kia "lỗi" đều ALERT, các ca khác giữ nguyên nhãn. Hayabusa chạy lại không đổi nhãn nào; cột thời gian giờ là thời gian trên mỗi ca (0,16 s) thay vì tổng thời gian cả thư mục (8,3 s).
- Hệ thống thật mặc định tắt nhóm ID mới (`ENABLE_EXTENDED_IDS=0`); `run_combined_eval.py --set full` tự bật.
