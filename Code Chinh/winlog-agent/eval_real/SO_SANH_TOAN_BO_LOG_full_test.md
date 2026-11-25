# Test toàn bộ log máy thật, có hướng dẫn nhận biết nhiễu (25/11/2026)

- Thiết kế: `md/THIET_KE_TEST_TOAN_BO_LOG_25112026.md`. Hướng dẫn nhiễu chỉnh trên log **trước 22/11**, khoá, rồi mới chạy phần **kiểm tra 22–24/11** dưới đây.
- **Tấn công:** ca `labels.json` dựng lại với cả Event ID mới (bản `_full`). **Bình thường:** log laptop thật của một thành viên, cửa sổ 10 phút, đã ẩn danh.
- Qwen / Llama / luật nhóm thấy 12 ID agent thu + nhóm ID mới (4798/4799/4672/5382/4797/4738/4647/4616/1100/4719/4103/400/800); ID chỉ toàn nhiễu bị bỏ ở mức code. DeepBlueCLI và Hayabusa đọc **toàn bộ** evtx của cùng cửa sổ (DeepBlueCLI không đọc được log "Windows PowerShell" cổ điển).
- Ca DeepBlueCLI / Hayabusa chỉ phát hiện "Log Clear" tính là NORMAL. Sigma mô phỏng = regex trong `core/rule_baselines.py`.
- UNKNOWN / REVIEW: với ca tấn công tính là bỏ sót; với ca bình thường không tính là báo nhầm (ghi riêng).
- Đối chứng (`NOISE_GUIDANCE=0`) chỉ bỏ cột "hoạt động bình thường" của nhóm ID mới. Cột dấu hiệu tấn công vẫn giữ các điều kiện đã chỉnh trên phần dev (4798/4799 chỉ là đọc; -w hidden / -ExecutionPolicy Bypass chỉ đáng ngờ khi đi cùng dấu hiệu khác; 4647 tự nó không phải tấn công) -> đây không phải lượt "không có hướng dẫn".
- Ca bình thường chỉ toàn nhiễu (không gọi mô hình, không tính cho công cụ nào): 11. Ca tấn công bị bộ lọc nhiễu bỏ hết sự kiện (giữ lại, tính là bỏ sót nếu được chấm): `dbc_mimikatz_tokenelevate`.
- Mọi công cụ được chấm trên cùng tập ca. Loại 9 ca có công cụ lỗi / bị antivirus chặn: `dbc_metasploit_psexec_powershell`, `dbc_metasploit_psexec_powershell_system`, `dbc_obfuscation_encoding`, `dbc_obfuscation_many`, `lam_full_20261123_0820`, `lam_full_20261123_0830`, `lam_full_20261123_1110`, `lam_full_20261123_1830`, `lam_full_20261123_1840`

## 0. Phễu số liệu và prompt đã khoá

- Nguồn: Security.evtx 28,343, Microsoft-Windows-PowerShell_Operational.evtx 1,121, Windows PowerShell.evtx 3,553 (mốc chia 2026-11-22 00:00).

| | Phần chỉnh (dev) | Phần kiểm tra (test) |
|---|---:|---:|
| Tổng sự kiện | 10,340 | 22,677 |
| Sự kiện được đọc (bỏ ID chỉ toàn nhiễu) | 1,440 | 2,959 |
| Cửa sổ 10 phút (= số ca) | 98 | 62 |

- Prompt khoá lúc 2026-11-25T05:16:01+00:00: SHA-256 `analyze.py` `97582d4c557fb035a53301cfecc29fcdf7b41106ab59aa2ce4cb1f7b19f75b6c`, prompt `97393994e65506db2b79787c7aaf31606ed1c8873d364b80bfe2b6d41b9d8637`, prompt đối chứng `e196f062e8286e5ec3b54547c2d472b332dfa6f1827304d90d92e3005a553636`; Ollama ollama version is 0.40.18, GPU Tesla T4.

## 1. Tổng hợp (phần kiểm tra)

| Công cụ | Bắt tấn công `scored` | Bắt `coverage` | Báo nhầm trên ca bình thường | REVIEW/UNKNOWN (bình thường) | Precision | F1 | TG trung vị/ca |
|---|---|---|---|:---:|:---:|:---:|:---:|
| Qwen 2.5 3B (luật + AI) | 69.2% (9/13; KTC95% 42%–87%) | 2/2 | 15.2% (7/46; KTC95% 8%–28%) | 0 | 61.1% | 0.667 | 8.61s |
| Llama 3.2 3B (luật + AI) | 69.2% (9/13; KTC95% 42%–87%) | 2/2 | 28.3% (13/46; KTC95% 17%–43%) | 9 | 45.8% | 0.564 | 11.63s |
| Qwen 2.5 3B — đối chứng (bỏ cột bình thường) | 69.2% (9/13; KTC95% 42%–87%) | 2/2 | 15.2% (7/46; KTC95% 8%–28%) | 2 | 61.1% | 0.667 | 8.59s |
| Llama 3.2 3B — đối chứng (bỏ cột bình thường) | 76.9% (10/13; KTC95% 50%–92%) | 2/2 | 23.9% (11/46; KTC95% 14%–38%) | 11 | 52.2% | 0.632 | 11.73s |
| Luật của nhóm (không AI) | 61.5% (8/13; KTC95% 36%–82%) | 2/2 | 0.0% (0/46; KTC95% 0%–8%) | 0 | 100.0% | 0.800 | 0.01s |
| DeepBlueCLI (công cụ thật) | 76.9% (10/13; KTC95% 50%–92%) | 2/2 | 28.3% (13/46; KTC95% 17%–43%) | 0 | 48.0% | 0.600 | 0.22s |
| Hayabusa + Sigma (công cụ thật, mức >= medium) | 76.9% (10/13; KTC95% 50%–92%) | 2/2 | 21.7% (10/46; KTC95% 12%–36%) | 0 | 54.5% | 0.649 | 8.30s |
| Sigma mô phỏng (regex) | 53.8% (7/13; KTC95% 29%–77%) | 1/2 | 2.2% (1/46; KTC95% 0%–11%) | 0 | 88.9% | 0.667 | 0.01s |

## 2. Ca bình thường bị báo nhầm

**Qwen 2.5 3B (luật + AI):** `lam_full_20261122_1350`, `lam_full_20261122_1410`, `lam_full_20261122_2050`, `lam_full_20261123_0730`, `lam_full_20261123_1820`, `lam_full_20261124_1910`, `lam_full_20261124_1920`
  - `lam_full_20261122_1350`: Credential Access Attempt; Privilege Escalation; Persistence Mechanism Creation
  - `lam_full_20261122_1410`: 
  - `lam_full_20261122_2050`: 
  - `lam_full_20261123_0730`: OS Credential Dumping
  - `lam_full_20261123_1820`: 
  - `lam_full_20261124_1910`: 
  - `lam_full_20261124_1920`: OS Credential Dumping

**Llama 3.2 3B (luật + AI):** `lam_full_20261122_1340`, `lam_full_20261122_1420`, `lam_full_20261122_1450`, `lam_full_20261123_0730`, `lam_full_20261123_0800`, `lam_full_20261123_0840`, `lam_full_20261123_0850`, `lam_full_20261123_0920`, `lam_full_20261123_0950`, `lam_full_20261123_1810`, `lam_full_20261123_1820`, `lam_full_20261123_1850`, `lam_full_20261124_1910`
  - `lam_full_20261122_1340`: 
  - `lam_full_20261122_1420`: 
  - `lam_full_20261122_1450`: 
  - `lam_full_20261123_0730`: 
  - `lam_full_20261123_0800`: 
  - `lam_full_20261123_0840`: 
  - `lam_full_20261123_0850`: 
  - `lam_full_20261123_0920`: 
  - `lam_full_20261123_0950`: 
  - `lam_full_20261123_1810`: 
  - `lam_full_20261123_1820`: 
  - `lam_full_20261123_1850`: 
  - `lam_full_20261124_1910`: 

**Qwen 2.5 3B — đối chứng (bỏ cột bình thường):** `lam_full_20261122_1350`, `lam_full_20261122_2050`, `lam_full_20261123_0730`, `lam_full_20261123_1000`, `lam_full_20261123_1820`, `lam_full_20261124_1910`, `lam_full_20261124_1920`
  - `lam_full_20261122_1350`: Credential Access Attempt; Privilege Escalation; Persistence Mechanism Creation
  - `lam_full_20261122_2050`: 
  - `lam_full_20261123_0730`: OS Credential Dumping
  - `lam_full_20261123_1000`: 
  - `lam_full_20261123_1820`: OS Credential Dumping
  - `lam_full_20261124_1910`: 
  - `lam_full_20261124_1920`: OS Credential Dumping; Malware Execution

**Llama 3.2 3B — đối chứng (bỏ cột bình thường):** `lam_full_20261122_1340`, `lam_full_20261122_1400`, `lam_full_20261122_1450`, `lam_full_20261122_1940`, `lam_full_20261123_0730`, `lam_full_20261123_0840`, `lam_full_20261123_0850`, `lam_full_20261123_1000`, `lam_full_20261123_1100`, `lam_full_20261123_1810`, `lam_full_20261124_1910`
  - `lam_full_20261122_1340`: 
  - `lam_full_20261122_1400`: 
  - `lam_full_20261122_1450`: 
  - `lam_full_20261122_1940`: 
  - `lam_full_20261123_0730`: 
  - `lam_full_20261123_0840`: 
  - `lam_full_20261123_0850`: 
  - `lam_full_20261123_1000`: 
  - `lam_full_20261123_1100`: 
  - `lam_full_20261123_1810`: 
  - `lam_full_20261124_1910`: 

**Luật của nhóm (không AI):** không có

**DeepBlueCLI (công cụ thật):** `lam_full_20261122_1350`, `lam_full_20261122_1400`, `lam_full_20261122_1450`, `lam_full_20261122_1940`, `lam_full_20261123_0730`, `lam_full_20261123_0740`, `lam_full_20261123_0900`, `lam_full_20261123_0940`, `lam_full_20261123_0950`, `lam_full_20261123_1820`, `lam_full_20261124_1910`, `lam_full_20261124_1920`, `lam_full_20261124_1930`
  - `lam_full_20261122_1350`: Suspicious Command Line; Multiple admin logons for one account
  - `lam_full_20261122_1400`: Suspicious Command Line; Multiple admin logons for one account
  - `lam_full_20261122_1450`: Multiple admin logons for one account
  - `lam_full_20261122_1940`: Suspicious Command Line; Multiple admin logons for one account
  - `lam_full_20261123_0730`: Suspicious Command Line; Multiple admin logons for one account
  - `lam_full_20261123_0740`: Multiple admin logons for one account
  - `lam_full_20261123_0900`: Multiple admin logons for one account
  - `lam_full_20261123_0940`: Multiple admin logons for one account
  - `lam_full_20261123_0950`: Multiple admin logons for one account
  - `lam_full_20261123_1820`: Suspicious Command Line; Multiple admin logons for one account
  - `lam_full_20261124_1910`: Multiple admin logons for one account
  - `lam_full_20261124_1920`: Suspicious Command Line
  - `lam_full_20261124_1930`: Suspicious Command Line

**Hayabusa + Sigma (công cụ thật, mức >= medium):** `lam_full_20261122_1350`, `lam_full_20261122_1400`, `lam_full_20261122_1410`, `lam_full_20261122_1940`, `lam_full_20261123_0730`, `lam_full_20261123_0810`, `lam_full_20261123_1820`, `lam_full_20261123_1900`, `lam_full_20261124_1920`, `lam_full_20261124_1930`
  - `lam_full_20261122_1350`: [med] Potentially Malicious PwSh
  - `lam_full_20261122_1400`: [med] Potentially Malicious PwSh
  - `lam_full_20261122_1410`: [med] Suspicious Non PowerShell WSMAN COM Provider; [med] Uncommon PowerShell Hosts
  - `lam_full_20261122_1940`: [med] Potentially Malicious PwSh
  - `lam_full_20261123_0730`: [med] Potentially Malicious PwSh
  - `lam_full_20261123_0810`: [med] Potentially Malicious PwSh
  - `lam_full_20261123_1820`: [med] Potentially Malicious PwSh
  - `lam_full_20261123_1900`: [med] Potentially Malicious PwSh
  - `lam_full_20261124_1920`: [med] Potentially Malicious PwSh
  - `lam_full_20261124_1930`: [med] Potentially Malicious PwSh

**Sigma mô phỏng (regex):** `lam_full_20261124_1930`
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

## 4. Nhận xét (viết tay 25/11 — `--report` không sinh mục 4–6, chạy lại `--report` thì chép lại)

**Bỏ cột "hoạt động bình thường" không làm kết quả khác đi.**
- Qwen: báo nhầm 7/46 ở cả hai lượt (UNKNOWN 0 so với 2).
- Llama: báo nhầm 13/46 khi có cột này, 11/46 khi bỏ; bắt tấn công 9/13 so với 10/13.
- Chênh 1–2 ca nằm trong mức dao động khi chạy lại (mục 5), nên coi như không khác.
- Lượt đối chứng vẫn giữ các điều kiện lọc đã chỉnh trên dev trong cột dấu hiệu tấn công (xem đầu báo cáo). Vì vậy kết quả chỉ nói được: phần mô tả "hoạt động bình thường" không có tác dụng thêm. Chưa đo prompt hoàn toàn không có hướng dẫn.

**Tỉ lệ báo nhầm ở mục 1 thấp hơn thực tế.** Mục 1 chấm trên cùng tập ca nên bỏ 5 cửa sổ bình thường mà DeepBlueCLI lỗi (lỗi giải mã base64, tức các cửa sổ có nhiều PowerShell mã hoá). Các cửa sổ này chứa nhiều báo nhầm của AI. Tính mỗi công cụ trên đủ 51 cửa sổ bình thường (bỏ 11 cửa sổ chỉ toàn nhiễu):

| Báo nhầm trên 51 cửa sổ | Có cột bình thường | Đối chứng |
|---|:---:|:---:|
| Qwen 2.5 3B | 10/51 (19.6%) | 10/51 (19.6%) |
| Llama 3.2 3B | 17/51 (33.3%) | 14/51 (27.5%) |
| Luật của nhóm | 0/51 | — |
| Sigma mô phỏng | 6/51 (11.8%) | — |

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

- Người viết hướng dẫn đã xem thống kê tổng (số lượng theo Event ID, tiến trình gọi 4798/4799) của cả 4 ngày trước khi chia. Danh sách nhiễu dựa trên tài liệu, nhưng không loại trừ hoàn toàn ảnh hưởng.
- Đối chứng chỉ bỏ cột "hoạt động bình thường", không phải prompt không có hướng dẫn (mục 4).
- Mục 1 bỏ 5 cửa sổ DeepBlueCLI lỗi, làm tỉ lệ báo nhầm của AI trông thấp hơn (số đủ 51 cửa sổ ở mục 4).
- Log của một máy, một người dùng, 4 ngày, không có tấn công. Ca tấn công chỉ 13 ca chấm điểm → khoảng tin cậy rộng.
- Agent thật chưa thu các ID mới → đây là thí nghiệm offline.
- Mô hình chạy trên Colab (Tesla T4), khác máy với lượt 24/11 (laptop).
- Trước khi lên Colab, ca bình thường đã đổi 22 tên tài khoản / nhóm thành `USERxx`; lượt 24/11 giữ tên thật. Tên lạ kiểu `USER03` có thể làm mô hình nghi ngờ hơn. So với 24/11 đổi cùng lúc máy, bộ ID và tên nên không tách riêng được; dao động do chạy lại (1/24) nhỏ hơn nhiều so với mức tăng báo nhầm (1 → 12 ca).
- Bỏ 5379: không thấy được kiểu đánh cắp Credential Manager chỉ để lại 5379.
- Mỗi cấu hình chạy một lần (xem mục 5).
