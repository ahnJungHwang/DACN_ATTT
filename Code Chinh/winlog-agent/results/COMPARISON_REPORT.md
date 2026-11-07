# 📊 BÁO CÁO KẾT QUẢ SO SÁNH HIỆU NĂNG MÔ HÌNH SLM
**Thời gian thực nghiệm:** `2026-11-07 15:00:22`  
**Môi trường suy luận:** Ollama Local API (`http://127.0.0.1:11434/api/chat`)  

## 1. Bảng chỉ số đối chiếu tổng hợp

| Chỉ số đánh giá | **QWEN** (`qwen2.5:3b-instruct-q4_K_M`) | **LLAMA** (`llama3.2:3b-instruct-q4_K_M`) |
|---| :---: | :---: |
| **Tổng số ca kiểm thử** | 40 | 40 |
| **Độ chuẩn xác (Precision)** | 96.2% | 96.0% |
| **Độ nhạy phát hiện (Recall)** | 100.0% | 96.0% |
| **Điểm F1-Score** | 0.98 | 0.96 |
| **Độ chính xác tổng thể (Accuracy)** | 97.5% | 77.5% |
| **Báo động giả (False Positive - FP)** | 1 ca | 1 ca |
| **Bỏ sót tấn công (False Negative - FN)** | 0 ca | 1 ca |
| **Tỷ lệ xuất JSON hợp lệ (Valid JSON)** | 100.0% | 100.0% |
| **Thời gian trung vị (Median Latency)** | 4.08s | 4.2s |
| **Thời gian trung bình (Mean Latency)** | 4.25s | 4.53s |
| **Cảnh báo do Luật + AI xác nhận** | 20 ca | 8 ca |
| **Cảnh báo do AI tự phát hiện** | 2 ca | 1 ca |
| **Cảnh báo chỉ do Luật (AI không xác nhận)** | 4 ca | 16 ca |
| **[Riêng AI] Precision** | 95.5% | 88.9% |
| **[Riêng AI] Recall** | 84.0% | 32.0% |
| **[Riêng AI] F1-Score** | 0.894 | 0.471 |
| **[Riêng AI] Accuracy** | 87.5% | 37.5% |
| **[Riêng AI] Báo động giả / Bỏ sót** | 1 / 4 ca | 1 / 17 ca |

## 2. Chi tiết kết quả từng ca thử nghiệm

| Model | Case ID | Ground Truth | Hệ thống | Riêng AI | Nguồn quyết định | Kết quả | Thời gian (s) | Giai đoạn tấn công phát hiện |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|---|
| `qwen` | `case_attack_01_bruteforce` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 4.004s | Password Brute Force (MITRE T1110); Successful Logon Post-Brute Force (MITRE T1078); Password Brute Force |
| `qwen` | `case_attack_02_ps_c2_download` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 3.938s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001) |
| `qwen` | `case_attack_03_backdoor_account` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 3.924s | Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098); Backdoor Creation |
| `qwen` | `case_attack_04_mimikatz_dump` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 3.894s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Reconnaissance; System Reconnaissance (MITRE T1033) |
| `qwen` | `case_attack_05_recon_discovery` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 5.727s | Password Brute Force (MITRE T1110); Reconnaissance; System Reconnaissance (MITRE T1033) |
| `qwen` | `case_attack_06_reg_persistence` | **ALERT** | `ALERT` | `NORMAL` | rule | ✅ Đúng | 3.729s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001) |
| `qwen` | `case_attack_07_encoded_powershell` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 3.696s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001) |
| `qwen` | `case_attack_08_schtasks_persistence` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 3.694s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001) |
| `qwen` | `case_attack_09_procdump_lsass` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 4.123s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Reconnaissance; System Reconnaissance (MITRE T1033) |
| `qwen` | `case_attack_10_disable_defender` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 3.781s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001) |
| `qwen` | `case_edge_01_multi_user_one_attack` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 5.066s | Password Brute Force (MITRE T1110); Password Brute Force |
| `qwen` | `case_edge_02_admin_typo_twice` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 4.236s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_edge_03_automated_inventory_tool` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 3.728s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_edge_04_it_create_employee_account` | **NORMAL** | `ALERT` | `ALERT` | ai | ❌ Sai | 7.724s | Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098) |
| `qwen` | `case_edge_05_bruteforce_all_failed` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 3.403s | Password Brute Force (MITRE T1110) |
| `qwen` | `case_edge_06_dual_session_different_ip` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 4.129s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_edge_07_scheduled_script_failed` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 3.741s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_edge_08_guest_account_login_attempt` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 4.445s | Password Brute Force (MITRE T1110); Password Brute Force |
| `qwen` | `case_edge_09_suspicious_script_benign_name` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 3.579s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001) |
| `qwen` | `case_edge_10_remote_desktop_after_hours` | **ALERT** | `ALERT` | `NORMAL` | rule | ✅ Đúng | 4.432s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001) |
| `qwen` | `case_mixed_01_office_macro_c2` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 4.285s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Malware Execution |
| `qwen` | `case_mixed_02_bruteforce_to_backdoor` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 5.124s | Password Brute Force (MITRE T1110); Successful Logon Post-Brute Force (MITRE T1078); Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098); Password Brute Force |
| `qwen` | `case_mixed_03_recon_then_mimikatz` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 4.102s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Reconnaissance; System Reconnaissance (MITRE T1033) |
| `qwen` | `case_mixed_04_dev_malicious_package` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 4.076s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Malware Execution |
| `qwen` | `case_mixed_05_sysadmin_hijacked_session` | **ALERT** | `ALERT` | `NORMAL` | rule | ✅ Đúng | 4.235s | Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098) |
| `qwen` | `case_mixed_06_c2_and_eventlog_clear` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 3.634s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001) |
| `qwen` | `case_mixed_07_browser_exploit_payload` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 4.351s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Malware Execution |
| `qwen` | `case_mixed_08_pass_the_hash_cmd` | **ALERT** | `ALERT` | `ALERT` | ai | ✅ Đúng | 7.23s | Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098) |
| `qwen` | `case_mixed_09_stealth_persistence_run` | **ALERT** | `ALERT` | `NORMAL` | rule | ✅ Đúng | 1.868s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001) |
| `qwen` | `case_mixed_10_recon_domain_trust` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 5.184s | Password Brute Force (MITRE T1110); Reconnaissance; System Reconnaissance (MITRE T1033) |
| `qwen` | `case_normal_01_office` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 4.659s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_normal_02_sysadmin` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 4.498s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_normal_03_developer` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 4.401s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_normal_04_typo_login` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 3.948s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_normal_05_backup_script` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 3.78s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_normal_06_disk_cleanup` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 3.794s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_normal_07_browser_work` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 4.401s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_normal_08_pdf_reader` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 3.719s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_normal_09_calc_and_tools` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 3.741s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_normal_10_powershell_profile` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 4.085s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `llama` | `case_attack_01_bruteforce` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 7.18s | Password Brute Force (MITRE T1110); Successful Logon Post-Brute Force (MITRE T1078) |
| `llama` | `case_attack_02_ps_c2_download` | **ALERT** | `ALERT` | `UNKNOWN` | rule | ✅ Đúng | 4.125s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001) |
| `llama` | `case_attack_03_backdoor_account` | **ALERT** | `ALERT` | `UNKNOWN` | rule | ✅ Đúng | 3.953s | Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098) |
| `llama` | `case_attack_04_mimikatz_dump` | **ALERT** | `ALERT` | `UNKNOWN` | rule | ✅ Đúng | 3.986s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001) |
| `llama` | `case_attack_05_recon_discovery` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 4.571s | Password Brute Force (MITRE T1110); System Reconnaissance (MITRE T1033) |
| `llama` | `case_attack_06_reg_persistence` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 3.654s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); PowerShell ScriptBlock Execution |
| `llama` | `case_attack_07_encoded_powershell` | **ALERT** | `ALERT` | `UNKNOWN` | rule | ✅ Đúng | 4.039s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001) |
| `llama` | `case_attack_08_schtasks_persistence` | **ALERT** | `ALERT` | `UNKNOWN` | rule | ✅ Đúng | 4.325s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001) |
| `llama` | `case_attack_09_procdump_lsass` | **ALERT** | `ALERT` | `UNKNOWN` | rule | ✅ Đúng | 3.95s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001) |
| `llama` | `case_attack_10_disable_defender` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 3.926s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Malware Execution |
| `llama` | `case_edge_01_multi_user_one_attack` | **ALERT** | `ALERT` | `UNKNOWN` | rule | ✅ Đúng | 5.292s | Password Brute Force (MITRE T1110) |
| `llama` | `case_edge_02_admin_typo_twice` | **NORMAL** | `UNKNOWN` | `UNKNOWN` | ai | ❌ Sai | 4.49s | AI chưa đủ căn cứ để kết luận và bộ luật không có  |
| `llama` | `case_edge_03_automated_inventory_tool` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 7.434s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `llama` | `case_edge_04_it_create_employee_account` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 1.589s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `llama` | `case_edge_05_bruteforce_all_failed` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 5.676s | Password Brute Force (MITRE T1110) |
| `llama` | `case_edge_06_dual_session_different_ip` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 4.119s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `llama` | `case_edge_07_scheduled_script_failed` | **NORMAL** | `UNKNOWN` | `UNKNOWN` | ai | ❌ Sai | 3.891s | AI chưa đủ căn cứ để kết luận và bộ luật không có  |
| `llama` | `case_edge_08_guest_account_login_attempt` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 4.79s | Password Brute Force (MITRE T1110) |
| `llama` | `case_edge_09_suspicious_script_benign_name` | **ALERT** | `ALERT` | `UNKNOWN` | rule | ✅ Đúng | 3.648s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001) |
| `llama` | `case_edge_10_remote_desktop_after_hours` | **ALERT** | `ALERT` | `UNKNOWN` | rule | ✅ Đúng | 4.49s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001) |
| `llama` | `case_mixed_01_office_macro_c2` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 4.504s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001) |
| `llama` | `case_mixed_02_bruteforce_to_backdoor` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 5.297s | Password Brute Force (MITRE T1110); Successful Logon Post-Brute Force (MITRE T1078); Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098) |
| `llama` | `case_mixed_03_recon_then_mimikatz` | **ALERT** | `ALERT` | `UNKNOWN` | rule | ✅ Đúng | 4.237s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001) |
| `llama` | `case_mixed_04_dev_malicious_package` | **ALERT** | `ALERT` | `UNKNOWN` | rule | ✅ Đúng | 4.023s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001) |
| `llama` | `case_mixed_05_sysadmin_hijacked_session` | **ALERT** | `ALERT` | `NORMAL` | rule | ✅ Đúng | 4.39s | Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098) |
| `llama` | `case_mixed_06_c2_and_eventlog_clear` | **ALERT** | `ALERT` | `UNKNOWN` | rule | ✅ Đúng | 4.522s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001) |
| `llama` | `case_mixed_07_browser_exploit_payload` | **ALERT** | `ALERT` | `UNKNOWN` | rule | ✅ Đúng | 4.419s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001) |
| `llama` | `case_mixed_08_pass_the_hash_cmd` | **ALERT** | `NORMAL` | `NORMAL` | ai | ❌ Sai | 4.151s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `llama` | `case_mixed_09_stealth_persistence_run` | **ALERT** | `ALERT` | `UNKNOWN` | rule | ✅ Đúng | 3.697s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001) |
| `llama` | `case_mixed_10_recon_domain_trust` | **ALERT** | `ALERT` | `UNKNOWN` | rule | ✅ Đúng | 5.014s | Password Brute Force (MITRE T1110) |
| `llama` | `case_normal_01_office` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 8.368s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `llama` | `case_normal_02_sysadmin` | **NORMAL** | `ALERT` | `ALERT` | ai | ❌ Sai | 6.162s | Nhận định của AI: Dựa trên thống kê, có 3 sự kiện  |
| `llama` | `case_normal_03_developer` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 5.98s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `llama` | `case_normal_04_typo_login` | **NORMAL** | `UNKNOWN` | `UNKNOWN` | ai | ❌ Sai | 2.316s | AI chưa đủ căn cứ để kết luận và bộ luật không có  |
| `llama` | `case_normal_05_backup_script` | **NORMAL** | `UNKNOWN` | `UNKNOWN` | ai | ❌ Sai | 4.072s | AI chưa đủ căn cứ để kết luận và bộ luật không có  |
| `llama` | `case_normal_06_disk_cleanup` | **NORMAL** | `UNKNOWN` | `UNKNOWN` | ai | ❌ Sai | 4.026s | AI chưa đủ căn cứ để kết luận và bộ luật không có  |
| `llama` | `case_normal_07_browser_work` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 4.455s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `llama` | `case_normal_08_pdf_reader` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 3.998s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `llama` | `case_normal_09_calc_and_tools` | **NORMAL** | `UNKNOWN` | `UNKNOWN` | ai | ❌ Sai | 4.164s | AI chưa đủ căn cứ để kết luận và bộ luật không có  |
| `llama` | `case_normal_10_powershell_profile` | **NORMAL** | `UNKNOWN` | `UNKNOWN` | ai | ❌ Sai | 4.079s | AI chưa đủ căn cứ để kết luận và bộ luật không có  |

## 3. Nhận định và Kết luận
- **Cơ chế quyết định**: Luật MẠNH (brute force >= 3 lần sai, tải/thực thi mã độc, thêm vào nhóm Administrators) luôn cảnh báo làm lưới an toàn; các trường hợp còn lại do AI quyết định sau khi kiểm chứng bằng chứng với dữ liệu và qua vòng tự thẩm định (self-verification).
- **Hệ thống** = nhãn cuối cùng. **Riêng AI** = nhãn của mô hình (sau kiểm chứng), không tính lớp luật — thể hiện năng lực tự phân tích của AI.
- **Độ chuẩn xác và Nhạy (Precision / Recall)**: So sánh khả năng phân biệt giữa hành vi quản trị thông thường và tấn công mạng.
- **Khả năng bám sát cấu trúc (JSON Compliance)**: Đảm bảo khả năng tích hợp tự động vào hệ thống SOC/EDR.
- **Khuyến nghị lựa chọn**: Mô hình có điểm F1 cao nhất và tỷ lệ False Negative = 0 nên được ưu tiên triển khai chính thức.

## 4. Kiểm tra trên bộ dữ liệu độc lập (`data/`, 15 ca)

Prompt và cơ chế kiểm chứng được điều chỉnh dựa trên `data01`. Để tránh đánh giá "học vẹt", hệ thống được chạy thêm trên bộ `data/` không dùng trong quá trình điều chỉnh.

| Chỉ số đánh giá | **QWEN** (`qwen2.5:3b-instruct-q4_K_M`) | **LLAMA** (`llama3.2:3b-instruct-q4_K_M`) |
|---| :---: | :---: |
| **Tổng số ca kiểm thử** | 15 | 15 |
| **Độ chuẩn xác (Precision)** | 100.0% | 90.0% |
| **Độ nhạy phát hiện (Recall)** | 100.0% | 100.0% |
| **Điểm F1-Score** | 1.0 | 0.947 |
| **Độ chính xác tổng thể (Accuracy)** | 100.0% | 80.0% |
| **Báo động giả (False Positive - FP)** | 0 ca | 1 ca |
| **Bỏ sót tấn công (False Negative - FN)** | 0 ca | 0 ca |
| **Tỷ lệ xuất JSON hợp lệ (Valid JSON)** | 100.0% | 100.0% |
| **Thời gian trung vị (Median Latency)** | 4.79s | 5.47s |
| **Thời gian trung bình (Mean Latency)** | 7.08s | 7.98s |
| **Cảnh báo do Luật + AI xác nhận** | 9 ca | 6 ca |
| **Cảnh báo do AI tự phát hiện** | 0 ca | 1 ca |
| **Cảnh báo chỉ do Luật (AI không xác nhận)** | 0 ca | 3 ca |
| **[Riêng AI] Precision** | 100.0% | 85.7% |
| **[Riêng AI] Recall** | 100.0% | 66.7% |
| **[Riêng AI] F1-Score** | 1.0 | 0.75 |
| **[Riêng AI] Accuracy** | 100.0% | 60.0% |
| **[Riêng AI] Báo động giả / Bỏ sót** | 0 / 0 ca | 1 / 3 ca |

<details><summary>Chi tiết từng ca (data/)</summary>

| Model | Case ID | Ground Truth | Hệ thống | Riêng AI | Nguồn quyết định | Kết quả | Thời gian (s) | Giai đoạn tấn công phát hiện |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|---|
| `qwen` | `case_attack_01` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 7.512s | Password Brute Force (MITRE T1110); Successful Logon Post-Brute Force (MITRE T1078); Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Password Brute Force; System Reconnaissance (MITRE T1033) |
| `qwen` | `case_attack_bruteforce` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 6.059s | Password Brute Force (MITRE T1110); Successful Logon Post-Brute Force (MITRE T1078); Password Brute Force |
| `qwen` | `case_attack_credential_dump` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 4.159s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Reconnaissance; System Reconnaissance (MITRE T1033) |
| `qwen` | `case_attack_new` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 15.771s | Password Brute Force (MITRE T1110); Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098); Malware Execution / PowerShell Download Cradle (MITRE T1059.001); System Reconnaissance (MITRE T1033) |
| `qwen` | `case_attack_persistence_backdoor` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 4.05s | Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098); Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Backdoor Creation |
| `qwen` | `case_attack_powershell_c2` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 4.159s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Malware Execution |
| `qwen` | `case_attack_recon_discovery` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 5.613s | Password Brute Force (MITRE T1110); Reconnaissance; System Reconnaissance (MITRE T1033) |
| `qwen` | `case_demo_02` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 22.261s | Password Brute Force (MITRE T1110); Successful Logon Post-Brute Force (MITRE T1078); Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098); Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Backdoor Creation; System Reconnaissance (MITRE T1033) |
| `qwen` | `case_mixed_stealth_attack` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 4.181s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Malware Execution |
| `qwen` | `case_normal_01` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.861s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_normal_backup_script` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 4.164s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_normal_developer` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 4.884s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_normal_office_worker` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 4.785s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_normal_sysadmin_task` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 4.571s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_normal_typo_login` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 4.21s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `llama` | `case_attack_01` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 6.624s | Password Brute Force (MITRE T1110); Successful Logon Post-Brute Force (MITRE T1078); Malware Execution / PowerShell Download Cradle (MITRE T1059.001); System Reconnaissance (MITRE T1033) |
| `llama` | `case_attack_bruteforce` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 5.473s | Password Brute Force (MITRE T1110); Successful Logon Post-Brute Force (MITRE T1078) |
| `llama` | `case_attack_credential_dump` | **ALERT** | `ALERT` | `UNKNOWN` | rule | ✅ Đúng | 4.039s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001) |
| `llama` | `case_attack_new` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 19.537s | Password Brute Force (MITRE T1110); Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098); Malware Execution / PowerShell Download Cradle (MITRE T1059.001); System Reconnaissance (MITRE T1033) |
| `llama` | `case_attack_persistence_backdoor` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 4.306s | Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098); Malware Execution / PowerShell Download Cradle (MITRE T1059.001) |
| `llama` | `case_attack_powershell_c2` | **ALERT** | `ALERT` | `NORMAL` | rule | ✅ Đúng | 4.305s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001) |
| `llama` | `case_attack_recon_discovery` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 5.25s | Password Brute Force (MITRE T1110); System Reconnaissance (MITRE T1033) |
| `llama` | `case_demo_02` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 25.758s | Password Brute Force (MITRE T1110); Successful Logon Post-Brute Force (MITRE T1078); Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098); Malware Execution / PowerShell Download Cradle (MITRE T1059.001); System Reconnaissance (MITRE T1033) |
| `llama` | `case_mixed_stealth_attack` | **ALERT** | `ALERT` | `UNKNOWN` | rule | ✅ Đúng | 4.452s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001) |
| `llama` | `case_normal_01` | **NORMAL** | `UNKNOWN` | `UNKNOWN` | ai | ❌ Sai | 14.546s | AI chưa đủ căn cứ để kết luận và bộ luật không có  |
| `llama` | `case_normal_backup_script` | **NORMAL** | `ALERT` | `ALERT` | ai | ❌ Sai | 5.528s | Nhận định của AI: Có sự kiện tấn công được phát hi |
| `llama` | `case_normal_developer` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 5.294s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `llama` | `case_normal_office_worker` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 6.43s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `llama` | `case_normal_sysadmin_task` | **NORMAL** | `UNKNOWN` | `UNKNOWN` | ai | ❌ Sai | 1.947s | AI chưa đủ căn cứ để kết luận và bộ luật không có  |
| `llama` | `case_normal_typo_login` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 6.143s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |

</details>

## 5. So sánh trước và sau cải tiến (Qwen 2.5 3B, data01)

| Chỉ số | Trước cải tiến (2026-11-01) | Sau cải tiến |
|---|:---:|:---:|
| Accuracy hệ thống | 92.5% | **97.5%** |
| Báo động giả / Bỏ sót (hệ thống) | 3 / 0 ca | **1 / 0 ca** |
| Recall riêng AI | 8.0% (2/25)* | **84.0%** (21/25) |
| Accuracy riêng AI | 42.5%* | **87.5%** |
| Ai quyết định nhãn ALERT | Chỉ bộ luật | Luật mạnh + AI (có tự thẩm định) |

\* Đo lại trên prompt cũ khi không có gợi ý từ luật: prompt cũ khẳng định "không phát hiện chuỗi tấn công" nên mô hình gần như luôn trả NORMAL; nhãn ALERT trước đây hoàn toàn do bộ luật quyết định.

**Các thay đổi chính:**
1. Prompt trung lập (không kết luận trước), thêm ý nghĩa mã sự kiện, tiêu chí hoạt động bình thường; nêu rõ chỉ cần một dấu hiệu là đủ ALERT.
2. Mỗi lô gửi mô hình kèm bảng THỐNG KÊ số lượng từng loại sự kiện để hạn chế bịa dữ liệu (hallucination).
3. Kiểm chứng kết luận của AI với dữ liệu: loại "dò mật khẩu" khi < 3 sự kiện 4625, loại "trinh sát" khi không có lệnh trinh sát, bằng chứng phải là event_ref có thật.
4. Vòng tự thẩm định (self-verification): khi chỉ AI muốn cảnh báo, mô hình được hỏi lại riêng về các sự kiện đã trích dẫn để loại báo động giả.
5. Luật tương quan chia MẠNH/YẾU: luật mạnh luôn cảnh báo (lưới an toàn), tín hiệu yếu để AI quyết định theo ngữ cảnh.

**Nhận xét:**
- Qwen 2.5 3B phù hợp triển khai: hệ thống 97.5% (data01) và 100% (data/), riêng AI đạt F1 0.894 và 1.0.
- Llama 3.2 3B yếu hơn rõ rệt khi tự phân tích (Recall riêng AI 32%), thường trả UNKNOWN cho ca bình thường; hệ thống vẫn bắt tấn công nhờ luật mạnh nhưng phần lớn cảnh báo không được AI xác nhận.
- Ca sai còn lại của Qwen (`case_edge_04_it_create_employee_account`): IT tạo tài khoản nhân viên bằng `net user ... /add` — hành vi mơ hồ, cần thêm ngữ cảnh (giờ làm việc, tài khoản thực hiện) để phân biệt với tạo backdoor.
