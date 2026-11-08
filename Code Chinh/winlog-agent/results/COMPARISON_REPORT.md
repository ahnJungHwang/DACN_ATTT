# 📊 BÁO CÁO KẾT QUẢ SO SÁNH HIỆU NĂNG MÔ HÌNH SLM
**Thời gian thực nghiệm:** `2026-11-01 22:51:39`  
**Môi trường suy luận:** Ollama Local API (`http://127.0.0.1:11434/api/chat`)  

## 1. Bảng chỉ số đối chiếu tổng hợp

| Chỉ số đánh giá | **QWEN** (`qwen2.5:3b-instruct-q4_K_M`) | **LLAMA** (`llama3.2:3b-instruct-q4_K_M`) |
|---| :---: | :---: |
| **Tổng số ca kiểm thử** | 40 | 40 |
| **Độ chuẩn xác (Precision)** | 89.3% | 89.3% |
| **Độ nhạy phát hiện (Recall)** | 100.0% | 100.0% |
| **Điểm F1-Score** | 0.943 | 0.943 |
| **Độ chính xác tổng thể (Accuracy)** | 92.5% | 75.0% |
| **Báo động giả (False Positive - FP)** | 3 ca | 3 ca |
| **Bỏ sót tấn công (False Negative - FN)** | 0 ca | 0 ca |
| **Tỷ lệ xuất JSON hợp lệ (Valid JSON)** | 100.0% | 100.0% |
| **Thời gian trung vị (Median Latency)** | 6.06s | 5.32s |
| **Thời gian trung bình (Mean Latency)** | 6.25s | 5.46s |

## 2. Chi tiết kết quả từng ca thử nghiệm

| Model | Case ID | Ground Truth | Dự đoán AI | Kết quả | Thời gian (s) | Giai đoạn tấn công phát hiện |
|---|---|:---:|:---:|:---:|:---:|---|
| `qwen` | `case_attack_01_bruteforce` | **ALERT** | `ALERT` | ✅ Đúng | 9.281s | Password Brute Force (MITRE T1110); Successful Logon Post-Brute Force (MITRE T1078); Password Brute Force; Reconnaissance |
| `qwen` | `case_attack_02_ps_c2_download` | **ALERT** | `ALERT` | ✅ Đúng | 5.927s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Malware Execution |
| `qwen` | `case_attack_03_backdoor_account` | **ALERT** | `ALERT` | ✅ Đúng | 6.479s | Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098); Password Brute Force |
| `qwen` | `case_attack_04_mimikatz_dump` | **ALERT** | `ALERT` | ✅ Đúng | 6.294s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); System Reconnaissance (MITRE T1033); Reconnaissance; Malware Execution |
| `qwen` | `case_attack_05_recon_discovery` | **ALERT** | `ALERT` | ✅ Đúng | 7.955s | Password Brute Force (MITRE T1110); System Reconnaissance (MITRE T1033); Password Brute Force; Reconnaissance |
| `qwen` | `case_attack_06_reg_persistence` | **ALERT** | `ALERT` | ✅ Đúng | 6.104s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Malware Execution |
| `qwen` | `case_attack_07_encoded_powershell` | **ALERT** | `ALERT` | ✅ Đúng | 5.987s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Malware Execution |
| `qwen` | `case_attack_08_schtasks_persistence` | **ALERT** | `ALERT` | ✅ Đúng | 6.128s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Malware Execution |
| `qwen` | `case_attack_09_procdump_lsass` | **ALERT** | `ALERT` | ✅ Đúng | 7.238s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); System Reconnaissance (MITRE T1033); Reconnaissance; Password Brute Force |
| `qwen` | `case_attack_10_disable_defender` | **ALERT** | `ALERT` | ✅ Đúng | 5.675s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Malware Execution |
| `qwen` | `case_edge_01_multi_user_one_attack` | **ALERT** | `ALERT` | ✅ Đúng | 7.818s | Password Brute Force (MITRE T1110); Password Brute Force |
| `qwen` | `case_edge_02_admin_typo_twice` | **NORMAL** | `ALERT` | ❌ Sai | 6.462s | Successful Logon Post-Brute Force (MITRE T1078); Password Brute Force |
| `qwen` | `case_edge_03_automated_inventory_tool` | **NORMAL** | `NORMAL` | ✅ Đúng | 5.878s | Các sự kiện log chỉ bao gồm hoạt động hệ thống và  |
| `qwen` | `case_edge_04_it_create_employee_account` | **NORMAL** | `ALERT` | ❌ Sai | 6.633s | Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098); Password Brute Force |
| `qwen` | `case_edge_05_bruteforce_all_failed` | **ALERT** | `ALERT` | ✅ Đúng | 8.003s | Password Brute Force (MITRE T1110); Password Brute Force |
| `qwen` | `case_edge_06_dual_session_different_ip` | **NORMAL** | `NORMAL` | ✅ Đúng | 6.311s | Các sự kiện log chỉ bao gồm hoạt động hệ thống và  |
| `qwen` | `case_edge_07_scheduled_script_failed` | **NORMAL** | `NORMAL` | ✅ Đúng | 5.599s | Các sự kiện log chỉ bao gồm hoạt động hệ thống và  |
| `qwen` | `case_edge_08_guest_account_login_attempt` | **ALERT** | `ALERT` | ✅ Đúng | 6.423s | Password Brute Force (MITRE T1110); Password Brute Force |
| `qwen` | `case_edge_09_suspicious_script_benign_name` | **ALERT** | `ALERT` | ✅ Đúng | 5.946s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Malware Execution |
| `qwen` | `case_edge_10_remote_desktop_after_hours` | **ALERT** | `ALERT` | ✅ Đúng | 6.418s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Malware Execution |
| `qwen` | `case_mixed_01_office_macro_c2` | **ALERT** | `ALERT` | ✅ Đúng | 6.468s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Malware Execution |
| `qwen` | `case_mixed_02_bruteforce_to_backdoor` | **ALERT** | `ALERT` | ✅ Đúng | 8.131s | Password Brute Force (MITRE T1110); Successful Logon Post-Brute Force (MITRE T1078); Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098); Password Brute Force; Backdoor Creation |
| `qwen` | `case_mixed_03_recon_then_mimikatz` | **ALERT** | `ALERT` | ✅ Đúng | 6.548s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); System Reconnaissance (MITRE T1033); Password Brute Force; Reconnaissance; Malware Execution |
| `qwen` | `case_mixed_04_dev_malicious_package` | **ALERT** | `ALERT` | ✅ Đúng | 6.002s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Malware Execution |
| `qwen` | `case_mixed_05_sysadmin_hijacked_session` | **ALERT** | `ALERT` | ✅ Đúng | 6.227s | Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098); Password Brute Force; Backdoor Creation |
| `qwen` | `case_mixed_06_c2_and_eventlog_clear` | **ALERT** | `ALERT` | ✅ Đúng | 5.92s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Malware Execution |
| `qwen` | `case_mixed_07_browser_exploit_payload` | **ALERT** | `ALERT` | ✅ Đúng | 6.009s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Malware Execution |
| `qwen` | `case_mixed_08_pass_the_hash_cmd` | **ALERT** | `ALERT` | ✅ Đúng | 5.57s | Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098); Password Brute Force; Backdoor Creation |
| `qwen` | `case_mixed_09_stealth_persistence_run` | **ALERT** | `ALERT` | ✅ Đúng | 5.44s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Malware Execution |
| `qwen` | `case_mixed_10_recon_domain_trust` | **ALERT** | `ALERT` | ✅ Đúng | 6.324s | Password Brute Force (MITRE T1110); System Reconnaissance (MITRE T1033); Password Brute Force |
| `qwen` | `case_normal_01_office` | **NORMAL** | `NORMAL` | ✅ Đúng | 5.772s | Các sự kiện log chỉ bao gồm hoạt động hệ thống và  |
| `qwen` | `case_normal_02_sysadmin` | **NORMAL** | `NORMAL` | ✅ Đúng | 6.044s | Các sự kiện log chỉ bao gồm hoạt động hệ thống và  |
| `qwen` | `case_normal_03_developer` | **NORMAL** | `NORMAL` | ✅ Đúng | 5.76s | Các sự kiện log chỉ bao gồm hoạt động hệ thống và  |
| `qwen` | `case_normal_04_typo_login` | **NORMAL** | `ALERT` | ❌ Sai | 5.385s | Successful Logon Post-Brute Force (MITRE T1078); Password Brute Force |
| `qwen` | `case_normal_05_backup_script` | **NORMAL** | `NORMAL` | ✅ Đúng | 4.704s | Các sự kiện log chỉ bao gồm hoạt động hệ thống và  |
| `qwen` | `case_normal_06_disk_cleanup` | **NORMAL** | `NORMAL` | ✅ Đúng | 4.716s | Các sự kiện log chỉ bao gồm hoạt động hệ thống và  |
| `qwen` | `case_normal_07_browser_work` | **NORMAL** | `NORMAL` | ✅ Đúng | 5.225s | Các sự kiện log chỉ bao gồm hoạt động hệ thống và  |
| `qwen` | `case_normal_08_pdf_reader` | **NORMAL** | `NORMAL` | ✅ Đúng | 5.346s | Các sự kiện log chỉ bao gồm hoạt động hệ thống và  |
| `qwen` | `case_normal_09_calc_and_tools` | **NORMAL** | `NORMAL` | ✅ Đúng | 5.936s | Các sự kiện log chỉ bao gồm hoạt động hệ thống và  |
| `qwen` | `case_normal_10_powershell_profile` | **NORMAL** | `NORMAL` | ✅ Đúng | 6.073s | Các sự kiện log chỉ bao gồm hoạt động hệ thống và  |
| `llama` | `case_attack_01_bruteforce` | **ALERT** | `ALERT` | ✅ Đúng | 7.883s | Password Brute Force (MITRE T1110); Successful Logon Post-Brute Force (MITRE T1078); Password Brute Force; Reconnaissance |
| `llama` | `case_attack_02_ps_c2_download` | **ALERT** | `ALERT` | ✅ Đúng | 6.317s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Password Brute Force; Malware Execution |
| `llama` | `case_attack_03_backdoor_account` | **ALERT** | `ALERT` | ✅ Đúng | 6.779s | Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098); Password Brute Force; Backdoor Creation |
| `llama` | `case_attack_04_mimikatz_dump` | **ALERT** | `ALERT` | ✅ Đúng | 6.142s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); System Reconnaissance (MITRE T1033); Reconnaissance; Privilege Escalation |
| `llama` | `case_attack_05_recon_discovery` | **ALERT** | `ALERT` | ✅ Đúng | 7.963s | Password Brute Force (MITRE T1110); System Reconnaissance (MITRE T1033); Password Brute Force; Reconnaissance |
| `llama` | `case_attack_06_reg_persistence` | **ALERT** | `ALERT` | ✅ Đúng | 6.486s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Password Brute Force; Backdoor Creation |
| `llama` | `case_attack_07_encoded_powershell` | **ALERT** | `ALERT` | ✅ Đúng | 5.973s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Tải & Thực thi mã độc |
| `llama` | `case_attack_08_schtasks_persistence` | **ALERT** | `ALERT` | ✅ Đúng | 6.164s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Password Brute Force; Reconnaissance; Malware Execution |
| `llama` | `case_attack_09_procdump_lsass` | **ALERT** | `ALERT` | ✅ Đúng | 6.942s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); System Reconnaissance (MITRE T1033); Password Brute Force; Reconnaissance; Backdoor Creation |
| `llama` | `case_attack_10_disable_defender` | **ALERT** | `ALERT` | ✅ Đúng | 6.445s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Password Brute Force; Reconnaissance; Backdoor Creation |
| `llama` | `case_edge_01_multi_user_one_attack` | **ALERT** | `ALERT` | ✅ Đúng | 7.299s | Password Brute Force (MITRE T1110); Password Brute Force |
| `llama` | `case_edge_02_admin_typo_twice` | **NORMAL** | `ALERT` | ❌ Sai | 5.849s | Successful Logon Post-Brute Force (MITRE T1078); Password Brute Force |
| `llama` | `case_edge_03_automated_inventory_tool` | **NORMAL** | `NORMAL` | ✅ Đúng | 4.325s | Các sự kiện log chỉ bao gồm hoạt động hệ thống và  |
| `llama` | `case_edge_04_it_create_employee_account` | **NORMAL** | `ALERT` | ❌ Sai | 5.152s | Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098); Password Brute Force |
| `llama` | `case_edge_05_bruteforce_all_failed` | **ALERT** | `ALERT` | ✅ Đúng | 6.203s | Password Brute Force (MITRE T1110); Password Brute Force |
| `llama` | `case_edge_06_dual_session_different_ip` | **NORMAL** | `NORMAL` | ✅ Đúng | 4.955s | Các sự kiện log chỉ bao gồm hoạt động hệ thống và  |
| `llama` | `case_edge_07_scheduled_script_failed` | **NORMAL** | `UNKNOWN` | ❌ Sai | 4.29s | Chưa thấy chuỗi tấn công xác thực trong các lô log |
| `llama` | `case_edge_08_guest_account_login_attempt` | **ALERT** | `ALERT` | ✅ Đúng | 5.273s | Password Brute Force (MITRE T1110); Password Brute Force |
| `llama` | `case_edge_09_suspicious_script_benign_name` | **ALERT** | `ALERT` | ✅ Đúng | 4.543s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Password Brute Force; Malware Execution |
| `llama` | `case_edge_10_remote_desktop_after_hours` | **ALERT** | `ALERT` | ✅ Đúng | 4.769s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Password Brute Force; Reconnaissance; Malware Execution |
| `llama` | `case_mixed_01_office_macro_c2` | **ALERT** | `ALERT` | ✅ Đúng | 4.678s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Password Brute Force; Reconnaissance; Malware Execution |
| `llama` | `case_mixed_02_bruteforce_to_backdoor` | **ALERT** | `ALERT` | ✅ Đúng | 5.37s | Password Brute Force (MITRE T1110); Successful Logon Post-Brute Force (MITRE T1078); Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098); Password Brute Force; Reconnaissance; Backdoor Creation |
| `llama` | `case_mixed_03_recon_then_mimikatz` | **ALERT** | `ALERT` | ✅ Đúng | 4.736s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); System Reconnaissance (MITRE T1033); Reconnaissance; Password Brute Force |
| `llama` | `case_mixed_04_dev_malicious_package` | **ALERT** | `ALERT` | ✅ Đúng | 4.193s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Password Brute Force; Reconnaissance |
| `llama` | `case_mixed_05_sysadmin_hijacked_session` | **ALERT** | `ALERT` | ✅ Đúng | 5.44s | Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098); Password Brute Force; Reconnaissance; Backdoor Creation |
| `llama` | `case_mixed_06_c2_and_eventlog_clear` | **ALERT** | `ALERT` | ✅ Đúng | 4.613s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Tải & Thực thi mã độc |
| `llama` | `case_mixed_07_browser_exploit_payload` | **ALERT** | `ALERT` | ✅ Đúng | 5.371s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Password Brute Force; Reconnaissance; Malware Execution |
| `llama` | `case_mixed_08_pass_the_hash_cmd` | **ALERT** | `ALERT` | ✅ Đúng | 5.044s | Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098); Password Brute Force; Reconnaissance |
| `llama` | `case_mixed_09_stealth_persistence_run` | **ALERT** | `ALERT` | ✅ Đúng | 4.319s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Password Brute Force; Malware Execution |
| `llama` | `case_mixed_10_recon_domain_trust` | **ALERT** | `ALERT` | ✅ Đúng | 6.083s | Password Brute Force (MITRE T1110); System Reconnaissance (MITRE T1033); Password Brute Force; Reconnaissance |
| `llama` | `case_normal_01_office` | **NORMAL** | `NORMAL` | ✅ Đúng | 5.689s | Các sự kiện log chỉ bao gồm hoạt động hệ thống và  |
| `llama` | `case_normal_02_sysadmin` | **NORMAL** | `UNKNOWN` | ❌ Sai | 6.318s | Chưa thấy chuỗi tấn công xác thực trong các lô log |
| `llama` | `case_normal_03_developer` | **NORMAL** | `NORMAL` | ✅ Đúng | 5.464s | Các sự kiện log chỉ bao gồm hoạt động hệ thống và  |
| `llama` | `case_normal_04_typo_login` | **NORMAL** | `ALERT` | ❌ Sai | 5.113s | Successful Logon Post-Brute Force (MITRE T1078); Password Brute Force; Reconnaissance |
| `llama` | `case_normal_05_backup_script` | **NORMAL** | `UNKNOWN` | ❌ Sai | 4.136s | Chưa thấy chuỗi tấn công xác thực trong các lô log |
| `llama` | `case_normal_06_disk_cleanup` | **NORMAL** | `NORMAL` | ✅ Đúng | 4.322s | Các sự kiện log chỉ bao gồm hoạt động hệ thống và  |
| `llama` | `case_normal_07_browser_work` | **NORMAL** | `UNKNOWN` | ❌ Sai | 4.53s | Chưa thấy chuỗi tấn công xác thực trong các lô log |
| `llama` | `case_normal_08_pdf_reader` | **NORMAL** | `UNKNOWN` | ❌ Sai | 4.469s | Chưa thấy chuỗi tấn công xác thực trong các lô log |
| `llama` | `case_normal_09_calc_and_tools` | **NORMAL** | `UNKNOWN` | ❌ Sai | 4.397s | Chưa thấy chuỗi tấn công xác thực trong các lô log |
| `llama` | `case_normal_10_powershell_profile` | **NORMAL** | `UNKNOWN` | ❌ Sai | 4.433s | Chưa thấy chuỗi tấn công xác thực trong các lô log |

## 3. Nhận định và Kết luận
- **Độ chuẩn xác và Nhạy (Precision / Recall)**: So sánh khả năng phân biệt giữa hành vi quản trị thông thường và tấn công mạng.
- **Khả năng bám sát cấu trúc (JSON Compliance)**: Đảm bảo khả năng tích hợp tự động vào hệ thống SOC/EDR.
- **Khuyến nghị lựa chọn**: Mô hình có điểm F1 cao nhất và tỷ lệ False Negative = 0 nên được ưu tiên triển khai chính thức.