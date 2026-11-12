# 📊 BÁO CÁO KẾT QUẢ SO SÁNH HIỆU NĂNG MÔ HÌNH SLM
**Thời gian thực nghiệm:** `2026-11-12 12:34:39`  
**Môi trường suy luận:** Ollama Local API (`http://127.0.0.1:11434/api/chat`)  

## 1. Bảng chỉ số đối chiếu tổng hợp

| Chỉ số đánh giá | **QWEN** (`qwen2.5:3b-instruct-q4_K_M`) |
|---| :---: |
| **Tổng số ca kiểm thử** | 200 |
| **Độ chuẩn xác (Precision)** | 52.2% |
| **Độ nhạy phát hiện (Recall)** | 77.4% |
| **Điểm F1-Score** | 0.623 |
| **Độ chính xác tổng thể (Accuracy)** | 85.0% |
| **Báo động giả (False Positive - FP)** | 22 ca |
| **Bỏ sót tấn công (False Negative - FN)** | 7 ca |
| **Tỉ lệ báo động giả (FP / số ca NORMAL)** | 13.0% (22/169) |
| **Không kết luận được (UNKNOWN / lỗi)** | 1 / 0 ca |
| **Tỷ lệ xuất JSON hợp lệ (Valid JSON)** | 100.0% |
| **Thời gian trung vị (Median Latency)** | 9.76s |
| **Thời gian trung bình (Mean Latency)** | 11.61s |
| **Cảnh báo do Luật + AI xác nhận** | 18 ca |
| **Cảnh báo do AI tự phát hiện** | 22 ca |
| **Cảnh báo chỉ do Luật (AI không xác nhận)** | 6 ca |
| **[Riêng AI] Precision** | 45.0% |
| **[Riêng AI] Recall** | 58.1% |
| **[Riêng AI] F1-Score** | 0.507 |
| **[Riêng AI] Accuracy** | 82.0% |
| **[Riêng AI] Báo động giả / Bỏ sót** | 22 / 13 ca |

## 2. Chi tiết kết quả từng ca thử nghiệm

| Model | Case ID | Ground Truth | Hệ thống | Riêng AI | Nguồn quyết định | Kết quả | Thời gian (s) | Giai đoạn tấn công phát hiện |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|---|
| `qwen` | `case_rnd_001_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 4.715s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_002_alert` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 10.523s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Reconnaissance; System Reconnaissance (MITRE T1033) |
| `qwen` | `case_rnd_003_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.251s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_004_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.81s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_005_normal` | **NORMAL** | `ALERT` | `ALERT` | ai | ❌ Sai | 18.428s | PowerShell ScriptBlock Execution |
| `qwen` | `case_rnd_006_alert` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 8.238s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Malware Execution |
| `qwen` | `case_rnd_007_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.7s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_008_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 10.328s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_009_alert` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 9.459s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Malware Execution |
| `qwen` | `case_rnd_010_alert` | **ALERT** | `NORMAL` | `NORMAL` | ai | ❌ Sai | 10.034s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_011_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.291s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_012_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.592s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_013_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 10.082s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_014_alert` | **ALERT** | `ALERT` | `NORMAL` | rule | ✅ Đúng | 10.045s | Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098) |
| `qwen` | `case_rnd_015_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 10.636s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_016_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 10.402s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_017_alert` | **ALERT** | `NORMAL` | `NORMAL` | ai | ❌ Sai | 10.582s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_018_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.177s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_019_alert` | **ALERT** | `ALERT` | `NORMAL` | rule | ✅ Đúng | 12.756s | Password Brute Force (MITRE T1110); Successful Logon Post-Brute Force (MITRE T1078) |
| `qwen` | `case_rnd_020_normal` | **NORMAL** | `ALERT` | `ALERT` | ai | ❌ Sai | 18.441s | PowerShell ScriptBlock Execution |
| `qwen` | `case_rnd_021_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 8.127s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_022_alert` | **ALERT** | `NORMAL` | `NORMAL` | ai | ❌ Sai | 10.962s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_023_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 8.88s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_024_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.225s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_025_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 10.961s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_026_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.044s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_027_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.989s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_028_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.326s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_029_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 28.623s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_030_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 30.121s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_031_alert` | **ALERT** | `ALERT` | `NORMAL` | rule | ✅ Đúng | 10.501s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001) |
| `qwen` | `case_rnd_032_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 8.986s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_033_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 8.725s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_034_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.618s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_035_normal` | **NORMAL** | `ALERT` | `ALERT` | ai | ❌ Sai | 19.16s | PowerShell ScriptBlock Execution |
| `qwen` | `case_rnd_036_normal` | **NORMAL** | `ALERT` | `ALERT` | ai | ❌ Sai | 16.149s | Malware Execution |
| `qwen` | `case_rnd_037_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 7.3s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_038_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.152s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_039_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 28.901s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_040_normal` | **NORMAL** | `ALERT` | `ALERT` | ai | ❌ Sai | 17.874s | Malware Execution |
| `qwen` | `case_rnd_041_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 7.161s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_042_normal` | **NORMAL** | `ALERT` | `ALERT` | ai | ❌ Sai | 18.163s | PowerShell ScriptBlock Execution |
| `qwen` | `case_rnd_043_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 8.912s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_044_normal` | **NORMAL** | `ALERT` | `ALERT` | ai | ❌ Sai | 19.503s | Backdoor Creation |
| `qwen` | `case_rnd_045_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 7.507s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_046_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 10.605s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_047_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.534s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_048_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.078s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_049_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 10.096s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_050_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.184s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_051_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.074s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_052_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 8.906s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_053_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 8.809s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_054_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.782s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_055_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.322s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_056_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.909s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_057_normal` | **NORMAL** | `ALERT` | `ALERT` | ai | ❌ Sai | 20.105s | Backdoor Creation |
| `qwen` | `case_rnd_058_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 7.259s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_059_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 8.88s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_060_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.676s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_061_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.503s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_062_alert` | **ALERT** | `NORMAL` | `NORMAL` | ai | ❌ Sai | 10.139s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_063_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.462s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_064_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.466s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_065_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.582s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_066_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 8.712s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_067_normal` | **NORMAL** | `UNKNOWN` | `UNKNOWN` | ai | ❌ Sai | 9.396s | AI chưa đủ căn cứ để kết luận và bộ luật không có  |
| `qwen` | `case_rnd_068_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.854s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_069_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.73s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_070_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 10.412s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_071_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.302s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_072_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 30.308s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_073_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 11.359s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_074_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.657s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_075_normal` | **NORMAL** | `ALERT` | `ALERT` | ai | ❌ Sai | 17.996s | Malware Execution |
| `qwen` | `case_rnd_076_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 27.26s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_077_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 10.244s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_078_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 12.015s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_079_alert` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 10.216s | Password Brute Force (MITRE T1110); Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098); Password Brute Force; System Reconnaissance (MITRE T1033) |
| `qwen` | `case_rnd_080_alert` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 12.493s | Password Brute Force (MITRE T1110); Successful Logon Post-Brute Force (MITRE T1078); Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Password Brute Force; System Reconnaissance (MITRE T1033) |
| `qwen` | `case_rnd_081_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 10.257s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_082_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.933s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_083_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.149s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_084_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 10.057s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_085_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 8.969s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_086_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 8.921s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_087_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.499s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_088_normal` | **NORMAL** | `ALERT` | `ALERT` | ai | ❌ Sai | 18.791s | Malware Execution |
| `qwen` | `case_rnd_089_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 8.732s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_090_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.496s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_091_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.213s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_092_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 30.939s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_093_alert` | **ALERT** | `ALERT` | `NORMAL` | rule | ✅ Đúng | 23.63s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001) |
| `qwen` | `case_rnd_094_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.366s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_095_normal` | **NORMAL** | `ALERT` | `ALERT` | ai | ❌ Sai | 18.197s | PowerShell ScriptBlock Execution |
| `qwen` | `case_rnd_096_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 7.385s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_097_normal` | **NORMAL** | `ALERT` | `ALERT` | ai | ❌ Sai | 17.53s | Malware Execution |
| `qwen` | `case_rnd_098_normal` | **NORMAL** | `ALERT` | `ALERT` | ai | ❌ Sai | 16.762s | PowerShell ScriptBlock Execution |
| `qwen` | `case_rnd_099_normal` | **NORMAL** | `ALERT` | `ALERT` | ai | ❌ Sai | 16.366s | Nhận định của AI: Đã phát hiện sự kiện 4688, cho t |
| `qwen` | `case_rnd_100_normal` | **NORMAL** | `ALERT` | `ALERT` | ai | ❌ Sai | 17.689s | Malware Execution |
| `qwen` | `case_rnd_101_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 8.494s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_102_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.546s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_103_alert` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 10.762s | Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098); Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Malware Execution |
| `qwen` | `case_rnd_104_alert` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 21.253s | Password Brute Force (MITRE T1110); Successful Logon Post-Brute Force (MITRE T1078); Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098); System Reconnaissance (MITRE T1033) |
| `qwen` | `case_rnd_105_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.637s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_106_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 10.143s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_107_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 10.614s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_108_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.798s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_109_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.112s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_110_alert` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 10.475s | Password Brute Force (MITRE T1110); Reconnaissance; System Reconnaissance (MITRE T1033) |
| `qwen` | `case_rnd_111_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.705s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_112_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.731s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_113_alert` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 9.803s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Reconnaissance; System Reconnaissance (MITRE T1033) |
| `qwen` | `case_rnd_114_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 10.587s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_115_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 8.847s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_116_normal` | **NORMAL** | `ALERT` | `ALERT` | ai | ❌ Sai | 18.929s | PowerShell ScriptBlock Execution |
| `qwen` | `case_rnd_117_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 7.341s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_118_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 10.855s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_119_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.716s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_120_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.649s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_121_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.946s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_122_alert` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 10.884s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Malware Execution |
| `qwen` | `case_rnd_123_alert` | **ALERT** | `NORMAL` | `NORMAL` | ai | ❌ Sai | 25.21s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_124_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 10.256s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_125_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.291s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_126_normal` | **NORMAL** | `ALERT` | `ALERT` | ai | ❌ Sai | 18.051s | PowerShell Script Execution |
| `qwen` | `case_rnd_127_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 8.054s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_128_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.07s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_129_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.045s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_130_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.31s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_131_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 8.947s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_132_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 11.218s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_133_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 10.289s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_134_alert` | **ALERT** | `ALERT` | `NORMAL` | rule | ✅ Đúng | 10.193s | Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098); Malware Execution / PowerShell Download Cradle (MITRE T1059.001) |
| `qwen` | `case_rnd_135_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.578s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_136_alert` | **ALERT** | `NORMAL` | `NORMAL` | ai | ❌ Sai | 9.936s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_137_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 10.0s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_138_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 10.095s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_139_alert` | **ALERT** | `NORMAL` | `NORMAL` | ai | ❌ Sai | 9.377s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_140_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 10.427s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_141_alert` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 10.831s | Password Brute Force (MITRE T1110); Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Reconnaissance; System Reconnaissance (MITRE T1033) |
| `qwen` | `case_rnd_142_alert` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 20.162s | Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098); Backdoor Creation |
| `qwen` | `case_rnd_143_normal` | **NORMAL** | `ALERT` | `ALERT` | ai | ❌ Sai | 18.02s | PowerShell ScriptBlock Execution |
| `qwen` | `case_rnd_144_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 7.827s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_145_alert` | **ALERT** | `ALERT` | `NORMAL` | rule | ✅ Đúng | 10.464s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001) |
| `qwen` | `case_rnd_146_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.049s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_147_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 10.115s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_148_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.719s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_149_alert` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 9.159s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001) |
| `qwen` | `case_rnd_150_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.131s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_151_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 10.822s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_152_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.039s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_153_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.928s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_154_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.347s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_155_alert` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 9.922s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Malware Execution |
| `qwen` | `case_rnd_156_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.134s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_157_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.063s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_158_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 10.461s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_159_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 10.37s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_160_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 10.021s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_161_alert` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 9.715s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Reconnaissance; System Reconnaissance (MITRE T1033) |
| `qwen` | `case_rnd_162_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 8.599s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_163_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 10.147s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_164_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.128s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_165_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.699s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_166_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.039s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_167_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.172s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_168_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.072s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_169_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.44s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_170_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.457s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_171_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 10.056s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_172_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.874s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_173_alert` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 21.22s | Password Brute Force (MITRE T1110); Successful Logon Post-Brute Force (MITRE T1078); Password Brute Force |
| `qwen` | `case_rnd_174_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.216s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_175_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 8.791s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_176_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.846s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_177_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 8.943s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_178_normal` | **NORMAL** | `ALERT` | `ALERT` | ai | ❌ Sai | 17.978s | PowerShell ScriptBlock Execution |
| `qwen` | `case_rnd_179_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 7.867s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_180_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.035s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_181_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.509s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_182_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.552s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_183_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 10.307s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_184_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 28.364s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_185_normal` | **NORMAL** | `ALERT` | `ALERT` | ai | ❌ Sai | 19.51s | PowerShell ScriptBlock Execution |
| `qwen` | `case_rnd_186_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 8.342s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_187_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 8.993s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_188_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.664s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_189_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 10.141s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_190_normal` | **NORMAL** | `ALERT` | `ALERT` | ai | ❌ Sai | 20.104s | Malware Execution |
| `qwen` | `case_rnd_191_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 7.098s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_192_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 10.384s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_193_alert` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 9.823s | Malware Execution / PowerShell Download Cradle (MITRE T1059.001); Reconnaissance; Malware Execution; System Reconnaissance (MITRE T1033) |
| `qwen` | `case_rnd_194_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.206s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_195_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.079s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_196_alert` | **ALERT** | `ALERT` | `ALERT` | rule+ai | ✅ Đúng | 10.219s | Password Brute Force (MITRE T1110); Successful Logon Post-Brute Force (MITRE T1078); Backdoor Creation / Privilege Escalation (MITRE T1136 / T1098); Password Brute Force |
| `qwen` | `case_rnd_197_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 10.194s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_198_normal` | **NORMAL** | `ALERT` | `ALERT` | ai | ❌ Sai | 37.96s | Tạo tiến trình mới |
| `qwen` | `case_rnd_199_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 7.976s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |
| `qwen` | `case_rnd_200_normal` | **NORMAL** | `NORMAL` | `NORMAL` | ai | ✅ Đúng | 9.041s | AI đánh giá các sự kiện là hoạt động hệ thống / ng |

## 3. Nhận định và Kết luận
- **Cơ chế quyết định**: Luật MẠNH (brute force >= 3 lần sai, tải/thực thi mã độc, thêm vào nhóm Administrators) luôn cảnh báo làm lưới an toàn; các trường hợp còn lại do AI quyết định sau khi kiểm chứng bằng chứng với dữ liệu và qua vòng tự thẩm định (self-verification).
- **Hệ thống** = nhãn cuối cùng. **Riêng AI** = nhãn của mô hình (sau kiểm chứng), không tính lớp luật — thể hiện năng lực tự phân tích của AI.
- **Độ chuẩn xác và Nhạy (Precision / Recall)**: So sánh khả năng phân biệt giữa hành vi quản trị thông thường và tấn công mạng.
- **Khả năng bám sát cấu trúc (JSON Compliance)**: Đảm bảo khả năng tích hợp tự động vào hệ thống SOC/EDR.
- **Khuyến nghị lựa chọn**: Mô hình có điểm F1 cao nhất và tỷ lệ False Negative = 0 nên được ưu tiên triển khai chính thức.