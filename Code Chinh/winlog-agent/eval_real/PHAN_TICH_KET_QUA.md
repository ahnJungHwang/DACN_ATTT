# Phân tích kết quả đánh giá trên log THẬT (07/11/2026)

Số liệu gốc: [REAL_LOG_REPORT.md](REAL_LOG_REPORT.md) · CSV từng lượt: [real_log_results.csv](real_log_results.csv) · Nhãn: [labels.json](labels.json)

Mô hình: `qwen2.5:3b-instruct-q4_K_M` · 14 ca tấn công thật được tính điểm · mỗi ca chạy 3 lần.

## 1. Kết quả chính

| Cách phát hiện | Bắt được (theo ca) | So với dữ liệu tự sinh `data01` |
|---|:---:|:---:|
| **Hệ thống** (luật mạnh + AI + tự thẩm định) | **9/14 = 64%** (KTC95% 39%–84%) | 100% |
| Riêng AI | 8/14 ≈ 57% | 84% |
| Chỉ luật (không AI) | 5/14 = 36% | 100% |

1. **Dữ liệu tự sinh đánh giá quá cao năng lực hệ thống.** Recall giảm từ 100% (data01) xuống **64%** trên log thật. Đây là lý do không thể chỉ dựa vào `data01` để kết luận.
2. **AI có đóng góp thật.** Trên log thật, bộ luật chỉ bắt 5/14 ca; nhờ AI hệ thống bắt thêm 4 ca mà luật bỏ sót: password spraying (sự kiện 4648 — luật không xét), PSAttack, PowerSploit (2 mẫu). Mức tăng **36% → 64%**.
3. **AI không "hên xui" giữa các lần chạy**: 13/14 ca cho cùng kết quả ở cả 3 lần (temperature = 0). Vấn đề là AI **sai một cách nhất quán** ở một số kiểu tấn công, không phải ngẫu nhiên.

## 2. Các ca bị bỏ sót và nguyên nhân

| Ca | Dấu vết rõ ràng trong log | AI (vòng 1) | Nguyên nhân |
|---|---|:---:|---|
| `dbc_metasploit_psexec_native` | File tên ngẫu nhiên `C:\Windows\duKhLYUX.exe`, `cmd.exe /c echo … > \\.\pipe\…` (kỹ thuật getsystem) | NORMAL | Mô hình 3B không nhận ra mẫu named-pipe/tên file ngẫu nhiên; luật không có |
| `dbc_metasploit_psexec_powershell` | `powershell -nop -w hidden -c … FromBase64String('H4sI…')` (payload nén Base64) | NORMAL | Prompt đã liệt kê `FromBase64String` nhưng mô hình vẫn bỏ qua; luật chỉ khớp `-encodedcommand` |
| `dbc_sliver_c2` | `wevtutil cl security/system/…/Windows Defender` (xoá nhật ký) | NORMAL | Prompt đã liệt kê `wevtutil cl` nhưng mô hình vẫn bỏ qua; luật không có |
| `e2m_openssh_install` ⚠️ | `Add-WindowsCapability OpenSSH.Server` | NORMAL | Hành vi hai mặt (quản trị hợp lệ / tạo lối vào từ xa) — nhãn ALERT của nguồn có thể tranh luận |
| `e2m_openssh_activation` ⚠️ | 103 script block cấu hình SSH | UNKNOWN | Script block dài → 73 lô, 316 giây/ca; mô hình không đủ căn cứ |

Kết luận: mô hình 3B **đọc được** từ khoá nhưng **không suy luận ổn định** từ dấu hiệu tấn công kinh điển (xoá log, payload Base64 ẩn, named pipe). Luật hiện tại so khớp chuỗi quá hẹp (vd `-encodedcommand` không khớp dạng rút gọn `-Enc`).

## 3. Vấn đề triển khai phát hiện thêm

1. **Độ phủ thu thập:** 11/25 mẫu DeepBlueCLI là tấn công thật nhưng agent **không thể thấy** vì chỉ thu Security 4624/4625/4648/4688 và PowerShell 4104. Cần thu thêm: System 7045 (cài service – PsExec), Security 1102 (xoá log), 4720/4732 (tạo user/thêm vào nhóm admin), Sysmon.
2. **Antivirus can thiệp:** Microsoft Defender
   - cách ly 2 file log chứa mã PowerShell làm rối (`Trojan:PowerShell/Splitfuse.C`) → 2 ca bị loại;
   - cách ly các file kết quả `results/<ca>/*.json` vì chứa lại payload của kẻ tấn công;
   - quét nội dung trong bộ nhớ Ollama qua AMSI (`llama-server.exe`) trong lúc chạy.
   Trên máy chủ SOC thật cần chính sách loại trừ có kiểm soát cho thư mục dữ liệu phân tích, hoặc chạy phân tích trên máy chuyên dụng.
3. **Hiệu năng:** ca có script block dài tạo hàng chục lô (316 giây/ca). Cần cắt ngắn ScriptBlockText hoặc gộp lô thông minh hơn.

## 4. Giới hạn của đợt đánh giá này

- Chỉ đo **Recall**; hai nguồn không có log bình thường nên **chưa đo được báo động giả** → cần bước 2 (thu log hoạt động bình thường từ máy ảo).
- 14 ca là nhỏ: khoảng tin cậy rộng (39%–84%).
- Nhãn lấy theo mô tả nguồn, chưa có người chấm thứ hai; 2 ca OpenSSH là hành vi hai mặt.
- 2 ca bị antivirus chặn không được tính.

## 5. Hướng cải tiến (và cách tránh "học vẹt")

Các ca bỏ sót ở trên **đã bị nhìn thấy**, nên nếu sửa luật/prompt theo chúng thì bộ này trở thành **tập phát triển**. Để đánh giá lại công bằng cần một **tập kiểm tra mới chưa từng dùng**, ví dụ [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES), và chốt nhãn trước khi chạy.

Đề xuất cải tiến theo thứ tự ưu tiên:
1. Mở rộng thu thập trong `client_agent.ps1`: System 7045, Security 1102/4720/4732 (và cập nhật `read_events`).
2. Bổ sung luật cho dấu hiệu chắc chắn: `wevtutil cl`, `Clear-EventLog`, `-enc`/`-e` rút gọn, `-w hidden` + `FromBase64String`, `\\.\pipe\` từ `cmd /c echo`.
3. Thử mô hình lớn hơn vừa 6GB VRAM (vd Qwen2.5 7B Q4 ~4.7GB) và so sánh trên cùng bộ, có theo dõi nhiệt độ GPU.
4. Thu log bình thường (bước 2) để đo báo động giả.
