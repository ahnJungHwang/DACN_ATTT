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

---

# Cập nhật sau khi MỞ RỘNG THU THẬP (07/11/2026, lượt 2)

Thay đổi: agent thu thêm Security 1102/4720/4728/4732/4698 và System 7045/104; thêm 5 luật MITRE và mô tả các sự kiện mới vào prompt. Sự kiện xoá log ở **đầu** mỗi mẫu DeepBlueCLI (do người tạo mẫu xoá log trước khi ghi) được loại theo quy tắc đặt trước — nếu không, Recall sẽ tăng ảo gần 100%. Nhiệt độ GPU trong lượt chạy: tối đa 80°C, trung bình 67°C.

## Kết quả

| | Trước mở rộng | Sau mở rộng |
|---|:---:|:---:|
| Ca độ phủ mới (PsExec service 7045, tạo user + thêm Administrators) | không thấy được | **2/2 bắt được** (luật + AI cùng xác nhận) |
| Bộ gốc 14 ca — Hệ thống (theo ca) | **9/14 (64%)** | **7/14 (50%)** |
| Bộ gốc 14 ca — Riêng AI (theo lượt) | 55% | 45% |
| Bộ gốc 14 ca — Chỉ luật | 36% | 36% (không đổi) |
| `data01` (dữ liệu tự sinh) — Hệ thống | 97.5% | 97.5% (FP 1→0, FN 0→1) |
| Mẫu bị Defender cách ly | 2 | 4 |

## Phát hiện quan trọng: mô hình 3B rất nhạy với độ dài/nội dung prompt

Nội dung log của 14 ca gốc **không thay đổi** (chúng không chứa sự kiện mới), chỉ có prompt dài thêm. Vậy mà kết quả của AI đổi:

| Ca | Trước | Sau |
|---|:---:|:---:|
| `dbc_metasploit_psexec_powershell` | NORMAL | **ALERT** ✅ |
| `dbc_password_spray` | ALERT | UNKNOWN ❌ |
| `dbc_powersploit_security` | ALERT (2/3) | NORMAL ❌ |
| `dbc_powersploit_system` | ALERT | NORMAL ❌ |
| `dbc_sliver_c2` | NORMAL | ALERT 1/3 (không ổn định) |

→ Thêm kiến thức cho loại sự kiện mới đã **làm giảm** khả năng nhận diện các loại cũ. Với mô hình 3B, prompt dài hơn làm mô hình "phân tán chú ý". Phần độ phủ mới bắt được là nhờ **luật mạnh** (dấu hiệu rõ ràng), AI chỉ xác nhận.

## Hướng xử lý đề xuất

1. **Prompt động:** chỉ đưa mô tả dấu hiệu tấn công của những loại sự kiện **có mặt trong lô** (lô chỉ có 4688 thì không cần mô tả 7045/4698). Prompt ngắn và tập trung hơn.
2. **Mô hình lớn hơn** (vd Qwen2.5 7B Q4 ~4.7 GB, vừa 6 GB VRAM) — cần theo dõi nhiệt độ.
3. **Đánh giá lại trên tập mới chưa dùng** (EVTX-ATTACK-SAMPLES): bộ 14 ca này đã được dùng hai lần để ra quyết định, càng chỉnh theo nó thì số liệu càng kém tin cậy.

---

# Lượt 3: PROMPT ĐỘNG (07/11/2026)

Thay đổi: mô tả dấu hiệu cho sự kiện mở rộng (1102/104, 7045, 4720/4728/4732, 4698) chỉ được đưa vào prompt, bảng thống kê và prompt tự thẩm định **khi lô có loại sự kiện đó**. Đã đối chiếu với bản trước mở rộng (commit `e35eb49`): với lô chỉ có sự kiện cơ bản, toàn bộ đầu vào của mô hình **giống hệt từng ký tự**. GPU: tối đa 80°C, trung bình 68°C.

## So sánh ba phiên bản (Qwen 2.5 3B, mỗi ca 3 lần)

| | (1) Trước mở rộng | (2) Mở rộng, prompt tĩnh | (3) Mở rộng, **prompt động** |
|---|:---:|:---:|:---:|
| 14 ca log thật gốc — Hệ thống (theo ca) | 9/14 (64%) | 7/14 (50%) | **9/14 (64%)** |
| 14 ca log thật gốc — Riêng AI (theo lượt) | 55% | 45% | **55%** |
| Ca độ phủ mới (7045 PsExec, tạo user + Administrators) | không thấy được | 2/2 | **2/2** |
| **Tổng ca tấn công thật bắt được** | 9/16 (56%) | 9/16 (56%) | **11/16 (69%)** |
| `data01` — Hệ thống | 97.5% | 97.5% | 97.5% |
| Độ ổn định (cùng kết quả cả 3 lần) | 13/14 | 13/14 | 13/14 + 2/2 |

Kết quả từng ca của 14 ca gốc ở phiên bản (3) **trùng khớp hoàn toàn** với phiên bản (1).

## Kết luận

1. **Prompt động cho phép mở rộng phạm vi phát hiện mà không làm giảm khả năng cũ** của mô hình nhỏ: tổng số tấn công thật bắt được tăng từ 9/16 lên 11/16, không đánh đổi.
2. Với mô hình 3B, "nhồi" thêm kiến thức vào prompt là có hại; nên đưa kiến thức **theo ngữ cảnh** (chỉ những gì liên quan đến dữ liệu đang xét). Đây là một nguyên tắc thiết kế quan trọng cho AI Agent chạy local.
3. Phần độ phủ mới chủ yếu nhờ **luật mạnh** (dấu hiệu rõ ràng) và được AI xác nhận; các ca khó (Metasploit native, payload Base64 ẩn, Sliver xoá log bằng `wevtutil`) vẫn bị bỏ sót — giới hạn của mô hình 3B.

## Lưu ý về độ tin cậy

- Bộ 16 ca này đã được dùng **ba lần** để ra quyết định thiết kế → con số 69% là của tập phát triển. Đánh giá cuối cùng nên làm trên tập chưa từng dùng (EVTX-ATTACK-SAMPLES).
- Vẫn chưa đo được báo động giả trên log thật (cần log hoạt động bình thường từ máy ảo).
