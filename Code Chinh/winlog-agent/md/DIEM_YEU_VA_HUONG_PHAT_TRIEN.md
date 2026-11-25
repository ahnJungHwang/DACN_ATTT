# Điểm yếu và lộ trình phát triển

> Cập nhật lần cuối: 13/11/2026 (mục #17; các phần khác giữ nguyên từ 07/11).

## Quyết định đã chốt
- **07/11/2026 — Tiếp tục phát triển trên `Code Chinh/`, KHÔNG ghép code của Thắng (`CodeThuNghiem/`, `Thang Code/`).** Lý do: ghép nguyên khối sẽ mất các loại sự kiện đã hỗ trợ (4648, 1102/104, 7045, 4720/4728/4732, 4698), xung đột khi dùng chung Ollama (`EXTERNAL_MODEL_LOADED`, một worker), làm chậm cảnh báo, và vô hiệu các số liệu đã đo. Các mục trong lộ trình (xác thực, cửa sổ trượt, ...) được tự viết trong `Code Chinh`; có thể tham khảo ý tưởng từ `CodeThuNghiem` nhưng không chép nguyên module.

## Hiện trạng (07/11/2026)

| Chỉ số | Giá trị | Ghi chú |
|---|---|---|
| Recall trên log thật (DeepBlueCLI + EVTX-to-MITRE) | **11/16 = 69%** | tập phát triển — đã dùng 3 lần để ra quyết định |
| Recall riêng AI trên log thật (14 ca gốc) | 55% | chỉ luật: 36% |
| `data01` (dữ liệu tự sinh, 40 ca) | 97.5% | lạc quan quá mức, không dùng làm kết luận chính |
| Báo động giả trên log thật | **chưa đo** | thiếu log hoạt động bình thường |

## A. Điểm yếu về phát hiện

| # | Điểm yếu | Mức |
|---|---|:---:|
| 1 | Mỗi lô 5 giây phân tích riêng lẻ (server ghi đè XML mỗi request) → không tương quan qua nhiều lô; brute force chậm không bao giờ đạt ngưỡng ≥3 lần 4625 | Cao |
| 2 | Mô hình 3B bỏ sót tấn công tinh vi (Metasploit native, payload Base64 ẩn, Sliver `wevtutil cl`) | Cao |
| 3 | Mô hình 3B nhạy với độ dài prompt (đã giảm nhờ prompt động) | TB |
| 4 | Độ phủ: chưa thu Sysmon, 4673/4674, WMI, log mạng (8 mẫu DeepBlueCLI vẫn không thấy) | TB |
| 5 | Luật so khớp chuỗi hẹp, dễ né bằng làm rối (`-Enc` vs `-encodedcommand`) | TB |
| 6 | Script block dài → hàng chục lô (316 s/ca); `keep_alive: 0` nạp lại model mỗi lần | Thấp |

## B. Điểm yếu về bảo mật của chính hệ thống

| # | Điểm yếu | Hậu quả |
|---|---|---|
| 7 | `/ingest` không xác thực | log giả, làm ngập server, gây báo động giả |
| 8 | Nhận diện n8n bằng header tự khai báo `x-n8n-request` | kẻ tấn công tự gắn header → bỏ qua n8n, **không có Telegram** |
| 9 | Client bỏ qua kiểm tra chứng chỉ TLS | MITM sửa/chặn log |
| 10 | RecordId cập nhật **trước** khi gửi (`ps1/client_agent.ps1`) | server/mạng lỗi → **mất log vĩnh viễn** |
| 11 | Agent dễ bị tắt / log bị xoá trong 5 s; không có heartbeat | mất khả năng giám sát mà không ai biết |
| 12 | Prompt injection qua nội dung log | kẻ tấn công cài chuỗi điều khiển AI kết luận NORMAL |

## C. Điểm yếu về đánh giá và vận hành

| # | Điểm yếu |
|---|---|
| 13 | Chưa đo báo động giả trên log thật |
| 14 | Tập đánh giá bị dùng lại để chỉnh hệ thống; cỡ mẫu nhỏ, KTC rộng (39–84%) |
| 15 | Nhãn chưa có người chấm thứ hai; vài ca mơ hồ (OpenSSH, IEUser) |
| 16 | Microsoft Defender cách ly log/kết quả và quét bộ nhớ Ollama (AMSI) |
| 17 | Không gom/chống trùng cảnh báo, không quản lý sự cố |
| 18 | Xử lý tuần tự một máy; `results/` tăng không giới hạn |

## Lộ trình

### Ngắn hạn — nên xong trước khi bảo vệ
- [ ] (#10) Chỉ cập nhật RecordId sau khi gửi thành công; lưu đệm ra file khi server lỗi
- [ ] (#7, #8) Xác thực `/ingest` bằng khoá riêng từng client (HMAC); n8n dùng khoá bí mật thay header tự khai báo
- [ ] (#9) Ghim chứng chỉ server ở client
- [ ] (#1) Cửa sổ trượt 5–15 phút theo từng client để tương quan qua nhiều lô
- [ ] (#11) Heartbeat: cảnh báo khi client im lặng quá N phút

### Trung hạn — hoàn thiện đánh giá (quan trọng nhất cho báo cáo)
- [ ] (#13) Thu log hoạt động bình thường từ máy ảo (≈10 phiên, nhãn theo phiên) → đo báo động giả
- [ ] (#14, #15) Đánh giá cuối trên tập CHƯA DÙNG (EVTX-ATTACK-SAMPLES), nhãn chốt trước, người chấm chéo
- [~] So sánh với DeepBlueCLI / Hayabusa / Chainsaw (Sigma) trên cùng dữ liệu — 12/11: DeepBlueCLI đã chạy trên 31 file EVTX thật (`eval_real/run_deepblue.ps1`, bảng ở `eval_real/SO_SANH_CONG_CU.md`). Ca tấn công có dấu vết trong log agent thu: DeepBlueCLI 13/16, Qwen hệ thống 9/14, Llama hệ thống 10/14 (2 ca bị Defender cách ly). **Còn thiếu:** log bình thường thật để đo báo động giả cho cả ba, Hayabusa/Chainsaw.
- [ ] Thử Qwen2.5 7B Q4 (~4.7 GB VRAM), theo dõi nhiệt độ GPU
- [~] (#17) Gom cảnh báo thành sự cố (cùng máy + thời gian + kỹ thuật) — `core/alerting.py` (12/11, cửa sổ trượt 10 phút). 13/11: gom theo mã MITRE cha (riêng Password Spraying T1110.003 giữ khóa riêng), tên AI tự đặt quy về mã hoặc dồn vào một khóa chung; test ở `tests/test_alerting.py`. Chạy lại `results/alerts_log.csv` phiên 11/11 (37 ALERT): 14 → 11 tin. **Còn thiếu:** đo lại trên lab thật rồi sinh lại `results/LATENCY_REPORT.md`; AI vẫn được đặt tên stage tự do (tên lạ đến trước mã của luật thì vẫn ra 2 tin).
- [ ] (#12) Chống prompt injection: đánh dấu log là dữ liệu không tin cậy, kiểm tra chéo bằng luật

### Dài hạn — mở rộng
- [ ] (#4, #5) Sysmon + luật Sigma
- [ ] RAG kiến thức MITRE ATT&CK / Sigma theo từng sự kiện (nối tiếp prompt động)
- [ ] Fine-tune QLoRA trên Colab/Kaggle khi có vài trăm ca có nhãn (không train trên laptop)
- [ ] SOAR có người duyệt: n8n đề xuất cô lập máy / khoá tài khoản, xác nhận qua Telegram
- [ ] Nhiều client: hàng đợi, CSDL sự cố, dashboard tổng hợp

## Đã hoàn thành
- [x] 07/11 — Cấu hình lab (VMnet8), `.env`, workflow n8n + Telegram
- [x] 07/11 — Sửa client: gửi lặp sự kiện (RecordId), kiểm tra admin, lỗi `.bat` (CRLF/BOM, dấu ngoặc)
- [x] 07/11 — AI tham gia quyết định: prompt trung lập, kiểm chứng bằng chứng, tự thẩm định, luật mạnh/yếu
- [x] 07/11 — Đánh giá trên log thật (DeepBlueCLI + EVTX-to-MITRE), nhãn chốt trước, lặp 3 lần, KTC95%
- [x] 07/11 — Mở rộng thu thập (1102/104/7045/4720/4728/4732/4698) + prompt động → 9/16 → 11/16
- [x] 20/11 — (#5) Chuẩn hoá dòng lệnh trước mọi luật (bỏ đường dẫn + `.exe`: trước đây `"C:\...\net.exe" user /add` và `"C:\...\wevtutil.exe" cl` lọt luật) + chữ ký công cụ tấn công (Rubeus, LaZagne, SharpHound, winPEAS, PrintNightmare, tắt firewall/Sysmon, bcdedit, hijack registry, reverse shell, tunnel...). Riêng luật: luật mạnh bắt 49 → 77/150 ca tấn công của benchmark 600 ca, 9 → 10/21 ca log thật (Sliver C2), 0 báo nhầm trên 688 ca bình thường. Benchmark 600 ca đã dùng để tìm lỗi nên không còn là tập kiểm tra độc lập. Chạy lại Qwen (20/11, `results/benchmark600_luat_20112026/`, `eval_real/real_log_results_qwen_20112026.csv`): benchmark recall 48% → 72% (108/150; tấn công thật 51 → 79/80, ca giả lập Invoke-Stage/Invoke-Evasion 21 → 29/70), báo nhầm 3 → 0/450, UNKNOWN 15 → 5; log thật hệ thống 9 → 10/14. Test: `tests/test_signatures.py`.
- [x] 25/11 — Thử cho Qwen / Llama thấy thêm 13 Event ID + hướng dẫn nhận biết nhiễu (chỉnh trên log trước 22/11, khoá prompt, kiểm tra trên 22–24/11, chạy trên Colab T4). Kết quả `eval_real/SO_SANH_TOAN_BO_LOG_full_test.md`: bỏ phần mô tả "hoạt động bình thường" **không làm khác kết quả** (trên đủ 51 cửa sổ: Qwen báo nhầm 10/51 = 19.6% cả hai lượt; Llama 17/51 so với 14/51; đối chứng vẫn giữ điều kiện lọc trong cột dấu hiệu nên chưa đo prompt không hướng dẫn). Thêm ID mới làm báo nhầm tăng mạnh so với 12 ID (55 cửa sổ chung: Qwen 2 → 7, Llama 1 → 12; lẫn cả khác máy và ẩn danh tên) mà không bắt thêm tấn công. Giữ agent 12 ID. Chạy lại y hệt vẫn lệch ~1/24 nhãn. Bước tiếp: fine-tune (mục Dài hạn).

## Bài học đã rút ra (giữ để không lặp lại)
1. Dữ liệu tự sinh cho 97.5–100%, log thật chỉ 64–69%: luôn kiểm tra trên log thật.
2. Prompt cũ nói trước "không phát hiện tấn công" khiến AI gần như luôn trả NORMAL; nhãn ALERT trước đây thực chất do luật.
3. Mô hình 3B bịa sự kiện (vd "nhiều 4625" khi không có) → cần kiểm chứng kết luận với dữ liệu.
4. Thêm kiến thức tĩnh vào prompt làm mất ca cũ → dùng prompt động.
5. Mẫu DeepBlueCLI đều bắt đầu bằng sự kiện xoá log do người tạo mẫu → phải loại, nếu không Recall tăng ảo.
6. Cho mô hình 3B thấy thêm loại sự kiện thì nó nghi ngờ nhiều hơn, không bắt thêm được gì; thêm mô tả "hoạt động bình thường" vào prompt không kéo lại được (25/11). Chênh 1–2 ca giữa hai lượt chạy là trong mức dao động. Khi chấm "cùng tập ca", xem công cụ khác lỗi ở ca nào: ca bị bỏ có thể chứa phần lớn báo nhầm.
