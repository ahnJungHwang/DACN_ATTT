# Điểm yếu và lộ trình phát triển

> Cập nhật lần cuối: 07/11/2026. 

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
| 10 | RecordId cập nhật **trước** khi gửi (`client_agent.ps1`) | server/mạng lỗi → **mất log vĩnh viễn** |
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
- [ ] So sánh với DeepBlueCLI / Hayabusa / Chainsaw (Sigma) trên cùng dữ liệu
- [ ] Thử Qwen2.5 7B Q4 (~4.7 GB VRAM), theo dõi nhiệt độ GPU
- [ ] (#17) Gom cảnh báo thành sự cố (cùng máy + thời gian + kỹ thuật)
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

## Bài học đã rút ra (giữ để không lặp lại)
1. Dữ liệu tự sinh cho 97.5–100%, log thật chỉ 64–69%: luôn kiểm tra trên log thật.
2. Prompt cũ nói trước "không phát hiện tấn công" khiến AI gần như luôn trả NORMAL; nhãn ALERT trước đây thực chất do luật.
3. Mô hình 3B bịa sự kiện (vd "nhiều 4625" khi không có) → cần kiểm chứng kết luận với dữ liệu.
4. Thêm kiến thức tĩnh vào prompt làm mất ca cũ → dùng prompt động.
5. Mẫu DeepBlueCLI đều bắt đầu bằng sự kiện xoá log do người tạo mẫu → phải loại, nếu không Recall tăng ảo.
