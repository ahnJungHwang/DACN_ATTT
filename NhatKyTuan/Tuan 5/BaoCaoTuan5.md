# Nhật Ký Tuần 5

- **Thời gian thực hiện**: 09/11/2026 - 15/11/2026 (phiên làm việc chính: 10/11 - 12/11/2026)
- **Thành viên tham gia**: Lâm, Thắng

---

# BÁO CÁO BÀI THỰC HÀNH TUẦN 5

**Môn học:** Đồ Án Chuyên Ngành An Toàn Thông Tin

| **Họ và tên:** | Nhan Huỳnh Lâm<br>Trần Minh Thắng | **MSSV:** | 2387700037<br>2387700063 |
| **Lớp:** | 23DATA1 | **Ngày thực hiện:** | 12/11/2026 |

---

## HỆ THỐNG GIÁM SÁT AN NINH WINDOWS EVENT LOG BẰNG AI LOCAL
### Ổn định pipeline Windows → Telegram, chống trùng cảnh báo và đo độ trễ đầu-cuối

### Tóm tắt

Tuần 5 tập trung vào các yêu cầu thầy góp ý sau tuần 4: lấy Security log làm nguồn chính, pipeline từ Windows tới Telegram phải chạy ổn định và **không gửi trùng cảnh báo**, đồng thời **đo độ trễ từ lúc sinh sự kiện tới lúc nhận cảnh báo**.

Nhóm đã sắp xếp lại mã nguồn theo thư mục chức năng, sửa các lỗi vận hành làm pipeline đứt (sai cổng giữa client, server và n8n; server không tắt được; client gửi lặp), rồi bổ sung hai chức năng mới: **chống trùng cảnh báo** theo máy + kỹ thuật MITRE, và **ghi độ trễ đầu-cuối** cho từng lô log.

Kết quả đo trên lab thật (máy ảo Windows 10 → server HTTPS → n8n → Telegram), 54 lô log với 344 sự kiện Security:

- Độ trễ **từ sự kiện đầu tiên tới khi Telegram gửi xong**: trung vị **23,7 s**, P95 **32,9 s**, lớn nhất 33,9 s (13 cảnh báo).
- AI phân tích chiếm khoảng **58%** thời gian; n8n + Telegram dưới **1,3 s**.
- AI kết luận ALERT 37 lần, chỉ **14 lần gửi Telegram**, **23 lần bị chặn vì trùng (62%)**.

---

## Mục lục

1. [Mục tiêu trong tuần](#1-mục-tiêu-trong-tuần)
2. [Công việc chi tiết](#2-công-việc-chi-tiết)
3. [Kết quả đạt được](#3-kết-quả-đạt-được)
4. [Khó khăn và vấn đề gặp phải](#4-khó-khăn--vấn-đề-gặp-phải)
5. [Kế hoạch tuần tiếp theo](#5-kế-hoạch-tuần-tiếp-theo)

---

## 1. Mục Tiêu Trong Tuần

Góp ý của thầy sau tuần 4:

> Đề tài của nhóm gần với nhóm 1, nên nhóm lấy Security log làm nguồn chính và tập trung vào vận hành cảnh báo từ Windows tới Telegram. Dữ liệu đánh giá phải có phần lớn là log bình thường, vì thực tế là vậy. Thầy cần pipeline chạy ổn định và không gửi trùng cảnh báo, bộ đánh giá có nhãn lưu CSV từng ca ngay trong repo, bảng so sánh Qwen, Llama và một công cụ không dùng AI như DeepBlueCLI hoặc Sigma, kèm số đo độ trễ từ lúc sinh sự kiện tới lúc nhận cảnh báo.

Mục tiêu tuần 5:

- [x] Dọn repo, sắp xếp mã nguồn theo thư mục chức năng, viết hướng dẫn sử dụng từng thư mục.
- [x] Chạy lại lab server + client trên máy ảo, sửa các lỗi làm đứt luồng Windows → n8n → Telegram.
- [x] Pipeline ổn định: client không gửi lặp, không mất log khi server tạm ngừng, server tắt gọn.
- [x] **Chống gửi trùng cảnh báo** Telegram.
- [x] **Đo độ trễ đầu-cuối** từ lúc Windows sinh sự kiện tới lúc Telegram gửi xong.
- [x] Rà soát yêu cầu của thầy: phần nào đã có, phần nào còn thiếu.
- [ ] Bộ đánh giá có nhãn (CSV từng ca), đa số là log bình thường → chuyển sang tuần 6.
- [ ] Bảng so sánh Qwen / Llama / DeepBlueCLI (hoặc Sigma) → chuyển sang tuần 6.

---

## 2. Công Việc Chi Tiết

### Lâm:

- [x] Sắp xếp lại repo và viết hướng dẫn (mục 2.1).
- [x] Chạy lab, sửa lỗi kết nối và vận hành (mục 2.2).
- [x] Sửa các lỗi làm pipeline thiếu ổn định (mục 2.3).
- [x] Xây dựng chức năng chống trùng cảnh báo (mục 2.4).
- [x] Xây dựng chức năng đo độ trễ đầu-cuối và script tổng hợp báo cáo (mục 2.5).
- [x] Thêm luật phát hiện Password Spraying (mục 2.6).
- [x] Rà soát yêu cầu của thầy (mục 2.7).

### Thắng:

- [ ] *(Thắng bổ sung phần việc của mình)*

---

### 2.1. Sắp xếp lại repo và viết hướng dẫn

- Xóa các thư mục thử nghiệm không còn dùng: `CodeThuNghiem/`, `Lam Code/`, `Thang Code/` (commit `fbe53ba`). Toàn bộ phát triển tiếp tục trên `Code Chinh/winlog-agent`.
- Chia `winlog-agent` theo chức năng:

```text
winlog-agent/
├── app/            Các phiên bản AI Server (FastAPI): app.py (bản chính), app1-3, app_origin
├── core/           analyze.py (luật + AI), evaluate.py, generate_*.py, alerting.py, latency_report.py
├── web/
│   ├── frontend/   index.html (giao diện SIEM)
│   └── backend/    siem.py, dashboard.py
├── bat/            Các file .bat chạy nhanh (server, client, mô phỏng, n8n)
├── ps1/            client_agent.ps1, stop_client.ps1, extract_evtx_fragments.ps1
├── md/             Tài liệu chung
└── data*, results, blind_test, eval_real, .env, cert.pem, key.pem
```

- Sửa toàn bộ đường dẫn trong code sau khi chuyển file (import Python, `cd` trong `.bat`, `$PSScriptRoot` trong `.ps1`) và kiểm tra lại: 5 phiên bản server đều nạp được, các script đánh giá chạy được.
- Viết **8 file hướng dẫn** `HUONG_DAN_SU_DUNG_<thư mục>.md` cho `app`, `bat`, `core`, `ps1`, `web`, `md`, `blind_test`, `eval_real`; cập nhật đường dẫn trong 3 tài liệu chung.
- Thêm `.vscode/settings.json` để VS Code (Pylance) tìm thấy module trong `core/` và `web/backend/`.

### 2.2. Chạy lab và sửa lỗi kết nối

Cấu hình lab: server là máy thật (VMnet8 `192.168.153.1`, HTTPS cổng **8443**), client là máy ảo Windows 10 `DESKTOP-D38O4BR` (`192.168.153.147`), n8n chạy trong Docker cổng 5678, bot Telegram `@aisoc_winlog_alert_bot`.

| Lỗi gặp phải | Nguyên nhân | Cách xử lý |
|---|---|---|
| Client báo `TCP ... KHONG THONG` | Tường lửa máy thật chưa mở cổng (mạng ở chế độ Public) | Thêm luật inbound cho TCP 8443 |
| Client không gửi được log | `run_client.bat` cũ trên máy ảo trỏ cổng 9443, server chạy 8443 | Thống nhất cổng 8443 |
| n8n báo `ECONNREFUSED ...:9443` | Node **HTTP Request** trong workflow vẫn gọi lại server ở cổng 9443 | Sửa URL thành `https://host.docker.internal:8443/ingest`, **Save + Publish** (n8n 2.x chỉ chạy bản đã Publish) |
| Telegram chưa nhận tin | Credential Telegram trong n8n chưa có token bot mới | Gắn token vào credential đang được workflow sử dụng |

Sau khi sửa, luồng đầy đủ đã chạy: client → server lưu log → n8n → server phân tích AI → n8n IF → Telegram.

### 2.3. Sửa các lỗi làm pipeline thiếu ổn định

| Lỗi | Hậu quả | Cách sửa |
|---|---|---|
| Client chờ server tối đa 300 s, server chờ n8n tới 600 s | Lô phân tích lâu → client tưởng lỗi, **gửi lại cùng lô** → phân tích và cảnh báo lặp | Tăng thời gian chờ của client lên 660 s |
| Server chỉ xóa `security.xml`, `powershell.xml` sau khi phân tích | Sự kiện System (7045, 104) trong `system.xml` **bị phân tích lại** ở lô sau | Xóa cả 3 file XML sau khi đọc |
| Log bị xóa (1102/104) có thể đánh số RecordId lại từ đầu | Client bỏ sót chính sự kiện "xóa log" | Client phát hiện RecordId mới nhỏ hơn mốc đã gửi thì đặt lại mốc |
| `stop_client.bat` cần `client_agent.pid` nhưng agent không tạo file này | Không tắt được agent bằng file .bat | Agent ghi PID lúc khởi động; `ps1/stop_client.ps1` xác nhận đúng tiến trình agent rồi mới tắt (không tắt nhầm chương trình khác dùng lại PID cũ) |
| `Ctrl+C` không tắt được server / báo `ERROR: Cancel 0 running task(s)` | Cơ chế báo dừng cho trang SIEM không chạy với uvicorn 0.54; kết nối HTTPS rảnh chờ client chào tạm biệt TLS tới 30 s | Thêm `--timeout-graceful-shutdown 3`; móc vào `Server.shutdown` để dừng luồng SIEM và đóng ngay các kết nối đã trả lời xong. Đo lại: tắt trong **0,7 s**, không còn lỗi; request đang phân tích dở vẫn trả `200 OK` |

Ngoài ra, client đã giữ lại log khi server tạm ngừng và gửi bù khi server chạy lại. Phiên đo ngày 11/11 ghi nhận một lô như vậy: server tắt khoảng 10 phút, sự kiện tấn công lúc 23:37 vẫn được gửi và cảnh báo lúc 23:43, **không mất log**.

### 2.4. Chống gửi trùng cảnh báo

Module mới `core/alerting.py`, gắn vào bước phân tích của `app/app.py`:

- Mỗi kết luận ALERT được gom theo khóa **(máy client, kỹ thuật MITRE)**.
- Khóa chưa có, hoặc đã im lặng quá **10 phút** → **sự cố mới** → gửi Telegram.
- Khóa đang mở → **trùng** → chỉ tăng bộ đếm, không gửi. Mỗi lần trùng, sự cố được gia hạn (cửa sổ trượt): tấn công còn tiếp diễn thì không gửi lại.
- Lô có thêm **kỹ thuật mới** so với sự cố đang mở → vẫn gửi, vì có thông tin mới.
- Tên kỹ thuật AI ghi không kèm mã (ví dụ "Password Brute Force") được quy về mã MITRE, để một cuộc tấn công không bị tách thành nhiều sự cố.
- Trạng thái lưu ở `results/alert_state.json`, nên khởi động lại server không gửi lại cảnh báo cũ.
- Mọi quyết định ghi vào `results/alerts_log.csv` làm bằng chứng.
- **Không phải sửa workflow n8n**: cảnh báo trùng trả nhãn `ALERT_DUPLICATE` cho n8n nên node IF (`label == "ALERT"`) tự rẽ nhánh không gửi. Nhãn thật vẫn giữ trong `true_label`, trang SIEM và CSV.
- Cửa sổ gom trùng chỉnh bằng biến `ALERT_DEDUP_MINUTES` trong `.env`.

### 2.5. Đo độ trễ đầu-cuối

Mỗi lô log được ghi một dòng vào `results/latency.csv` với các mốc:

```text
Windows ghi sự kiện ─① gom & gửi─► client gửi ─②─► server nhận ─③─► n8n gọi lại ─④ AI─► AI xong ─⑤─► Telegram gửi xong
   (đồng hồ máy ảo)                                  (đồng hồ máy thật)
```

- Mốc cuối chính xác vì webhook n8n trả lời ở chế độ `lastNode`: n8n chỉ trả lời server sau khi node Telegram đã gửi xong.
- **Bù lệch đồng hồ** giữa máy ảo và máy thật theo kiểu NTP. Mỗi lô có: giờ server nhận − giờ client gửi = lệch đồng hồ + trễ truyền. Trễ truyền luôn ≥ 0, nên lệch đồng hồ thật ≈ **giá trị nhỏ nhất** của hiệu này. Đo được: máy ảo lệch **+0,377 s** so với máy thật. Phần dư của từng lô được tính vào chặng ② "truyền tải".
- Script `core/latency_report.py` tổng hợp ra `results/LATENCY_REPORT.md`, `latency_summary.csv` (min / trung vị / trung bình / P95 / max) và `latency_alerts.csv` (từng cảnh báo).
- Lô có sự kiện phải chờ ở client trên 60 s (server đang ngừng) được tách riêng thành "tồn đọng", không tính vào thống kê vận hành bình thường.

### 2.6. Luật phát hiện Password Spraying

Thêm luật **Password Spraying (MITRE T1110.003)** vào `core/analyze.py`: đăng nhập thất bại (4625) trên **từ 3 tài khoản khác nhau** trong cùng lô. Luật này bổ sung cho luật brute-force cũ (nhiều lần sai trên một tài khoản), phục vụ hướng lấy Security log làm nguồn chính.

### 2.7. Rà soát yêu cầu của thầy

| # | Yêu cầu | Hiện trạng sau tuần 5 |
|---|---|---|
| 1 | Security log là nguồn chính, cảnh báo Windows → Telegram | ✅ Luồng chạy ổn định. Client thu 9 loại sự kiện Security; phiên đo có 344/471 sự kiện là Security |
| 2 | Dữ liệu đánh giá đa số là log bình thường | ❌ Chưa có: `data01` 25 ALERT / 15 NORMAL; `data100` 46 / 54 |
| 3 | Pipeline ổn định, không gửi trùng cảnh báo | ✅ Đã làm (mục 2.3, 2.4) |
| 4 | Bộ đánh giá có nhãn, CSV từng ca trong repo | 🟡 Nhãn đang rải rác trong `manifest.json`; chưa có CSV chung |
| 5 | So sánh Qwen / Llama / công cụ không dùng AI | 🟡 Đã có Qwen vs Llama (trên dữ liệu tự sinh); chưa chạy DeepBlueCLI / Sigma |
| 6 | Độ trễ từ sinh sự kiện tới nhận cảnh báo | ✅ Đã đo (mục 3) |

---

## 3. Kết Quả Đạt Được

Phiên đo: 11/11/2026 23:27 → 12/11/2026 00:08, client `DESKTOP-D38O4BR`, mô hình **Qwen 2.5 3B**, luồng qua n8n. Tổng **54 lô log**, **471 sự kiện**, trong đó **344 sự kiện Security**. Các kịch bản chạy từ `simulate_attacks_demo2.bat`: brute-force, PowerShell download cradle, tạo backdoor + thêm quyền admin, trinh sát.

### 3.1. Độ trễ đầu-cuối (giây)

Vận hành bình thường (đã loại 1 lô tồn đọng do server ngừng):

| Nhóm | Số lô | Sự kiện đầu → cảnh báo<br>trung vị / P95 / max | Sự kiện cuối → cảnh báo<br>trung vị / P95 / max |
|---|---:|---:|---:|
| **Cảnh báo đã gửi Telegram** | 13 | **23,7** / 32,9 / 33,9 | **12,6** / 27,2 / 27,9 |
| ALERT bị chặn vì trùng | 23 | 18,3 / 27,6 / 28,6 | 11,6 / 21,3 / 22,5 |
| NORMAL (không cảnh báo) | 17 | 19,4 / 32,2 / 34,7 | 14,5 / 30,4 / 31,6 |
| Tất cả các lô | 53 | 20,3 / 31,9 / 34,7 | 12,5 / 28,5 / 31,6 |

- **Sự kiện đầu → cảnh báo**: tính từ sự kiện sớm nhất của lô; đây là con số chính.
- **Sự kiện cuối → cảnh báo**: tính từ sự kiện muộn nhất của lô, thường là bước tấn công cuối cùng.

### 3.2. Phân rã theo từng chặng (cảnh báo đã gửi, 13 lô)

| Chặng | Trung vị | P95 | Tỉ trọng trung bình |
|---|---:|---:|---:|
| ① Client gom & gửi | 3,6 s | 13,5 s | 31% |
| ② Truyền tải (sau bù đồng hồ) | 0,0 s | 4,9 s | 6% |
| ③ n8n gọi lại server | 0,1 s | 0,1 s | ~0% |
| ④ **AI phân tích** (luật + Qwen) | **8,3 s** | 14,1 s | **58%** |
| ⑤ n8n + Telegram | 0,8 s | 1,1 s | 5% |

Nhận xét:
- **AI là chặng chậm nhất.** Lô có nhiều sự kiện PowerShell 4104 mất khoảng 11–14 s; lô brute-force nhỏ chỉ khoảng 7–8 s.
- **Client chiếm khoảng 1/3.** Agent quét log mỗi 5 s và gửi tuần tự: sự kiện sinh ra trong lúc agent đang chờ server trả lời lô trước phải đợi sang lô sau.
- **n8n + Telegram rất nhanh** (dưới 1,3 s), không phải điểm nghẽn.

### 3.3. Từng cảnh báo đã gửi Telegram

| # | Giờ nhận | Kỹ thuật | Trạng thái | Sự kiện (Security) | Sự kiện đầu → cảnh báo |
|---:|---|---|---|---:|---:|
| 1 | 11/11 23:28:57 | T1059.001 | NEW | 10 (7) | 25,3 s |
| 2 | 11/11 23:29:19 | T1098/T1136 | NEW | 11 (10) | 29,9 s |
| 3 | 11/11 23:30:23 | T1110 | NEW | 5 (4) | 10,2 s |
| 4 | 11/11 23:32:06 | T1033 | NEW_TECHNIQUE | 7 (3) | 19,5 s |
| 5 | 11/11 23:43:44 ⚠ | PowerShell execution | NEW (tồn đọng) | 38 (36) | 378,0 s |
| 6 | 11/11 23:44:03 | Tạo tiến trình mới | NEW | 10 (9) | 27,7 s |
| 7 | 11/11 23:44:33 | T1059.001 | NEW | 16 (7) | 32,2 s |
| 8 | 11/11 23:44:56 | T1110; T1033 | NEW | 10 (7) | 17,1 s |
| 9 | 11/11 23:45:11 | T1098/T1136 | NEW_TECHNIQUE | 8 (6) | 22,1 s |
| 10 | 12/11 00:00:14 | PowerShell ScriptBlock | NEW | 12 (11) | 31,1 s |
| 11 | 12/11 00:00:35 | T1059.001 | NEW | 16 (7) | 33,9 s |
| 12 | 12/11 00:01:05 | T1098/T1136 | NEW | 5 (4) | 23,7 s |
| 13 | 12/11 00:01:36 | T1110 | NEW | 5 (4) | 11,6 s |
| 14 | 12/11 00:01:51 | T1033 | NEW_TECHNIQUE | 11 (7) | 23,1 s |

⚠ Cảnh báo #5: server tắt từ khoảng 23:33 tới 23:43 để cập nhật mã. Agent giữ sự kiện lúc 23:37 lại và gửi bù khi server chạy lại, nên **không mất log**. Lô này không phản ánh độ trễ vận hành bình thường và đã được tách khỏi thống kê ở mục 3.1–3.2.

Brute-force (T1110) luôn nhanh nhất (khoảng 10–12 s) vì lô nhỏ và luật nhận ra ngay. Các lô có PowerShell chậm hơn (khoảng 30 s) vì nhiều sự kiện hơn.

### 3.4. Chống trùng cảnh báo

| Chỉ số | Giá trị |
|---|---:|
| Số kết luận ALERT của AI | 37 |
| Gửi Telegram (sự cố mới / có kỹ thuật mới) | 14 |
| **Bị chặn vì trùng** | **23 (62%)** |
| Số sự cố riêng biệt (máy + kỹ thuật MITRE) | 14 |
| Cửa sổ gom trùng | 10 phút (trượt) |

So với tuần 4 (Hình 33: cùng một kịch bản sinh 3 kết luận ALERT liên tiếp trong 41 giây; Hình 30: Telegram nhận 2 tin trùng nội dung), giờ mỗi kỹ thuật trên một máy chỉ sinh **1 tin** trong suốt thời gian tấn công còn tiếp diễn.

### 3.5. Tệp kết quả trong repo

| Tệp | Nội dung |
|---|---|
| `Code Chinh/winlog-agent/results/LATENCY_REPORT.md` | Báo cáo độ trễ và chống trùng đầy đủ |
| `Code Chinh/winlog-agent/results/latency_summary.csv` | Bảng thống kê độ trễ (min / trung vị / trung bình / P95 / max) |
| `Code Chinh/winlog-agent/results/latency_alerts.csv` | Chi tiết từng cảnh báo đã gửi |
| `Code Chinh/winlog-agent/results/latency.csv` | Dữ liệu thô, mỗi lô log một dòng |
| `Code Chinh/winlog-agent/results/alerts_log.csv` | Mỗi kết luận ALERT một dòng (NEW / DUPLICATE) |

Tạo lại báo cáo sau mỗi lần demo:

```powershell
cd "H:\Nam 4\DACN\Demo\Code Chinh\winlog-agent"
.\.venv\Scripts\python.exe core\latency_report.py
```

---

## 4. Khó Khăn & Vấn Đề Gặp Phải

- **Cấu hình cổng không thống nhất** giữa ba nơi (client, server, node HTTP Request trong n8n): một chỗ sai là luồng đứt mà thông báo lỗi không chỉ rõ nguyên nhân. Đã thống nhất cổng 8443.
- **n8n 2.x phân biệt bản nháp và bản đã Publish**: sửa workflow rồi bấm Save chưa đủ, webhook vẫn chạy bản cũ cho tới khi Publish.
- **Đồng hồ máy ảo và máy thật lệch nhau**: phải bù lệch mới đo được độ trễ đầu-cuối. Có một lô bị trễ truyền 12 s, ban đầu bị tính nhầm thành lệch đồng hồ; đã chuyển sang cách bù kiểu NTP (lấy giá trị nhỏ nhất).
- **AI đôi khi ghi tên kỹ thuật không kèm mã MITRE** ("powershell execution", "tạo tiến trình mới"): chống trùng vẫn đúng nhờ chuẩn hóa tên, nhưng nội dung cảnh báo chưa thống nhất.
- **Số mẫu còn ít**: 13 cảnh báo vận hành bình thường; cần khoảng 20 trở lên để P95 đáng tin.
- **Dữ liệu demo nghiêng về tấn công**: chưa đo được tỉ lệ báo động giả trên log bình thường, đúng như thầy nhận xét.
- Một số lệnh hệ thống (mở tường lửa, ghi credential n8n) cần quyền quản trị và phải thao tác tay.

---

## 5. Kế Hoạch Tuần Tiếp Theo

1. **Bộ đánh giá có nhãn, đa số log bình thường** (yêu cầu 2 và 4 của thầy):
   - Thu log hoạt động bình thường thật từ máy ảo (nhiều phiên làm việc, mỗi phiên 15–30 phút).
   - Ghép với ca tấn công từ kịch bản Security và EVTX-ATTACK-SAMPLES, tỉ lệ khoảng **80–90% bình thường**.
   - Lưu nhãn từng ca vào **một file CSV** trong repo (`case_id, label, kỹ thuật, nguồn, số sự kiện`).
2. **So sánh với công cụ không dùng AI** (yêu cầu 5): chạy **DeepBlueCLI** (đọc Security log) trên cùng bộ dữ liệu. Lập bảng **Qwen / Llama / DeepBlueCLI** gồm Precision, Recall, tỉ lệ báo động giả, độ trễ.
3. **Bổ sung mẫu đo độ trễ** lên trên 20 cảnh báo; chạy các kịch bản cách nhau trên 10 phút để mỗi lần đều có cảnh báo mới.
4. **Mở rộng kịch bản thuần Security log**: đăng nhập thành công sau brute-force (4625 → 4624), password spraying, xóa Security log (1102), scheduled task (4698), thêm vào nhóm đặc quyền (4732). Kèm kịch bản log bình thường để đo báo động giả.
5. **Cải thiện nội dung tin Telegram**: luôn ghi mã MITRE, kèm mã sự cố (`INC-...`) và số lần lặp; giảm độ trễ chặng AI (giữ mô hình trong bộ nhớ Ollama giữa các lô).

---

## Tài liệu sử dụng

[1] Mã nguồn và kết quả đo: `Code Chinh/winlog-agent/` (các tệp trong `results/` nêu ở mục 3.5).

[2] Hướng dẫn từng thư mục: `Code Chinh/winlog-agent/md/HUONG_DAN_SU_DUNG_md.md` (mục lục các file `HUONG_DAN_SU_DUNG_*.md`).

[3] MITRE ATT&CK: https://attack.mitre.org/

## Góp ý của thầy:
