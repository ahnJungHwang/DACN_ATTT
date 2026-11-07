# 🛡️ HƯỚNG DẪN CÀI ĐẶT, CẤU HÌNH VÀ VẬN HÀNH DỰ ÁN
## HỆ THỐNG GIÁM SÁT AN NINH WINDOWS EVENT LOG BẰNG AI AGENT (LOCAL SLM)

---

## 📌 TỔNG QUAN KIẾN TRÚC CLIENT - SERVER

Hệ thống được thiết kế theo mô hình **SOC / EDR phân tán**:
* **Máy AI SERVER (`192.168.147.1`)**: Máy chủ trung tâm chịu trách nhiệm chạy Local SLM (Ollama), phân tích tương quan sự kiện, nhận định nguy cơ và tự động gửi cảnh báo khẩn cấp tới Telegram.
* **Máy CLIENT (`192.168.147.136`)**: Máy trạm cần giám sát, chạy Agent thu thập log bằng PowerShell siêu nhẹ. **Không cần cài Python, không cần cài Ollama, không tốn tài nguyên.**

```
┌──────────────────────────────────────┐             ┌─────────────────────────────────────────┐
│     MÁY CLIENT (192.168.147.136)     │             │       MÁY SERVER (192.168.147.1)        │
│                                      │             │                                         │
│  [Windows Event Log: Security + PS]  │             │   [FastAPI Server - app.py (Port 8000)] │
│                  │                   │             │                      │                  │
│       (Định kỳ 15 giây/lần)          │             │                      ▼                  │
│                  ▼                   │             │   [Correlation Engine + Ollama SLM]     │
│         [client_agent.ps1]           │             │          (Model: qwen2.5:3b)            │
│                  │                   │             │                      │                  │
│                  └──── Gửi HTTP POST ─────────────►│                      ▼                  │
│                        (Port 8000)   │             │             Kết luận: ALERT?            │
└──────────────────────────────────────┘             │                      │                  │
                                                     │                      ▼                  │
                                                     │         [Telegram Bot Notification]     │
                                                     └──────────────────────┬──────────────────┘
                                                                            │
                                                                            ▼
                                                                📱 Điện thoại chuyên viên SOC
```

---

## 🖥️ PHẦN 1: CẤU HÌNH TRÊN MÁY AI SERVER (`192.168.147.1`)

Máy Server cần cài đặt môi trường AI và ứng dụng phân tích trung tâm.

### 1. Cài đặt Ollama & Tải Model AI
1. Tải và cài đặt Ollama từ trang chủ: [https://ollama.com/download/windows](https://ollama.com/download/windows).
2. Sau khi cài xong, mở PowerShell trên Server và tải mô hình SLM:
   ```powershell
   ollama pull qwen2.5:3b-instruct-q4_K_M
   ```
3. Đảm bảo Ollama đang chạy ngầm (biểu tượng con Lạc đà ở khay Taskbar góc phải màn hình).

---

### 2. Cài đặt Python & Thư viện dự án
1. Cài đặt Python 3.10 trở lên (nhớ tích chọn **"Add python.exe to PATH"** khi cài).
2. Mở PowerShell tại thư mục dự án `winlog-agent` và tạo môi trường ảo:
   ```powershell
   cd winlog-agent
   python -m venv .venv
   .\.venv\Scripts\pip install -r requirements.txt
   ```

---

### 3. Mở cổng tường lửa Windows (Firewall Port 8000)
Để máy Client (`192.168.147.136`) có thể đẩy log sang Server qua cổng `8000`, mở PowerShell với quyền **Administrator** trên Server và chạy lệnh:
```powershell
New-NetFirewallRule -DisplayName "WinLog Agent Server (Port 8000)" -Direction Inbound -LocalPort 8000 -Protocol TCP -Action Allow
```

---

### 4. Hướng dẫn tạo và cấu hình Telegram Bot nhận cảnh báo (Chi tiết từ đầu)

Để hệ thống có thể tự động gửi thông báo khẩn cấp về điện thoại hoặc máy tính của bạn khi phát hiện tấn công, hãy làm theo 4 bước sau:

#### Bước 4.1 — Tạo Bot mới qua BotFather
1. Mở ứng dụng **Telegram** (hoặc truy cập [Telegram Web](https://web.telegram.org)).
2. Tại ô tìm kiếm (Search), gõ tìm kiếm: **`@BotFather`** *(chú ý chọn tài khoản chính thức có dấu tích xanh xác thực của Telegram)*.
3. Bấm nút **START** (hoặc gõ gửi lệnh `/start`).
4. Gửi tiếp lệnh: **`/newbot`**
5. BotFather sẽ yêu cầu nhập tên hiển thị của Bot:
   - Gõ tên bất kỳ bạn thích, ví dụ: `SOC Alert Bot` hoặc `AI Log Monitoring`.
6. BotFather sẽ yêu cầu nhập **Username** cho Bot (bắt buộc phải kết thúc bằng chữ `bot` hoặc `_bot`):
   - Ví dụ: `my_soc_alert_bot` hoặc `winlog_detector_bot`.
7. Khi tạo thành công, BotFather sẽ gửi lại một thông điệp kèm chuỗi mã **HTTP API Token** có dạng:
   ```text
   Use this token to access the HTTP API:
   1234567890:AAH_xxx_ABCdef1234567890XYZ
   ```
   👉 Hãy lưu lại chuỗi này, đây chính là **`TELEGRAM_BOT_TOKEN`**.

---

#### Bước 4.2 — Lấy Chat ID của bạn (Nơi nhận tin nhắn)
Bot cần biết ID tài khoản của bạn để gửi thông báo riêng tư:
1. Tại ô tìm kiếm của Telegram, gõ tìm: **`@userinfobot`**
2. Bấm vào bot có tên **User Info Bot** và bấm **START**.
3. Bot sẽ phản hồi lại ngay thông tin tài khoản của bạn, trong đó có một dòng số:
   ```text
   Id: 987654321
   ```
   👉 Hãy copy dãy số đó, đây chính là **`TELEGRAM_CHAT_ID`**.

*(Lưu ý nếu muốn gửi vào Group Telegram của đội ngũ SOC: Thêm bot vừa tạo vào Group, cấp quyền gửi tin, sau đó lấy Chat ID của Group dạng số âm, ví dụ `-1001234567890`).*

---

#### Bước 4.3 — Kích hoạt Bot (Rất quan trọng - Tránh lỗi `Chat not found`)
Telegram có chính sách bảo mật chống spam: **Bot không được phép tự ý gửi tin nhắn cho người dùng nếu người dùng đó chưa từng chủ động mở lời với bot.**
1. Tìm kiếm con bot bạn vừa tạo ở Bước 4.1 (ví dụ `@my_soc_alert_bot`).
2. Bấm nút **START** ở dưới cùng khung chat (hoặc gửi tin nhắn bất kỳ như `hi` hay `alo`).
3. Sau khi bạn đã gửi tin nhắn mở đầu, bot đã sẵn sàng gửi cảnh báo cho bạn.

---

#### Bước 4.4 — Cấu hình Token và Chat ID vào hệ thống
Trên máy Server, bạn có 2 cách để cấu hình thông số vừa lấy được:

* **Cách 1 (Sửa trực tiếp trong code - Nhanh nhất)**:
  Mở file `app.py` bằng Notepad hoặc VSCode, tìm đến dòng cấu hình Telegram và thay thế giá trị của bạn vào:
  ```python
  TELEGRAM_BOT_TOKEN = "ĐIỀN_TOKEN_BOT_VỪA_LẤY_Ở_BƯỚC_4.1_VÀO_ĐÂY"
  TELEGRAM_CHAT_ID = "ĐIỀN_CHAT_ID_VỪA_LẤY_Ở_BƯỚC_4.2_VÀO_ĐÂY"
  ```

* **Cách 2 (Dùng biến môi trường - Khuyên dùng trong sản xuất)**:
  Thiết lập biến môi trường trên Windows PowerShell trước khi chạy server:
  ```powershell
  $env:TELEGRAM_BOT_TOKEN = "ĐIỀN_TOKEN_BOT_VÀO_ĐÂY"
  $env:TELEGRAM_CHAT_ID = "ĐIỀN_CHAT_ID_VÀO_ĐÂY"
  ```

---

### 5. Khởi động Server
Trên máy Server, bạn chỉ cần click đúp vào file:
👉 **`run_server.bat`**

Cửa sổ sẽ hiện lên và giữ nguyên trạng thái lắng nghe:
```text
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```
*(Hãy luôn giữ cửa sổ này chạy khi thực hiện giám sát).*

---

## 💻 PHẦN 2: CẤU HÌNH TRÊN MÁY CLIENT (`192.168.147.136`)

Máy Client **hoàn toàn không cần cài đặt Python hay thư viện ngoài**.

### 1. Chuẩn bị thư mục Client
Tạo một thư mục trên máy Client (ví dụ `C:\winlog-client`) và copy **4 file** sau từ Server sang:
1. `setup_client.bat`: Script bật chính sách Audit ghi log Windows.
2. `run_client.bat`: File 1-click khởi chạy Agent.
3. `client_agent.ps1`: Script thu thập và gửi log thời gian thực.
4. `simulate_attack.bat`: Script mô phỏng chuỗi tấn công để thử nghiệm.

---

### 2. Bật chính sách Audit log của Windows (Chỉ chạy 1 lần duy nhất)
Windows mặc định không ghi lại chi tiết dòng lệnh và PowerShell. Để hệ thống có log phân tích:
1. Vào thư mục `C:\winlog-client`.
2. **Click chuột phải** vào file **`setup_client.bat`** ➔ Chọn **`Run as administrator`**.
3. Cửa sổ chạy khoảng 3 giây báo `[✓] CAU HINH HOAN TAT!` là xong.

---

### 3. Khởi chạy Agent giám sát thời gian thực
1. **Click chuột phải** vào file **`run_client.bat`** ➔ Chọn **`Run as administrator`**.
2. Màn hình Client sẽ hiển thị trạng thái kết nối tới Server:
   ```text
   ======================================================================
      WINLOG CLIENT AGENT - GIAM SAT VA DAY LOG VE SERVER
   ======================================================================
    - Client Hostname    : WINLAB
    - Client IP          : 192.168.147.136
    - AI Server URL      : http://192.168.147.1:8000/ingest
    - Chu ky quet        : 15 giay/lan
   ----------------------------------------------------------------------
   [*] Dang ket noi thu toi AI Server...
   [OK] Ket noi toi AI Server thanh cong! Model: qwen, llama

   [*] Bat dau thu thap va day log thoi gian thuc...
   [07:10:00] (Lan 1) Dang theo doi... Khong co su kien moi.
   [07:10:15] (Lan 2) Dang theo doi... Khong co su kien moi.
   ```
*(Lúc này Client đang giám sát ngầm, sẵn sàng đẩy dữ liệu ngay khi có sự cố).*

---

## 🎯 PHẦN 3: KỊCH BẢN DEMO MÔ PHỎNG TẤN CÔNG

Để kiểm tra hệ thống hoạt động thực tế từ đầu đến cuối:

### 1. Thực thi kịch bản tấn công trên Client
Trong khi cửa sổ `run_client.bat` vẫn đang chạy:
1. **Click chuột phải** vào file **`simulate_attack.bat`** (trên máy Client) ➔ Chọn **`Run as administrator`**.
2. File này sẽ tự động mô phỏng 3 kỹ thuật tấn công thực tế:
   - **Tấn công dò mật khẩu (Brute-force)**: Gây ra 5 lỗi đăng nhập thất bại liên tiếp (Event 4625).
   - **PowerShell thực thi mã độc từ xa (Download Cradle)**: Thực thi lệnh nguy hiểm (Event 4104).
   - **Tạo backdoor user & leo thang Admin**: Chạy lệnh `net user /add` và `net localgroup Administrators /add` (Event 4688).
   - Tự động dọn dẹp tài khoản test sau 5 giây để giữ sạch hệ thống.

---

### 2. Quan sát chuỗi phản ứng liên hoàn của hệ thống

#### Tại máy Client (`192.168.147.136`):
Trong vòng 15 giây, Agent phát hiện log và đẩy sang Server:
```text
[07:11:15] [PHAT HIEN SU KIEN] Security: 10 | PowerShell: 9
  -> Dang dong goi va gui ve AI Server (http://192.168.147.1:8000/ingest)...
  [OK] Da day 19 su kien log len AI Server thanh cong!
```

#### Tại máy Server (`192.168.147.1`):
Server tiếp nhận log, kích hoạt AI Qwen suy luận và phân tích tương quan:
```text
[+] Nhan log tu Client WINLAB (192.168.147.136) gom 19 su kien.
[*] Dang chay Local SLM (qwen) phan tich tuong quan...
[!] Ket qua AI: ALERT (14.03s)
[!] PHAT HIEN TAN CONG! Dang ban canh bao ve Telegram...
[✓] Da gui canh bao Telegram thanh cong!
```

#### Tại Telegram:
Điện thoại/máy tính của bạn sẽ rung chuông và nhận ngay tin nhắn:
> 🚨 **CẢNH BÁO BẢO MẬT TỪ CLIENT** 🚨  
> 🖥️ **Máy Client:** `WINLAB` (`192.168.147.136`)  
> 🕒 **Thời gian:** `2026-10-21 21:42:29`  
> ⚠️ **Trạng thái:** `ALERT`  
> ⏱️ **Thời gian AI xử lý:** 14.03s  
> 🎯 **Giai đoạn:** `Credential Access, Persistence, Privilege Escalation`  
> 📝 **Chi tiết phát hiện:** Phát hiện 5 lần đăng nhập thất bại liên tiếp (Event 4625) nhằm vào tài khoản 'fake_hacker_test'; lệnh tạo backdoor user và gán quyền Administrators; lệnh PowerShell tải mã độc từ xa.  
> 🔍 **Bằng chứng:** `E0008, E0009, E0010, E0011, E0012, E0022, E0024...`

---

## 🛠️ PHẦN 4: KHẮC PHỤC SỰ CỐ THƯỜNG GẶP (TROUBLESHOOTING)

| Tình trạng | Nguyên nhân | Cách xử lý |
|---|---|---|
| **Client báo: `[!] CANH BAO: Chua ket noi duoc toi AI Server`** | Tường lửa trên Server chặn cổng 8000 hoặc Server chưa bật. | 1. Đảm bảo file `run_server.bat` đang chạy trên Server.<br>2. Chạy lệnh mở cổng 8000 trong PowerShell Admin trên Server (xem Bước 1.3). |
| **Cửa sổ CMD trên Client đứng yên, không quét tiếp** | Người dùng click chuột vào cửa sổ CMD gây ra chế độ **Select/QuickEdit** (Windows đóng băng tiến trình). | Bấm vào cửa sổ CMD và ấn phím **`ENTER`** (hoặc click chuột phải) để thoát trạng thái bôi đen. |
| **Telegram không nhận được tin nhắn** | Tài khoản Telegram chưa bấm `START` với bot. | Mở cuộc trò chuyện với con Bot của bạn và bấm nút **START** (hoặc gửi tin nhắn bất kỳ cho bot). |
| **Client không bắt được sự kiện sau khi chạy lệnh tấn công** | Chưa chạy `setup_client.bat` bằng quyền Administrator. | Click chuột phải `setup_client.bat` chọn **Run as administrator** để Windows bật tính năng ghi log. |

---

## 📁 BẢNG TỔNG HỢP DANH MỤC FILE DỰ ÁN

| File | Máy chạy | Chức năng |
|---|---|---|
| **`app.py`** | Server | API nhận log, tích hợp Qwen AI và Telegram Alert. |
| **`analyze.py`** | Server | Lõi phân tích tương quan sự kiện, tiền lọc nhiễu, prompt AI. |
| **`generate_data01.py`** | Server | Script tự động khởi tạo bộ Benchmark 40 ca kiểm thử chuẩn vào thư mục `data01/`. |
| **`evaluate.py`** | Server | Script tự động chạy benchmark so sánh Qwen và Llama, tính Precision/Recall/F1. |
| **`run_evaluation.bat`** | Server | File 1-click khởi chạy đánh giá so sánh và xuất báo cáo CSV/Markdown. |
| **`run_server.bat`** | Server | File 1-click khởi động Server API cổng 8000. |
| **`setup_client.bat`** | Client | File 1-click bật chính sách Windows Audit (Process Creation, PowerShell). |
| **`run_client.bat`** | Client | File 1-click khởi chạy Agent thu gom log. |
| **`client_agent.ps1`** | Client | Script quét Windows Event Log mỗi 15s và đẩy sang Server. |
| **`simulate_attack.bat`** | Client | File mô phỏng 3 chuỗi tấn công thực tế (tự động dọn dẹp). |
