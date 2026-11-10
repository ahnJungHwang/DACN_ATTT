# 🛡️ HƯỚNG DẪN CÀI ĐẶT, CẤU HÌNH VÀ VẬN HÀNH DỰ ÁN
## HỆ THỐNG GIÁM SÁT AN NINH WINDOWS EVENT LOG BẰNG AI AGENT (LOCAL SLM)

---

## 📌 TỔNG QUAN KIẾN TRÚC CLIENT - SERVER

Hệ thống được thiết kế theo mô hình **SOC / EDR phân tán**:
* **Máy AI SERVER (`192.168.147.1`)**: Máy chủ trung tâm chịu trách nhiệm chạy Local SLM (Ollama), phân tích tương quan sự kiện, nhận định nguy cơ và tự động gửi cảnh báo khẩn cấp tới Telegram.
* **Máy CLIENT (`192.168.147.136`)**: Máy trạm cần giám sát, chạy Agent thu thập log bằng PowerShell siêu nhẹ. **Không cần cài Python, không cần cài Ollama, không tốn tài nguyên.**

```
┌──────────────────────────────────────┐             ┌──────────────────────────────────────────────────┐
│     MÁY CLIENT (192.168.153.147)     │             │            MÁY SERVER (192.168.153.1)            │
│                                      │             │                                                  │
│  [Windows Event Log: Security + PS]  │             │   [FastAPI Server - app/app.py (Port 8000/9443)] │
│                  │                   │             │                      │                           │
│       (Định kỳ 5-15s/lần)            │             │                      ▼                           │
│                  ▼                   │             │   [Correlation Engine + Ollama Local SLM]        │
│       [ps1/client_agent.ps1]         │             │            (Model: qwen2.5:3b)                   │
│                  │                   │             │                      │                           │
│                  └──── Gửi HTTP POST ─────────────►│                      ▼                           │
│                        (Port 8000)   │             │   [Đẩy Webhook sang n8n Workflow (Port 5679)]    │
└──────────────────────────────────────┘             │                      │                           │
                                                     │                      ▼                           │
                                                     │           [n8n Workflow Automation]              │
                                                     │          (IF: ALERT ➔ Format Markdown)           │
                                                     └──────────────────────┬───────────────────────────┘
                                                                            │
                                                                            ▼
                                                                📱 Telegram Chuyên viên SOC
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
2. Mở PowerShell tại thư mục dự án `D:\Freelancer\AI_agent_ollama\winlog-agent` và tạo môi trường ảo:
   ```powershell
   cd D:\Freelancer\AI_agent_ollama\winlog-agent
   python -m venv .venv
   .\.venv\Scripts\pip install fastapi uvicorn requests pydantic
   ```

---

### 3. Mở cổng tường lửa Windows (Firewall Port 8000)
Để máy Client (`192.168.147.136`) có thể đẩy log sang Server qua cổng `8000`, mở PowerShell với quyền **Administrator** trên Server và chạy lệnh:
```powershell
New-NetFirewallRule -DisplayName "WinLog Agent Server (Port 8000)" -Direction Inbound -LocalPort 8000 -Protocol TCP -Action Allow
```

---

### 4. Khởi động Docker n8n & Nạp Workflow Cảnh báo SOC

Hệ thống sử dụng **n8n Workflow Automation** làm trung tâm điều phối và gửi cảnh báo tới Telegram:

1. Click đúp vào file: 👉 **`run_n8n.bat`** (hoặc gõ `docker compose up -d`).
2. Mở trình duyệt web truy cập: **`http://localhost:5679`**
3. Nếu là lần đầu mở n8n, hãy tạo tài khoản Admin (Email & Password tùy ý).
4. Tại thanh menu bên trái, vào mục **Workflows** ➔ Bấm nút **`Add workflow`** (hoặc biểu tượng `...` góc phải) ➔ Chọn **`Import from file`**.
5. Chọn file **`winlog_soc_workflow.json`** ngay trong thư mục dự án.
6. Bật công tắc **`Active`** (chuyển sang màu xanh lá) ở góc trên bên phải để n8n kích hoạt webhook lắng nghe tại đường dẫn: `http://localhost:5679/webhook/windows-log` (hoặc cổng 5678 tùy cấu hình của bạn).

---

### 5. Khởi động AI Server qua HTTPS (Port 9443)
Do Workflow trong n8n kết nối tới API Server qua địa chỉ `https://host.docker.internal:9443/ingest`, trên máy Server bạn hãy khởi chạy bằng file HTTPS:
👉 Click đúp vào file: **`bat\run_server_https.bat`**

Cửa sổ sẽ hiện lên và giữ nguyên trạng thái lắng nghe:
```text
INFO:     Uvicorn running on https://0.0.0.0:9443 (Press CTRL+C to quit)
```
*(Server đã sẵn sàng nhận log từ Client, tự động chuyển tiếp vào n8n Webhook `windows-log` và phân tích AI khi n8n gọi lại).*

---

## 💻 PHẦN 2: CẤU HÌNH TRÊN MÁY CLIENT (`192.168.147.136`)

Máy Client **hoàn toàn không cần cài đặt Python hay thư viện ngoài**.

### 1. Chuẩn bị thư mục Client
Tạo một thư mục trên máy Client (ví dụ `C:\winlog-client`) và copy các file sau từ Server sang, **giữ nguyên 2 thư mục con `bat\` và `ps1\`**. `run_client.bat` gọi `..\ps1\client_agent.ps1`, nên nếu để các file chung một chỗ thì Agent sẽ không chạy:

```text
C:\winlog-client\
├── bat\
│   ├── setup_client.bat         # Bật chính sách Audit ghi log Windows
│   ├── run_client.bat           # 1-click khởi chạy Agent
│   ├── stop_client.bat          # Tắt Agent
│   ├── view_log.bat             # Xem log của Agent
│   └── simulate_attack.bat      # Mô phỏng chuỗi tấn công để thử nghiệm
└── ps1\
    ├── client_agent.ps1         # Thu thập và gửi log thời gian thực
    └── stop_client.ps1          # Được stop_client.bat gọi để tắt Agent
```

Agent sẽ ghi `client_agent.log` và `client_agent.pid` vào `C:\winlog-client\`.

---

### 2. Bật chính sách Audit log của Windows (Chỉ chạy 1 lần duy nhất)
Windows mặc định không ghi lại chi tiết dòng lệnh và PowerShell. Để hệ thống có log phân tích:
1. Vào thư mục `C:\winlog-client`.
2. **Click chuột phải** vào file **`bat\setup_client.bat`** ➔ Chọn **`Run as administrator`**.
3. Cửa sổ chạy khoảng 3 giây báo `[✓] CAU HINH HOAN TAT!` là xong.

---

### 3. Khởi chạy Agent giám sát thời gian thực
1. **Click chuột phải** vào file **`bat\run_client.bat`** ➔ Chọn **`Run as administrator`**.
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
Trong khi cửa sổ `bat\run_client.bat` vẫn đang chạy:
1. **Click chuột phải** vào file **`bat\simulate_attack.bat`** (trên máy Client) ➔ Chọn **`Run as administrator`**.
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

#### Tại máy Server (`192.168.153.1`):
Server tiếp nhận log, kích hoạt AI Qwen suy luận và chuyển tiếp kết quả sang n8n:
```text
[+] Nhan log tu Client WINLAB (192.168.147.136) gom 19 su kien.
[*] Dang chay Local SLM (qwen) phan tich tuong quan...
[!] Ket qua AI: ALERT (14.03s)
[!] PHAT HIEN TAN CONG! Dang kich hoat luong n8n SOC Workflow...
[*] Dang day ket qua sang n8n Workflow (http://127.0.0.1:5679/webhook/winlog-alert)...
[✓] Da day du lieu thanh cong vao luong n8n! (Endpoint: http://127.0.0.1:5679/webhook/winlog-alert)
[✓] n8n Engine dang dieu phoi: IF (ALERT) -> Format -> Telegram Alert.
```

#### Tại n8n Workflow & Telegram:
Trên giao diện `http://localhost:5679`, bạn sẽ thấy các node sáng đèn xanh:
1. **Webhook Nhận Log từ AI Server**: Tiếp nhận gói JSON từ `app/app.py`.
2. **IF - Kiểm tra nhãn ALERT**: Đánh giá điều kiện `label == "ALERT"`.
3. **Định dạng Cảnh báo Markdown**: Ghép các trường bằng chứng, tiến trình, thời gian xử lý.
4. **Gửi Cảnh báo tới Telegram Bot**: Thực hiện gửi tin nhắn cảnh báo tới chuyên viên SOC.

Điện thoại/máy tính của bạn sẽ rung chuông và nhận ngay tin nhắn:
> 🚨 **CẢNH BÁO BẢO MẬT TỪ N8N SOC WORKFLOW** 🚨  
> 🖥️ **Máy Client:** `WINLAB` (`192.168.153.147`)  
> 🕒 **Thời gian:** `2026-10-21 21:42:29`  
> ⚠️ **Trạng thái:** `ALERT`  
> ⏱️ **Thời gian AI xử lý:** 14.03s  
> 🎯 **Giai đoạn MITRE:** `Credential Access, Persistence, Privilege Escalation`  
> 📝 **Chi tiết phát hiện:** Phát hiện 5 lần đăng nhập thất bại liên tiếp (Event 4625) nhằm vào tài khoản 'fake_hacker_test'; lệnh tạo backdoor user và gán quyền Administrators; lệnh PowerShell tải mã độc từ xa.  
> 🔍 **Bằng chứng:** `E0008, E0009, E0010, E0011, E0012, E0022, E0024...`  
> ⚡ **Điều phối bởi:** n8n Workflow Automation Engine

---

## 🛠️ PHẦN 4: KHẮC PHỤC SỰ CỐ THƯỜNG GẶP (TROUBLESHOOTING)

| Tình trạng | Nguyên nhân | Cách xử lý |
|---|---|---|
| **Client báo: `[!] CANH BAO: Chua ket noi duoc toi AI Server`** | Tường lửa trên Server chặn cổng 8000 hoặc Server chưa bật. | 1. Đảm bảo file `bat\run_server.bat` đang chạy trên Server.<br>2. Chạy lệnh mở cổng 8000 trong PowerShell Admin trên Server (xem Bước 1.3). |
| **Server báo: `[!] Khong the ket noi toi n8n Webhook`** | Container n8n chưa bật hoặc workflow n8n chưa được Active. | 1. Chạy `run_n8n.bat` để bật Docker n8n.<br>2. Truy cập `http://localhost:5679` và kiểm tra công tắc **Active** của workflow đã bật màu xanh chưa. |
| **Cửa sổ CMD trên Client đứng yên, không quét tiếp** | Người dùng click chuột vào cửa sổ CMD gây ra chế độ **Select/QuickEdit** (Windows đóng băng tiến trình). | Bấm vào cửa sổ CMD và ấn phím **`ENTER`** (hoặc click chuột phải) để thoát trạng thái bôi đen. |
| **Telegram không nhận được tin nhắn** | Tài khoản Telegram chưa bấm `START` với bot. | Mở cuộc trò chuyện với con Bot của bạn và bấm nút **START** (hoặc gửi tin nhắn bất kỳ cho bot). |
| **Client không bắt được sự kiện sau khi chạy lệnh tấn công** | Chưa chạy `bat\setup_client.bat` bằng quyền Administrator. | Click chuột phải `bat\setup_client.bat` chọn **Run as administrator** để Windows bật tính năng ghi log. |

---

## 📁 BẢNG TỔNG HỢP DANH MỤC FILE DỰ ÁN

| File | Máy chạy | Chức năng |
|---|---|---|
| **`app/app.py`** | Server | API nhận log, phân tích bằng Qwen AI và chuyển tiếp sang n8n Webhook. |
| **`winlog_soc_workflow.json`** | Server / n8n | File cấu hình toàn bộ luồng tự động hóa n8n (Webhook ➔ IF ➔ Telegram). |
| **`run_n8n.bat`** | Server | 1-Click khởi chạy Docker n8n trên cổng 5679. |
| **`docker-compose.yml`** | Server | Cấu hình service n8n container và mạng kết nối với host. |
| **`core/analyze.py`** | Server | Lõi phân tích tương quan sự kiện, tiền lọc nhiễu, prompt AI Local SLM. |
| **`core/generate_data01.py`** | Server | Script tự động khởi tạo bộ Benchmark 40 ca kiểm thử chuẩn vào thư mục `data01/`. |
| **`core/evaluate.py`** | Server | Script tự động chạy benchmark so sánh Qwen và Llama, tính Precision/Recall/F1. |
| **`bat/run_evaluation.bat`** | Server | File 1-click khởi chạy đánh giá so sánh và xuất báo cáo CSV/Markdown. |
| **`bat/run_server.bat`** | Server | File 1-click khởi động Server API cổng 8000. |
| **`bat/run_server_https.bat`** | Server | File 1-click khởi động Server API bảo mật HTTPS cổng 9443. |
| **`bat/setup_client.bat`** | Client | File 1-click bật chính sách Windows Audit (Process Creation, PowerShell). |
| **`bat/run_client.bat`** | Client | File 1-click khởi chạy Agent thu gom log. |
| **`ps1/client_agent.ps1`** | Client | Script quét Windows Event Log mỗi 5-15s và đẩy sang Server. |
| **`bat/simulate_attack.bat`** | Client | File mô phỏng 3 chuỗi tấn công thực tế (tự động dọn dẹp). |
| **`bat/stop_client.bat`** + **`ps1/stop_client.ps1`** | Client | Tắt Agent đang chạy (đọc PID từ `client_agent.pid`). |
| **`web/frontend/index.html`** + **`web/backend/siem.py`** | Server | Giao diện SIEM realtime tại `https://<IP server>:<cổng>/`. |

> Hướng dẫn chi tiết từng thư mục: xem `HUONG_DAN_SU_DUNG_<tên thư mục>.md` trong `app/`, `bat/`, `core/`, `ps1/`, `web/`... Mục lục ở [`md/HUONG_DAN_SU_DUNG_md.md`](HUONG_DAN_SU_DUNG_md.md).
