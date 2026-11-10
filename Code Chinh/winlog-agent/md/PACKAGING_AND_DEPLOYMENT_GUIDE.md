# HƯỚNG DẪN ĐÓNG GÓI VÀ TRIỂN KHAI TRỌN GÓI DỰ ÁN (AI SOC & N8N DOCKER)

Tài liệu này hướng dẫn cách đóng gói toàn bộ dự án WinLog AI SOC (bao gồm cả mã nguồn Python, Client Agent, kịch bản Demo và Container Docker n8n) để chuyển giao hoặc cài đặt sang máy mới 100%.

---

## I. CẤU TRÚC BỘ ĐÓNG GÓI HOÀN CHỈNH

Thư mục dự án sau khi đóng gói sẽ gồm các thành phần chính:

```text
winlog-agent/
├── app/                             # 1. AI Server (FastAPI + Local SLM)
│   └── app.py (+ app1/app2/app3/app_origin)   # API Server nhận log & phân tích
├── core/
│   ├── analyze.py                   # Reasoning Engine + Correlation Rules
│   ├── evaluate.py                  # Đánh giá Benchmark Precision/Recall
│   └── generate_*.py                # Sinh bộ dữ liệu kiểm thử
├── web/
│   ├── frontend/index.html          # Giao diện SIEM
│   └── backend/siem.py, dashboard.py
├── bat/
│   ├── run_server_https.bat         # 1-Click khởi động AI Server HTTPS (cổng HTTPS_PORT, mặc định 8443)
│   ├── run_server_https1.bat        # HTTPS 9443, tự tạo .venv trên máy mới
│   ├── run_client.bat               # 2. Client: 1-Click chạy Agent
│   ├── stop_client.bat, view_log.bat, setup_client.bat
│   ├── simulate_attack.bat          # Demo 1: Tấn công tự động (1-Click)
│   ├── simulate_attacks_demo2.bat   # Demo 2: Menu tương tác 8 kịch bản MITRE
│   ├── export_n8n_image.bat         # 3. n8n: 1-Click nén n8n thành file .tar độc lập
│   └── import_n8n_image.bat         # 1-Click phục hồi n8n trên máy mới
├── ps1/
│   ├── client_agent.ps1             # Script thu thập Event Log 4625, 4104, 4688...
│   └── stop_client.ps1              # Tắt Agent (được stop_client.bat gọi)
├── md/                              # Tài liệu chung
├── cert.pem, key.pem                # Chứng chỉ HTTPS TLS
├── requirements.txt                 # Danh sách thư viện Python
├── .env.example                     # Mẫu cấu hình -> copy thành .env
├── docker-compose.yml               # Khởi chạy n8n với 1 lệnh
├── winlog_soc_workflow.json         # File Workflow JSON sẵn sàng Import vào n8n
└── data/, data01/                   # 4. Bộ dữ liệu mẫu chuẩn (40 ca kiểm thử)
```

---

## II. 2 CÁCH ĐÓNG GÓI DOCKER N8N

### 👉 Cách 1: Đóng gói thành file Image Portable `.TAR` (Khuyên Dùng khi mang sang máy Offline / Nhanh nhất)
Cách này đóng gói **nguyên vẹn trạng thái n8n của bạn** (đã có sẵn Workflow, Credentials Telegram, cấu hình) thành 1 file duy nhất:

1. **Trên máy hiện tại**:
   - Click đúp vào file [`bat\export_n8n_image.bat`](../bat/export_n8n_image.bat).
   - Script sẽ chụp lại container `n8n` và xuất ra file **`winlog-n8n-docker.tar`** ngay trong thư mục dự án.
2. **Nén toàn bộ thư mục dự án (bao gồm cả file `.tar` vừa tạo) thành file `.ZIP`**.

---

### 👉 Cách 2: Đóng gói siêu nhẹ qua Workflow JSON + Docker Compose (Khuyên dùng khi gửi qua Zalo/Drive/GitHub)
Cách này không nén Image to mà chỉ lưu công thức:
1. Mở giao diện n8n tại: `http://localhost:5679`
2. Mở Workflow cảnh báo AI SOC của bạn.
3. Bấm vào nút menu **`...`** (góc trên bên phải) ➔ Chọn **`Download`** (hoặc `Export`) ➔ Đổi tên file thành **`winlog_soc_workflow.json`** và lưu vào thư mục dự án.
4. Dung lượng toàn bộ dự án lúc này chỉ khoảng **vài Megabytes**, gửi đi cực kỳ nhanh!

---

## III. QUY TRÌNH 3 BƯỚC TRIỂN KHAI TRÊN MÁY MỚI

Khi đem thư mục dự án sang một máy tính mới:

### Bước 1: Khởi động Local SLM (Ollama)
Cài đặt Ollama và tải mô hình Qwen 2.5 3B:
```bash
ollama run qwen2.5:3b
```

### Bước 2: Khởi động Docker n8n
- **Nếu dùng file Image .tar (Cách 1)**: Click đúp vào [`bat\import_n8n_image.bat`](../bat/import_n8n_image.bat). N8n sẽ tự nạp và chạy ngay trên cổng `5679` với đầy đủ workflow cũ!
- **Nếu dùng Docker Compose (Cách 2)**:
  ```bash
  docker compose up -d
  ```
  Vào `http://localhost:5679` ➔ Bấm `Import from file` ➔ Chọn `winlog_soc_workflow.json`.

### Bước 3: Cài đặt Python & Bật AI Server
```bash
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
```
Sau đó click đúp vào [`bat\run_server_https.bat`](../bat/run_server_https.bat) là toàn bộ hệ sinh thái AI SOC đã sẵn sàng hoạt động!

