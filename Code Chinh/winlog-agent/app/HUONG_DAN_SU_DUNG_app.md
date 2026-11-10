# Hướng dẫn sử dụng thư mục `app/`

Chứa các phiên bản **AI Server** (ứng dụng FastAPI). Server nhận log từ máy client qua `POST /ingest`, gọi bộ phân tích [`core/analyze.py`](../core/HUONG_DAN_SU_DUNG_core.md) và điều phối cảnh báo qua n8n.

Mỗi lần chỉ chạy **một** phiên bản, chọn bằng biến `APP_MODULE` trong file `.env`.

## Các phiên bản

| File | Mô tả | Giao diện web |
|---|---|---|
| `app.py` | **Bản chính, đang dùng (mặc định).** Nhận log → lưu xuống đĩa → gọi n8n theo 2 bước. Nếu không gọi được n8n thì server tự phân tích. | SIEM realtime (`web/backend/siem.py`) |
| `app1.py` | Bản cũ: chuyển tiếp toàn bộ log sang n8n để n8n điều phối. | SOC Dashboard (`web/backend/dashboard.py`) |
| `app2.py`, `app3.py` | Các bản thử nghiệm trung gian của luồng n8n 2 bước. Luôn ghi đè file XML của phiên trước, để không phân tích lại log tấn công cũ. | Không có |
| `app_origin.py` | Bản gốc ban đầu, giữ lại để đối chiếu. | Không có |

## Cách chạy

**Cách nhanh:** dùng file `.bat` trong [`bat/`](../bat/HUONG_DAN_SU_DUNG_bat.md):

| File | Giao thức / cổng |
|---|---|
| `bat\run_server_https.bat` | HTTPS, cổng `HTTPS_PORT` (mặc định 8443). Khuyên dùng. |
| `bat\run_server.bat` | HTTP, cổng 8000. |
| `bat\run_server_https1.bat` | HTTPS, cổng 9443. Tự tạo `.venv` nếu chưa có. Luôn chạy `app.py`. |

**Chạy tay** (đứng ở thư mục gốc `winlog-agent`):

```powershell
.venv\Scripts\python.exe -m uvicorn --app-dir app app:app --host 0.0.0.0 --port 8443 --ssl-keyfile key.pem --ssl-certfile cert.pem
```

Muốn chạy bản khác thì đổi `app:app` thành `app1:app`, `app2:app`...
Tham số `--app-dir app` là **bắt buộc**, vì các file server nằm trong thư mục `app/`.

## Cấu hình `.env` (ở thư mục gốc)

Copy `.env.example` thành `.env` rồi sửa. Các biến chính:

| Biến | Ý nghĩa |
|---|---|
| `APP_MODULE` | Phiên bản server: `app`, `app1`, `app2`... |
| `HTTPS_PORT` | Cổng HTTPS, mặc định `8443`. |
| `OLLAMA_URL` | Địa chỉ Ollama. |
| `MAX_BATCH_CHARS` | Số ký tự tối đa mỗi lô gửi cho AI. |
| `N8N_WEBHOOK_URL` | Webhook n8n. `app.py` tự thử thêm cổng 5678 và 5679 nếu không gọi được. |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | Thông tin bot Telegram để gửi cảnh báo. |

## Các địa chỉ (API) chính

| Địa chỉ | Chức năng |
|---|---|
| `GET /` | Chuyển sang giao diện web (`/dashboard`). |
| `GET /health` | Kiểm tra server còn sống và danh sách mô hình. Client gọi khi khởi động. |
| `POST /ingest` | Nhận log từ client (hoặc lượt gọi lại từ n8n). |
| `POST /analyze` | Phân tích một ca có sẵn trong `data/` hoặc `data01/`. |
| `GET /cases` | Liệt kê các ca có sẵn. |

## Luồng xử lý của `app.py`

1. Client gửi log tới `/ingest`.
2. Server lưu XML vào `data/client_<IP>_live/`, rồi báo cho n8n (gói tin không kèm XML).
3. n8n gọi lại `/ingest`. Server đọc XML từ đĩa, AI phân tích và trả kết luận.
4. Nếu kết luận là `ALERT`, n8n gửi cảnh báo Telegram.
5. Nếu không gọi được n8n (ví dụ Docker đang tắt), server **tự phân tích** và trả kết quả thẳng cho client.

Kết quả phân tích được lưu tại `results/client_<IP>_live/<model>_<thời gian>.json`.

## Lưu ý

- Các file trong `app/` tự thêm `core/` và `web/backend/` vào đường dẫn tìm module, nên không cần chỉnh `PYTHONPATH`.
- Trình duyệt sẽ cảnh báo chứng chỉ khi mở trang HTTPS, vì `cert.pem` là chứng chỉ tự ký. Chọn "Advanced" → "Proceed" để vào.
