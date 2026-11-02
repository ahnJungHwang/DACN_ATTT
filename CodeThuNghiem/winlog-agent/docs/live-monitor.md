# Theo dõi model và HTTPS

Trang chính có hai trạm Qwen/Llama, đọc `/activity` mỗi 2 giây sau đăng nhập. Mỗi trạm hiển thị yêu cầu đang chạy, chờ và lịch sử gần nhất (tối đa 8 mục), mã ca, mã yêu cầu, thời điểm nhận, tên nguồn XML và số sự kiện. Nút mở ca truy lại bằng chứng gốc. `completed` chỉ có nghĩa yêu cầu đã kết thúc, không đảm bảo model không gặp lỗi; kết quả phân tích vẫn nằm ở mục kết quả.

Đây là trạng thái từ SQLite, gồm cả yêu cầu gửi qua n8n/API. Không có phần trăm tiến độ giả, không xác định model đang đọc dòng nào trong payload. Khi mất mạng giao diện báo dữ liệu cũ. Hai yêu cầu có thể được gửi đồng thời nhưng worker chỉ suy luận một model tại một thời điểm.

## HTTPS local

`config.local.toml` trên máy hiện tại đã cấu hình chứng chỉ `data/tls/localhost.pem` và khóa `data/tls/localhost-key.pem`. Đây là chứng chỉ tự ký cho localhost/127.0.0.1, không tự cài vào kho tin cậy. Không chia sẻ private key hoặc đưa vào Git.

Chạy từ thư mục winlog-agent bằng môi trường Python đã cài requirements:

```powershell
python -m app.api --config config.local.toml
```

Mở `https://localhost:8000/`. Trình duyệt cần tin cậy chứng chỉ này qua quy trình quản lý chứng chỉ của máy hoặc thay bằng chứng chỉ được CA tin cậy cấp. Không tắt xác minh chứng chỉ trong n8n/client. Nếu có API đang chạy cùng data_root/port, dừng phiên cũ trước khi khởi động phiên HTTPS.

Frontend sử dụng URL tương đối nên các request, polling, upload và export cùng dùng HTTPS khi mở giao diện HTTPS. Cookie được đặt Secure khi cấu hình TLS. Uvicorn không tin header proxy tùy ý. Cấu hình example cũ vẫn là HTTP phục vụ tương thích thử nghiệm; dùng config.local.toml cho HTTPS. Client/n8n phải đổi base URL sang HTTPS và tin cậy CA tương ứng; hostname Docker cần nằm trong SAN của chứng chỉ riêng nếu sử dụng Docker.

HTTPS này bảo vệ đoạn trình duyệt/client → API. Adapter Ollama hiện vẫn dùng HTTP trên loopback 127.0.0.1:11434; chưa phải mã hóa toàn bộ các chặng nội bộ.
