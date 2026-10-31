# Kiểm chứng phục hồi — 2026-10-26

Đã thử trên bản sao kho log thật, API bằng tiến trình Python riêng và Ollama 0.40.11 thật. Không mock kết quả model, không sửa log-test, kho gốc hoặc volume n8n_data. Các lỗi chỉ tác động đến tiến trình/kết nối kiểm thử.

## API và Ollama

tests/verify_real_recovery.py sao lưu/khôi phục verify-original vào kho riêng, dùng ca 5 sự kiện a7133cc8-96b9-4e0b-86d8-d3413e24d016. Mỗi tình huống dùng UUID mới; khi tra/gửi lại giữ nguyên UUID.

- **Client mất phản hồi:** gửi đầy đủ HTTP POST rồi đóng socket trước khi đọc response. Job hoàn tất với response Qwen thật; GET /requests và gửi lại cùng key trả cùng result_id/toàn bộ nội dung. Database chỉ có một request và một result cho key.
- **Python dừng khi job running:** quan sát trạng thái running rồi dừng đúng tiến trình kiểm thử; xác nhận database còn running trước restart. Sau restart, kết quả thành UNKNOWN/INTERRUPTED; gửi lại cùng key giữ nguyên kết quả, không phát lại job cũ. Đây là ngắt trong vòng đời job, không khẳng định ngắt chính xác tại một token GPU cụ thể.
- **Timeout thật:** cấu hình riêng đặt inference_timeout_seconds=1, response_wait_seconds=1 để tạo quá hạn khi gọi Qwen local. Hệ thống lưu UNKNOWN/TIMEOUT. Yêu cầu model thứ hai ngay sau đó trả 503/SERVICE_DEGRADED và không tạo request mới. Gửi lại key cũ vẫn truy được kết quả. Đợi/giải phóng model của lượt thử trước khi tiếp tục; timeout không chứng minh Ollama đã ngừng xử lý.

Sau timeout, restart với cùng cấu hình vẫn trả kết quả cũ. Đổi timeout từ 1 sang 300 giây rồi gửi cùng key trả 409/IDEMPOTENCY_CONFLICT vì cấu hình nằm trong hash yêu cầu; GET vẫn đọc được kết quả cũ. Cấu hình sản phẩm mặc định 300 giây không đổi; bài thử không chờ đủ 300 giây.

Sau các lỗi, dừng API, sao lưu/khôi phục kho vào thư mục khác: cả ba kết quả giữ đúng hash, raw evidence không thiếu hoặc đổi hash. Bằng chứng thành công đầy đủ tại `data/real-recovery/29fb6d8a-0286-4331-8703-80b0aba6b01b/summary.json`. Request lần lượt fde384ae-0c39-434e-9eec-b667b751c99f, 2970bfa0-ff22-4d7d-b591-e0f72a72b90f và 29f0ddcb-08c3-4fd7-9067-66f927b4d598. api.log/database/bản sao/bản khôi phục nằm cùng thư mục. Lượt thử đầu dừng ở 409 do đổi cấu hình; giữ bằng chứng đó và bổ sung kiểm chứng cả hai trường hợp giữ nguyên/thay đổi cấu hình.

## Volume n8n

Container n8n ở trạng thái exited, không có container chạy gắn n8n_data. tests/verify_n8n_backup.py gắn nguồn read-only, tạo tar, khôi phục vào volume mới rồi đối chiếu toàn bộ cây file. Container sao lưu không có mạng. Không khởi chạy ứng dụng n8n trên bản khôi phục trong bước này.

Kết quả: 10 entry gồm 8 file, tổng 6.640.874 byte; tên, loại, nội dung SHA256, mode/UID/GID của bản khôi phục khớp nguồn. Inventory nguồn trước/sau cũng khớp. Bản sao gồm file cấu hình/encryption key trong volume; không xuất nội dung bí mật ra chat/Git.

- Bằng chứng: data/n8n-backup-verification/7d35dd52-e0e5-4648-9a71-3746adaddcfd/summary.json.
- Archive cùng thư mục: n8n-volume.tar.gz, SHA256 b13f61b15dd9203b0d102c4e09a92259b48499d74bd9df59585e5a5a1fd540e0.
- Volume khôi phục giữ để kiểm tra: winlog-n8n-restored-7d35dd52-e0e5-4648-9a71-3746adaddcfd. Volume n8n_data nguyên trạng; không đổi volume của container hằng ngày.

Archive chứa credential local, cần bảo quản như bí mật. Nếu triển khai khác dùng encryption key từ môi trường ngoài volume, cần sao lưu key đó riêng; không suy ra archive này đủ cho mọi máy.

## Phạm vi và chạy lại

Kết hợp real-n8n-verification.md (workflow thật, polling, tra lại sau restart, export/refs), đã kiểm tra phục hồi và bảo toàn database/volume của mục 11.3. Chưa chứng minh độ chính xác, phiên ngắt Internet, thu mới VMware hay toàn luồng giao diện với nhật ký thao tác; các mục đó vẫn mở.

Hai script không do pytest tự chạy. Chạy từ winlog-agent với PYTHONPATH=. và Python đã cài. verify_real_recovery.py yêu cầu cổng 8000 trống, Ollama không có model ngoài đang nạp, không có tác vụ ghi kho nguồn. verify_n8n_backup.py yêu cầu mọi container ghi n8n_data đã dừng. Script không tự dừng ứng dụng đang dùng của người vận hành. Mỗi lượt tạo bản sao mới, giữ kết quả và volume khôi phục riêng.
