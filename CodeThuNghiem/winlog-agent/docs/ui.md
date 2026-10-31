# Sử dụng giao diện local

## Chạy trên máy thật

Chuẩn bị môi trường và tokenizer theo setup.md và tokenizers.md. Mở PowerShell tại `Thang Code/winlog-agent`, chạy:

```powershell
.\.venv\Scripts\python.exe -m app.api --config config.example.toml
```

Giữ cửa sổ chạy dịch vụ, mở http://127.0.0.1:8000. Đọc token trong `data/secrets/api-token.txt` trên máy của bạn rồi nhập vào ô đăng nhập. Không gửi token lên chat hoặc lưu trong workflow xuất. Nếu dùng data_root khác, đọc token ở thư mục đó. Phiên đăng nhập hết hạn sau một giờ; tải lại trang và đăng nhập lại khi gặp UNAUTHORIZED.

## Nhập và phân tích

1. Chép `security.xml` và `powershell.xml` từ lần thu trên VMware Windows 10 sang máy thật theo windows10-collection.md. Chọn đúng hai file trong mục Nhập log. Chỉ đánh dấu dữ liệu mẫu khi dùng XML tổng hợp.
2. Nhấn **Nhập và kiểm tra**. Xem số sự kiện, Event ID còn thiếu, lỗi chất lượng và trạng thái từng nguồn. Một nguồn thiếu hoặc lỗi vẫn có thể giữ nguồn tốt, nhưng không được coi là lần thu đầy đủ. File lỗi không sinh sự kiện giả.
3. Khi trùng file, nút **Dùng lại lần nhập chứa file này** mở lần nhập cũ; không bổ sung file còn lại vào lần nhập đó. Kiểm tra lại nguồn và thống kê trước khi tiếp tục.
4. Lọc tài khoản/khoảng thời gian nếu cần, dùng thời gian có offset như `2026-10-25T09:00:00+07:00`. Bộ lọc giữ nguyên nhóm có sự kiện khớp. Chọn ca trộn nếu cần giữ nhiều nhóm trong một đầu vào, rồi nhấn **Tạo ca từ lần nhập**.
5. Chọn ca đã lưu, đọc quan hệ và nhấn mã sự kiện để mở XML. Ca chưa chạy không có nhãn NORMAL mặc định.
6. Chọn một hoặc hai model, nhấn **Phân tích ca đã chọn**. Hai model chạy lần lượt, kết quả hiển thị riêng. Nếu ngắt kết nối hoặc hết lượt chờ, dùng **Tra lại / gửi lại cùng mã yêu cầu** trong cùng tab; không tạo mã mới. Yêu cầu chờ được lưu trong sessionStorage của tab. Có thể tra mã qua API theo api.md.
7. Đọc nhãn, lý do, lỗi kỹ thuật và XML bằng chứng. UNKNOWN có lỗi kỹ thuật khác UNKNOWN do thiếu dữ kiện. INPUT_TOO_LARGE yêu cầu tạo ca nhỏ hơn; ứng dụng không tự cắt log.
8. Nhấn **Tải JSONL** để giữ kết quả đầy đủ hoặc **Tải CSV** để xem các trường kết luận. CSV vô hiệu hóa ký tự công thức sau khoảng trắng. File xuất và ảnh chụp có thể chứa log, chỉ lưu local.

## Bằng chứng kiểm thử ngày 2026-10-25

Đã chạy trình duyệt với `tests/serve_ui_fixture.py`, port 18081 và data root riêng `data/ui-mock`. Upload fixture synthetic-security.xml → báo 1 sự kiện/thiếu PowerShell → tạo ca mẫu → chạy hai kết quả mock UNKNOWN riêng biệt → mở XML 4624 đúng hash/ordinal → tải JSONL thành công. Nhập lại trả lựa chọn tái sử dụng và giữ cùng import. Chuỗi `<script>` trong reason xuất hiện như văn bản; vùng kết quả không tạo phần tử script. Ảnh lưu local ở data/ui-mock-verification.png.

Đây là kiểm thử mock, không gọi model và không dùng chấm độ chính xác. Trạng thái chờ, timeout, idempotency, xác thực và CSV được kiểm thử riêng trong tests/test_service.py và tests/test_api.py. Kiểm thử toàn hệ thống qua n8n và log mới từ VM còn chưa hoàn tất. Báo cáo hiện chưa có số liệu đủ để chọn model tốt nhất.
