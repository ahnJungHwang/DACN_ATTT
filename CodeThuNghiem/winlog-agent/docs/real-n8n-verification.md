# n8n gọi hai model thật — 2026-10-26

Đã chạy workflow bàn giao bằng CLI n8n 2.44.6 trong container kiểm thử riêng, gọi FastAPI trên 127.0.0.1:8000 qua host.docker.internal, sau đó Ollama 0.40.11. Không dùng backend/model mock. Container kiểm thử không gắn volume n8n_data và đã được dừng/xóa sau kiểm tra. Workflow trong n8n hằng ngày vẫn cần người dùng gán credential theo n8n.md.

## Dữ liệu và phạm vi

Dùng bản sao kho data/verify-original, ca a7133cc8-96b9-4e0b-86d8-d3413e24d016 với 5 sự kiện từ log-test mà người dùng xác nhận. Bản sao có toàn bộ 182 sự kiện và các ca/kết quả cũ, không sửa kho nguồn hoặc hai XML gốc. Chưa có manifest thu VM/nhật ký thao tác hoặc nhãn chuẩn. Đây là kiểm chứng tích hợp kỹ thuật, không phải benchmark độ chính xác.

## Kết quả đã xác minh

- Qwen2.5 3B trả NORMAL, không lỗi kỹ thuật. Request c40aa22a-0728-453f-81e6-368cb6603750, result 26c20416-0ab0-4b31-898f-7dcf758a3ae8.
- Llama3.2 3B trả ALERT, không lỗi kỹ thuật. Request f2fb0880-04c9-449f-a8fb-43247e9cc6cd, result d155196b-4709-4104-95f9-38f6f6fdd515.
- Cả hai lượt nhận response model thật, đi qua hai lượt poll trước khi vào nhánh nhãn. Lần kiểm thử đặt response_wait_seconds=1 để kiểm tra 202/poll; timeout suy luận vẫn là 300 giây. Không đổi prompt hoặc cấu hình model mặc định.
- request_id/result_id/label/evidence_refs của n8n khớp API. Tất cả refs trả về mở được XML gốc qua API; JSONL xuất ra khớp toàn bộ kết quả lưu.
- Sau khi hai yêu cầu hoàn tất, dừng rồi khởi động lại API và chạy workflow Qwen với đúng key/body cũ: result_id và hash toàn bộ kết quả không đổi, SQLite chỉ có một request ứng với key đó. Lượt gửi lại không cần poll. Đây là phục hồi yêu cầu đã hoàn tất, chưa chứng minh phục hồi khi đang suy luận.
- Sao lưu kho kiểm thử sau khi API dừng, khôi phục vào thư mục mới: hash kết quả của cả hai lượt khớp và recovery_report không có raw file thiếu hoặc sai hash. Không kiểm chứng backup volume n8n trong lượt này.

Hai nhãn khác nhau chưa có nhãn chuẩn để chấm. Kết quả Qwen cũng khác lần smoke trên Ollama 0.40.9; không xem temperature=0 là bảo đảm tái lập tuyệt đối, không gộp hai phiên bản Ollama vào một phép đối chứng.

## Bằng chứng và chạy lại

Kết quả hoàn chỉnh nằm trong data/real-n8n/30e36045-3a2c-4a52-b69d-72e9ce49b48f/: summary.json, execution của từng workflow, api.log, store, completed-backup và restored. Thư mục này ngoài Git, chứa log và credential local; không chia sẻ nguyên thư mục.

Script tests/verify_real_n8n.py dành riêng cho kho kiểm thử hiện tại và seed real-log-verification-5cf144eb-ee96-49c3-ae93-7b183457eea3.json. Nó không được pytest tự chạy. Cần Docker/Ollama sẵn sàng, không có model do ứng dụng khác nạp, không có tiến trình ghi vào verify-original, và cổng 8000 trống. Mỗi lượt tạo thư mục/container mới, dùng image đã chốt, không tự tải model hoặc gán nhãn chuẩn. Từ thư mục winlog-agent:

```powershell
$env:PYTHONPATH='.'
.\.venv-handoff\Scripts\python.exe tests/verify_real_n8n.py
```

Hai lần chuẩn bị chưa thành công cũng giữ bằng chứng: cổng 18084 thuộc dải Windows dành riêng 18038–18137; lần kế tiếp bị CONTEXT_UNVERIFIED vì Ollama đổi từ 0.40.9 sang 0.40.11. Lần đó summary complete chỉ phản ánh kiểm tra vận chuyển/lưu trữ lỗi UNKNOWN; không có suy luận model. Script hiện yêu cầu model_response_received=true để tránh công bố thành công khi model chưa chạy. Sau xác minh lại 10/10 mẫu tokenizer, lần cuối ở đường dẫn trên thành công.

## Phần còn lại

Cập nhật sau lượt thử này: mục 11.3 đã được kiểm chứng bổ sung, xem [biên bản phục hồi](recovery-verification.md). Đoạn dưới ghi phạm vi còn thiếu tại thời điểm riêng lượt n8n ban đầu.

Chưa đóng 11.1: còn luồng giao diện với dữ liệu thật và đối chiếu tài khoản/phiên theo nhật ký VMware. Chưa đóng 11.3: còn restart khi đang suy luận, timeout Ollama, client mất response và kiểm chứng bảo toàn volume n8n. Chưa thực hiện phiên ngắt Internet. Việc này không thay thế thu mới có manifest hoặc đánh giá 10/40 ca.
