# Chạy dịch vụ và gọi API

Từ winlog-agent, chuẩn bị tokenizer theo tokenizers.md, sao chép config.example.toml thành config.local.toml rồi chạy:

```powershell
.\.venv\Scripts\python.exe -m app.api --config config.local.toml
```

Mặc định http://127.0.0.1:8000, một worker. Khóa service.lock trong data_root ngăn hai tiến trình sở hữu cùng hàng chờ. Không khởi chạy Uvicorn với nhiều worker. Token API ngẫu nhiên tại data_root/secrets/api-token.txt; session key ở cùng thư mục, ngoài Git. Không dán token vào workflow xuất hoặc lịch sử chat.

GET /health công khai chỉ trả ok/degraded. Các tuyến còn lại cần `Authorization: Bearer <token>` hoặc session UI; session ghi yêu cầu thêm X-CSRF-Token. POST /login nhận JSON token và cấp cookie HttpOnly/SameSite Strict cùng csrf_token. GET /session trả token CSRF cho phiên hiện tại. Không bật CORS wildcard.

## Ví dụ PowerShell

Giả sử dùng data_root mặc định. Nhập một fixture tổng hợp để kiểm tra API rồi tạo ca; fixture không được dùng chấm độ chính xác. Trên PowerShell 7 có thể upload multipart bằng -Form; giao diện sẽ hỗ trợ Windows PowerShell 5.1. Các lệnh phân tích/poll dưới đây dùng được trên 5.1:

```powershell
$headers = @{ Authorization = 'Bearer ' + (Get-Content .\data\secrets\api-token.txt -Raw).Trim() }
$base = 'http://127.0.0.1:8000'
$cases = Invoke-RestMethod -Uri "$base/cases" -Headers $headers
$caseId = $cases.cases[0].case_id
$requestId = [guid]::NewGuid().ToString()
$headers['Idempotency-Key'] = $requestId
$body = @{ case_id = $caseId; model = 'qwen2.5:3b-instruct-q4_K_M' } | ConvertTo-Json
$response = Invoke-RestMethod -Uri "$base/analyze" -Method Post -Headers $headers -ContentType 'application/json' -Body $body -TimeoutSec 30
$deadline = (Get-Date).AddSeconds(600)
while ($response.state -ne 'completed' -and (Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 2
    $response = Invoke-RestMethod -Uri ($base + $response.status_url) -Headers $headers
}
$response
```

Phải có ca trước khi chọn dòng đầu. HTTP 200 là completed; HTTP 202 là queued/running, không có label mặc định. Nếu hết thời gian poll, giữ request_id/result_id và tra lại, không tạo key mới. Khi mất response POST, GET /requests/{requestId} phục hồi trạng thái; gửi lại cùng key/body cũng trả cùng job. Khác nội dung với key cũ trả 409. Tối đa 20 yêu cầu chờ; queue đầy trả 429. Model chưa sẵn sàng trước nhận job trả 503. ID không có trả 404; schema/model/key sai trả 422.

Sau nhận job, lỗi kỹ thuật được lưu như kết quả UNKNOWN có technical_error. UNKNOWN với technical_error=null là phản hồi hợp lệ thiếu bằng chứng. Timeout mặc định 300 giây theo thời gian thực: không chạy job tiếp khi lời gọi cũ chưa kết thúc/unload chưa được xác nhận. Service degraded cần kiểm tra Ollama trước khởi động lại. Restart biến running cũ thành INTERRUPTED, không tự phát lại; queued vẫn giữ trong SQLite.

## Các tuyến dữ liệu

- POST /imports: multipart security và/hoặc powershell; tối đa 50 MiB mỗi file; nguồn hỏng báo trong trạng thái partial. Trùng hash trả 409/SOURCE_EXISTS với source_id, không nhân đôi.
- GET /imports/{id}: thống kê, nguồn thiếu/lỗi, chất lượng và mảnh script.
- GET /cases và /cases/{id}: danh sách/snapshot.
- POST /cases: import_id, start/end có timezone, user, group_ids, mixed; xem cases.md về lọc nguyên nhóm.
- POST /analyze: case_id/model và Idempotency-Key UUID.
- GET /results/{id}, /requests/{id}: envelope trạng thái hoặc kết quả hoàn tất.
- GET /events/{event_ref}: bằng chứng qua ID đã đăng ký, không nhận đường dẫn.
- GET /results/{id}/export?format=jsonl hoặc csv: chưa hoàn tất trả 409. CSV neutralize ký tự công thức kể cả sau whitespace; JSONL giữ nguyên.
- GET /models: model có sẵn/metadata. Không tự tải model thiếu.

## Docker/n8n

Chỉ khi cần Docker truy cập: đặt bind_mode="docker", host="0.0.0.0" trong config.local.toml và khởi động lại. n8n dùng http://host.docker.internal:8000 với credential header token. Trước khi bật, kiểm tra adapter/subnet Docker thực tế trong Windows Network settings/Get-NetIPConfiguration. Windows Firewall chỉ cho TCP cổng cấu hình từ địa chỉ/phạm vi Docker đã xác định; giới hạn đúng chương trình Python và profile cần thiết. Không dùng Any remote address hoặc mở toàn bộ mạng. Địa chỉ Docker thay đổi cần kiểm tra lại rule; tài liệu không tự đoán subnet.

Kiểm thử API hiện dùng fixture/mock, không phải kiểm chứng mạng Docker hoặc n8n. Token local không thay thế phạm vi firewall.
