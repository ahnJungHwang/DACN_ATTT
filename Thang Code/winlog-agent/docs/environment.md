# Môi trường triển khai

Kiểm tra chỉ đọc ngày 2026-10-24 (Asia/Saigon). Chưa phải bằng chứng ứng dụng chạy.

## Đã xác minh trên máy thật
- CPU AMD Ryzen 7 7840HS: 8 nhân, 16 luồng.
- RAM hệ điều hành nhận: 23.19 GiB.
- GPU: AMD Radeon 780M và NVIDIA GeForce RTX 4050 Laptop GPU. Chưa đo VRAM hoặc GPU Ollama thực dùng.
- Python launcher ngoài sandbox chỉ liệt kê Python 3.13; executable báo 3.13.7. Chưa tìm thấy 3.11 qua launcher. Kết quả không có Python trong sandbox không phản ánh máy thật.
- Ollama CLI/API: 0.40.9, API local truy cập được ngoài sandbox.
- qwen2.5:3b-instruct-q4_K_M: ID ngắn 357c53fb659c, 1.9 GB.
- llama3.2:3b-instruct-q4_K_M: ID ngắn a80c4f17acd5, 2.0 GB.
- Chưa ghi full digest/tokenizer hoặc chạy suy luận.
- Docker CLI 29.9.2 build a82e528; docker ps không kết nối được pipe dockerDesktopLinuxEngine.

## Chưa xác nhận
- n8n version/image digest vì Docker Engine chưa truy cập được.
- Người dùng xác nhận VM Windows 10; edition/build, audit và thời gian thực nghiệm chưa kiểm tra.
- Tokenizer offline và số đo tài nguyên chưa kiểm chứng.

## Log được giữ nguyên
- ../log-test/powershell.xml: 46338 byte; SHA256 AFE90E8DE494B96E466DA8EBAAC7E785FAD94D3A5037E1A11846629CFC4C8A07.
- ../log-test/security.xml: 181430 byte; SHA256 C74FB48717F18FD697A1AE563A550F82F2B9E378F1A89CE2DC68B0CA91F68BDA.
- Chỉ kiểm kê/hash, chưa xác nhận nội dung đầy đủ hoặc nhãn.

## Điều kiện tiếp theo
Design yêu cầu Python 3.11, máy có 3.13.7. Cần chọn cài thêm 3.11 hoặc cập nhật design để kiểm chứng 3.13 trước task 1.3. Không tự thay runtime thiết kế. Mở Docker Engine trước khi kiểm chứng n8n.

