# Môi trường triển khai

Kiểm tra chỉ đọc ngày 2026-10-24 (Asia/Saigon). Chưa phải bằng chứng ứng dụng chạy.

## Đã xác minh trên máy thật
- CPU AMD Ryzen 7 7840HS: 8 nhân, 16 luồng.
- RAM hệ điều hành nhận: 23.19 GiB.
- GPU: AMD Radeon 780M và NVIDIA GeForce RTX 4050 Laptop GPU. Chưa đo VRAM hoặc GPU Ollama thực dùng.
- Python 3.13.7 có sẵn và được giữ nguyên. Đã cài thêm Python 3.11.9 bằng winget sau khi người dùng cho phép; ứng dụng dùng môi trường riêng `.venv` với Python 3.11.
- Ollama CLI/API: 0.40.9 ở lần kiểm tra đầu; API ngày 2026-10-26 báo 0.40.11. Đã xác minh lại 10/10 mẫu token trên 0.40.11; model digest/template không đổi.
- qwen2.5:3b-instruct-q4_K_M: ID ngắn 357c53fb659c, 1.9 GB.
- llama3.2:3b-instruct-q4_K_M: ID ngắn a80c4f17acd5, 2.0 GB.
- Full digest và tokenizer đã được kiểm chứng; xem tokenizers.md và dữ liệu kiểm chứng local. Cả hai model đã qua smoke test, chưa phải đo độ chính xác.
- Ngày 2026-10-25 đã khởi động lại Docker Desktop, engine 29.9.2 hoạt động.
- n8n thực tế 2.44.6, container `n8n`, image `n8nio/n8n:stable`, repo digest `sha256:d02752c6ab446ae9db8deec2f9cc887c378f77cdcad31650814df936b7386dfb`. Port chỉ publish 127.0.0.1:5678; volume hiện có n8n_data được giữ nguyên.
- Từ container: GET http://host.docker.internal:8000/health trả 200; GET /cases với Bearer token trả 200. API vẫn bind 127.0.0.1:8000 trên cấu hình Docker Desktop này; chưa cần đổi firewall hoặc bind mọi interface.

## Chưa xác nhận
- Workflow n8n đã chạy với backend tổng hợp và hai model thật trên bản sao log-test (docs/real-n8n-verification.md). Chưa hoàn tất toàn bộ luồng giao diện/nhật ký VMware. Workflow đã import vào n8n local hằng ngày, còn cần người vận hành gán credential và ca thực tế.
- Người dùng xác nhận VM Windows 10; edition/build, audit và thời gian thực nghiệm chưa kiểm tra.
- Chưa có số đo tài nguyên thực nghiệm đầy đủ.

## Log được giữ nguyên
- ../log-test/powershell.xml: 46338 byte; SHA256 AFE90E8DE494B96E466DA8EBAAC7E785FAD94D3A5037E1A11846629CFC4C8A07.
- ../log-test/security.xml: 181430 byte; SHA256 C74FB48717F18FD697A1AE563A550F82F2B9E378F1A89CE2DC68B0CA91F68BDA.
- Chỉ kiểm kê/hash, chưa xác nhận nội dung đầy đủ hoặc nhãn.

## Điều kiện tiếp theo
Đã chốt thư viện trong requirements.txt. Bộ kiểm thử ngày 2026-10-26 đạt 104 test trong môi trường cài mới. Dịch vụ/API, mock UI, workflow n8n và công cụ đánh giá với backend tổng hợp đã chạy; vẫn cần lần thu log mới từ VMware Win10 và thực nghiệm toàn hệ thống.

