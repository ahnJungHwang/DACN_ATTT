# Windows Log SLM Agent

Đang triển khai theo change build-local-windows-log-slm-agent. Đã có môi trường Python 3.11, cấu hình, lưu trữ SQLite/bằng chứng, sao lưu/khôi phục và script thu log Windows PowerShell 5.1. Chưa có API/giao diện hoặc luồng phân tích SLM hoàn chỉnh.

- [Cài đặt và kiểm thử](docs/setup.md)
- [Môi trường đã xác minh](docs/environment.md)
- [Thu log trong máy ảo Windows 10](docs/windows10-collection.md)
- [Lưu trữ và sao lưu](docs/storage.md)
- [Nhập XML và schema chuẩn hóa](docs/importing.md)

Kiểm thử hiện tại: 48 test Python đạt; bộ kiểm thử PowerShell 5.1 bằng sự kiện tổng hợp đạt. Đã nhập bản sao log-test và truy lại 182 sự kiện. Chưa chạy thu mới trên VM hoặc đo độ chính xác model.

app/: ứng dụng; scripts/: PowerShell/CLI; templates/ và static/: giao diện; workflows/: n8n; prompts/: prompt; tests/: kiểm thử; docs/: tài liệu.

Không đưa dữ liệu thật/bí mật vào Git. Giữ nguyên log-test.

