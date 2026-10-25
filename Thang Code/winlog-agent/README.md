# Windows Log SLM Agent

Đang triển khai theo change build-local-windows-log-slm-agent. Đã có nhập XML, ghép ca, lưu bằng chứng SQLite, API/hàng chờ và giao diện local. Hai SLM qua Ollama đã qua smoke test; tokenizer đã đối chiếu prompt_eval_count. Workflow n8n đã kiểm chứng với backend tổng hợp; bộ đánh giá thực nghiệm còn đang triển khai.

- [Cài đặt và kiểm thử](docs/setup.md)
- [Môi trường đã xác minh](docs/environment.md)
- [Thu log trong máy ảo Windows 10](docs/windows10-collection.md)
- [Lưu trữ và sao lưu](docs/storage.md)
- [Nhập XML và schema chuẩn hóa](docs/importing.md)
- [Ghép sự kiện và tạo ca](docs/cases.md)

Kiểm thử ngày 2026-10-25: 84 test đạt; bộ kiểm thử PowerShell 5.1 bằng sự kiện tổng hợp đạt. Đã nhập bản sao log-test và truy lại 182 sự kiện; giao diện đã thử upload → tạo ca → chạy hai mock → mở XML → tải JSONL. n8n 2.44.6 chạy qua 9 lượt kiểm chứng nhãn/poll/lỗi/retry trên backend tổng hợp. Smoke test model thật không phải đo độ chính xác. Chưa chạy thu mới trên VM hoặc hoàn tất tích hợp toàn hệ thống với dữ liệu thật.
- [Tích hợp Ollama và phần chưa xác minh](docs/ollama.md)
- [Chuẩn bị tokenizer và chạy thử model](docs/tokenizers.md)
- [Chạy API, xác thực và polling](docs/api.md)
- [Sử dụng giao diện](docs/ui.md)
- [Workflow n8n: cấu hình và kiểm chứng](docs/n8n.md)

app/: ứng dụng; scripts/: PowerShell/CLI; templates/ và static/: giao diện; workflows/: n8n; prompts/: prompt; tests/: kiểm thử; docs/: tài liệu.

Không đưa dữ liệu thật/bí mật vào Git. Giữ nguyên log-test.

