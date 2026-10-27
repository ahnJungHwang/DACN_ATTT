# Chuẩn bị trên máy thật

Dùng Python 3.11 riêng, không thay Python khác của máy. Mở PowerShell ở thư mục winlog-agent. Các lệnh tạo môi trường dưới đây dành cho lần cài mới; nếu đã có .venv thì dùng môi trường đó. Bộ test workflow cần Node.js (máy kiểm chứng dùng 24.12.0), ứng dụng Python không cần Node để chạy API.

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
if (-not (Test-Path -LiteralPath config.local.toml)) {
    Copy-Item -LiteralPath config.example.toml -Destination config.local.toml
}
.\.venv\Scripts\python.exe -m app.config config.local.toml
.\.venv\Scripts\python.exe -m pytest -q
```

data_root tương đối tính từ thư mục chứa file TOML. Lệnh kiểm tra cấu hình không tạo dữ liệu.
Giữ workers=1; nhiều worker sẽ vi phạm khóa suy luận và hàng chờ thiết kế.

Chuẩn bị hai model/tokenizer theo [tokenizers.md](tokenizers.md), rồi chạy API:

```powershell
.\.venv\Scripts\python.exe -m app.api --config config.local.toml
```

Mở http://127.0.0.1:8000, nhập token tại data_root/secrets/api-token.txt. Giữ cửa sổ dịch vụ hoạt động. Xem [ui.md](ui.md) và [api.md](api.md) để nhập log, tạo ca và phân tích.

Mặc định bind local 127.0.0.1. n8n Docker dùng http://host.docker.internal:8000; trên cấu hình máy đã kiểm chứng, API loopback vẫn truy cập được từ container. Thử kết nối trước, không tự mở host=0.0.0.0 hoặc firewall. Khi thật sự cần bind Docker, xem phạm vi firewall trong api.md. Workflow và credential được hướng dẫn tại [n8n.md](n8n.md).

Đánh giá theo [evaluation.md](evaluation.md): dừng API trước khi chạy CLI đánh giá cùng data_root. Singleton từ chối hai chủ sở hữu hàng chờ. Muốn xem báo cáo mới, khởi động lại API với cùng cấu hình.

requirements.in liệt kê dependency trực tiếp; requirements.txt là phiên bản được chốt sau khi cài và kiểm tra trong môi trường sạch. Không commit data, logs, secrets hoặc config.local.toml.

