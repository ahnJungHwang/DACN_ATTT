# Chuẩn bị trên máy thật

Dùng Python 3.11 riêng, không thay Python 3.13 của máy. Mở PowerShell ở thư mục winlog-agent:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item config.example.toml config.local.toml
.\.venv\Scripts\python.exe -m app.config config.local.toml
.\.venv\Scripts\python.exe -m pytest -q
```

data_root tương đối tính từ thư mục chứa file TOML. Lệnh kiểm tra cấu hình không tạo dữ liệu.
Giữ workers=1; nhiều worker sẽ vi phạm khóa suy luận và hàng chờ thiết kế.

Mặc định bind local 127.0.0.1. Khi tích hợp Docker, phải chọn đồng thời bind_mode="docker" và host="0.0.0.0", với firewall giới hạn nguồn Docker/host. Chưa có service API trong giai đoạn khởi tạo này; không chạy Uvicorn vào một module chưa được bàn giao.

requirements.in liệt kê dependency trực tiếp; requirements.txt là phiên bản được chốt sau khi cài và kiểm tra trong môi trường sạch. Không commit data, logs, secrets hoặc config.local.toml.

