# Hướng dẫn sử dụng thư mục `bat/`

Các file `.bat` để bấm đúp chạy nhanh trên Windows.
Mỗi file tự chuyển về **thư mục gốc `winlog-agent`** trước khi chạy, nên `.env`, `.venv`, `cert.pem`, `key.pem` vẫn nằm ở thư mục gốc như cũ.

## Phía máy SERVER

| File | Chức năng |
|---|---|
| `run_server_https.bat` | **Khởi động AI Server qua HTTPS** (khuyên dùng). Đọc `.env` để lấy `APP_MODULE` và `HTTPS_PORT` (mặc định `app`, cổng 8443). |
| `run_server.bat` | Khởi động AI Server qua HTTP, cổng 8000. |
| `run_server_https1.bat` | HTTPS cổng 9443, luôn chạy `app.py`. Tự kiểm tra `.venv`: nếu thiếu, hoặc chép từ máy khác không chạy được, thì tạo lại và cài `requirements.txt`. Dùng khi mang dự án sang máy mới. |
| `run_evaluation.bat` | Chạy [`core/evaluate.py`](../core/HUONG_DAN_SU_DUNG_core.md) để so sánh mô hình. Nhận tham số giống `evaluate.py`, ví dụ `bat\run_evaluation.bat --quick`. |
| `export_n8n_image.bat` | Đóng gói container Docker `n8n` đang chạy thành file `winlog-n8n-docker.tar` ở thư mục gốc, để mang sang máy khác. |
| `import_n8n_image.bat` | Nạp `winlog-n8n-docker.tar` vào Docker và chạy container `n8n` ở cổng **5679** (`http://localhost:5679`). |

Trước khi chạy server, cần có:
- Ollama đang chạy và đã tải mô hình.
- Docker Desktop đang bật, nếu muốn dùng n8n và Telegram. Không có n8n thì server tự phân tích.
- Đã có `.env` (copy từ `.env.example`).

## Phía máy CLIENT (máy được giám sát)

| File | Cần Admin? | Chức năng |
|---|---|---|
| `setup_client.bat` | **Có** | Bật chính sách ghi log của Windows (chỉ cần chạy 1 lần): tạo tiến trình + dòng lệnh (4688), đăng nhập (4624/4625), PowerShell ScriptBlock (4104), quản lý tài khoản (4720), nhóm bảo mật (4728/4732), scheduled task (4698). |
| `run_client.bat` | Nên có | Chạy [`ps1/client_agent.ps1`](../ps1/HUONG_DAN_SU_DUNG_ps1.md) để gửi log về server. Không có quyền Admin thì không đọc được Security log. |
| `view_log.bat` | Không | Xem trực tiếp 30 dòng cuối của `client_agent.log` (ở thư mục gốc). |
| `stop_client.bat` | Chỉ khi agent chạy bằng Admin | Tắt client agent. Đọc PID trong `client_agent.pid` và kiểm tra đúng là `client_agent.ps1` rồi mới tắt; nếu không có file `.pid` thì tìm agent theo dòng lệnh. Logic nằm trong [`ps1/stop_client.ps1`](../ps1/HUONG_DAN_SU_DUNG_ps1.md). |

**Sửa địa chỉ server trong `run_client.bat`** trước khi chạy:

```bat
set SERVER_URL=https://192.168.147.1:8443/ingest   & rem IP máy server + cổng HTTPS
set INTERVAL=5                                     & rem số giây giữa 2 lần quét log
set MODEL=qwen                                     & rem qwen hoặc llama
```

Nếu server và client chạy trên cùng một máy, dùng `https://127.0.0.1:8443/ingest`.

## Mô phỏng tấn công (để demo)

> ⚠️ Các file này **thực sự thay đổi máy**: tạo rồi xóa tài khoản `hacker_soc_test`, cố đăng nhập sai, chạy lệnh PowerShell giả lập tải mã độc. Chỉ chạy trên **máy ảo client**, bằng quyền Administrator.

| File | Nội dung |
|---|---|
| `simulate_attack.bat` | Demo 1, nhanh: đăng nhập sai nhiều lần, PowerShell tải mã từ C2 (4104), tạo tài khoản backdoor. |
| `simulate_attacks_demo2.bat` | Demo 2: nhiều kịch bản theo MITRE ATT&CK (brute-force, download cradle T1059.001, chiếm quyền, backdoor, trinh sát `whoami` / `systeminfo` / `nltest`...). |

## Thứ tự demo gợi ý

1. **Server:** bật Ollama và Docker n8n, rồi chạy `run_server_https.bat`.
2. **Client:** chạy `setup_client.bat` (lần đầu), rồi chạy `run_client.bat` bằng quyền Admin.
3. **Client:** chạy `simulate_attack.bat`. Theo dõi kết quả trên trang web của server và trên Telegram.

## Lưu ý

- Có 2 cách dừng client: chạy `stop_client.bat`, hoặc nhấn `Ctrl+C` / đóng cửa sổ `run_client.bat`.
- Nếu agent đang chạy bằng quyền Admin, `stop_client.bat` cũng phải chạy bằng quyền Admin. Nếu không, Windows không cho tắt, và script sẽ báo lỗi kèm hướng dẫn.
- Khi chép sang máy client, giữ nguyên 2 thư mục `bat\` và `ps1\` cạnh nhau, vì `run_client.bat` gọi `..\ps1\client_agent.ps1`.
