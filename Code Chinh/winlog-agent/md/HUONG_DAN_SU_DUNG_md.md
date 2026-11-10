# Hướng dẫn sử dụng thư mục `md/`

Nơi chứa các tài liệu Markdown chung của dự án.
Hướng dẫn cho từng thư mục code nằm ngay trong thư mục đó, theo dạng `HUONG_DAN_SU_DUNG_<tên thư mục>.md`.

## Tài liệu chung

| File | Nội dung | Đọc khi nào |
|---|---|---|
| `HUONG_DAN_CAI_DAT_VA_VAN_HANH.md` | Kiến trúc client-server; cài Ollama, Python, mở firewall, Docker n8n; cấu hình máy server và máy client. | Lần đầu dựng hệ thống. |
| `PACKAGING_AND_DEPLOYMENT_GUIDE.md` | Đóng gói dự án và n8n (file `.tar` hoặc workflow JSON + docker-compose), quy trình 3 bước triển khai trên máy mới. | Khi mang dự án sang máy khác. |
| `DIEM_YEU_VA_HUONG_PHAT_TRIEN.md` | Hiện trạng, các điểm yếu (phát hiện, bảo mật, đánh giá), lộ trình ngắn / trung / dài hạn và bài học. | Khi lên kế hoạch việc tiếp theo; cập nhật mỗi khi xong một mục. |

## Hướng dẫn theo từng thư mục

| Thư mục | Hướng dẫn |
|---|---|
| `app/` – các phiên bản AI Server | [HUONG_DAN_SU_DUNG_app.md](../app/HUONG_DAN_SU_DUNG_app.md) |
| `bat/` – file chạy nhanh | [HUONG_DAN_SU_DUNG_bat.md](../bat/HUONG_DAN_SU_DUNG_bat.md) |
| `core/` – bộ phân tích, đánh giá, sinh dữ liệu | [HUONG_DAN_SU_DUNG_core.md](../core/HUONG_DAN_SU_DUNG_core.md) |
| `ps1/` – agent client và script PowerShell | [HUONG_DAN_SU_DUNG_ps1.md](../ps1/HUONG_DAN_SU_DUNG_ps1.md) |
| `web/` – giao diện SIEM / Dashboard | [HUONG_DAN_SU_DUNG_web.md](../web/HUONG_DAN_SU_DUNG_web.md) |
| `blind_test/` – kiểm thử mù | [HUONG_DAN_SU_DUNG_blind_test.md](../blind_test/HUONG_DAN_SU_DUNG_blind_test.md) |
| `eval_real/` – đánh giá trên log thật | [HUONG_DAN_SU_DUNG_eval_real.md](../eval_real/HUONG_DAN_SU_DUNG_eval_real.md) |

## Bảng đối chiếu đường dẫn cũ → mới

3 tài liệu chung ở trên **đã được cập nhật** theo cấu trúc thư mục mới.
Bảng dưới đây dùng khi đọc các ghi chép cũ hơn (ví dụ nhật ký tuần trong `NhatKyTuan/`), viết trước khi sắp xếp lại thư mục:

| Trong tài liệu ghi | Đường dẫn hiện tại |
|---|---|
| `run_server_https.bat`, `run_client.bat`, ... | `bat\run_server_https.bat`, `bat\run_client.bat`, ... |
| `client_agent.ps1` | `ps1\client_agent.ps1` |
| `analyze.py`, `evaluate.py`, `generate_*.py` | `core\analyze.py`, ... |
| `app.py`, `app1.py`, ... | `app\app.py`, ... (chạy uvicorn với `--app-dir app`) |
| `siem.py`, `dashboard.py` | `web\backend\...` |
| `web\index.html` | `web\frontend\index.html` |
