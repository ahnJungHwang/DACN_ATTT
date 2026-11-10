# Hướng dẫn sử dụng thư mục `web/`

Giao diện web giám sát của AI Server, chia làm 2 phần:

```
web/
├── frontend/   index.html     -> trang SIEM (HTML/JS tĩnh) hiển thị trên trình duyệt
└── backend/    siem.py        -> API + luồng realtime cho trang SIEM (dùng với app.py)
                dashboard.py   -> SOC Dashboard kiểu cũ (dùng với app1.py)
```

Thư mục `web/` **không chạy riêng**. Nó được gắn vào AI Server trong [`app/`](../app/HUONG_DAN_SU_DUNG_app.md). Muốn xem giao diện thì khởi động server, rồi mở trình duyệt:

```
https://<IP máy server>:8443/          (chạy trên chính máy server: https://127.0.0.1:8443/)
```

## `frontend/index.html` – trang SIEM

Trang hiển thị theo thời gian thực:
- **Overview:** tổng quan số sự kiện, số cảnh báo và các agent đang hoạt động.
- **Events:** các sự kiện Windows nhận được từ client.
- **Alerts:** các kết luận `ALERT` của AI kèm lý do.
- **Live Terminal:** toàn bộ nội dung server in ra màn hình, đẩy thẳng lên web.

Muốn sửa giao diện thì sửa file này. Không cần khởi động lại server, chỉ cần tải lại trang.

## `backend/siem.py` – backend của trang SIEM

Được `app/app.py` gắn vào bằng `siem.install(app)`.

| Địa chỉ | Chức năng |
|---|---|
| `GET /dashboard` | Trả về `web/frontend/index.html`. |
| `GET /api/state` | Trạng thái hiện tại: sự kiện, cảnh báo, agent, lịch sử. |
| `GET /api/stream` | Đẩy dữ liệu realtime (Server-Sent Events) cho trang web. |

- Lịch sử cảnh báo được nạp lại từ các file JSON trong `results/`. Vì vậy khởi động lại server vẫn còn thấy các cảnh báo cũ.
- Nếu báo lỗi "Thiếu web/frontend/index.html", hãy kiểm tra file đó còn đúng chỗ không.

## `backend/dashboard.py` – SOC Dashboard (bản cũ)

Được `app/app1.py` gắn vào bằng `setup_dashboard(app)`. Ngoài xem kết quả, dashboard này còn cho chạy phân tích ngay trên web.

| Địa chỉ | Chức năng |
|---|---|
| `GET /dashboard` | Trang dashboard (HTML viết sẵn bên trong file). |
| `GET /api/dashboard/overview` | Số liệu tổng quan. |
| `GET /api/dashboard/cases` | Danh sách ca trong `data/` và `data01/`. |
| `GET /api/dashboard/run-detail` | Chi tiết một lần phân tích. |
| `GET /api/dashboard/benchmark` | Kết quả so sánh mô hình. |
| `POST /api/dashboard/run-case` | Chạy phân tích một ca ngay trên web. |

## Lưu ý

- Cả hai file backend đều dùng `core/analyze.py` và tự thêm `core/` vào đường dẫn tìm module.
- Đang dùng bản `app.py` thì giao diện là **SIEM** (`siem.py` + `index.html`). `dashboard.py` chỉ có tác dụng khi chạy `app1.py`.
