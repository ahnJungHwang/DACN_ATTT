# Hướng dẫn sử dụng thư mục `ps1/`

Các script PowerShell của hệ thống.
Dù file nằm trong `ps1/`, các file log và dữ liệu vẫn đọc/ghi ở **thư mục gốc `winlog-agent`**.

| File | Chạy ở đâu | Chức năng |
|---|---|---|
| `client_agent.ps1` | Máy client | Agent thu thập Windows Event Log và gửi về AI Server. |
| `stop_client.ps1` | Máy client | Tắt agent đang chạy. Được [`bat/stop_client.bat`](../bat/HUONG_DAN_SU_DUNG_bat.md) gọi. |
| `extract_evtx_fragments.ps1` | Máy server | Chuyển các file `.evtx` tấn công thật thành các khối XML (fragment), dùng để sinh bộ dữ liệu `data100`. |

## `client_agent.ps1` – agent thu thập log

Thường được gọi qua [`bat/run_client.bat`](../bat/HUONG_DAN_SU_DUNG_bat.md). Muốn chạy tay thì đứng ở thư mục gốc:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\ps1\client_agent.ps1 -ServerUrl "https://192.168.147.1:8443/ingest" -IntervalSeconds 5 -Model qwen
```

| Tham số | Mặc định | Ý nghĩa |
|---|---|---|
| `-ServerUrl` | `https://192.168.147.1:8443/ingest` | Địa chỉ `/ingest` của AI Server. |
| `-IntervalSeconds` | `5` | Số giây giữa 2 lần quét log. |
| `-Model` | `qwen` | Mô hình server dùng để phân tích (`qwen` / `llama`). |
| `-LogFile` | `client_agent.log` ở thư mục gốc | File nhật ký của agent. |

**Agent làm gì:**
1. Gọi `/health` để kiểm tra kết nối. Nếu lỗi, agent in gợi ý chẩn đoán (lỗi TCP hay lỗi HTTPS).
2. Cứ mỗi chu kỳ, đọc **sự kiện mới** từ:
   - **Security**: 4624, 4625, 4648, 4688, 1102, 4720, 4728, 4732, 4698. **Cần quyền Administrator.**
   - **PowerShell/Operational**: 4104.
   - **System**: 7045 (cài service), 104 (xóa nhật ký).
3. Gửi XML về server, rồi in thông báo phản hồi của server và thời gian phản hồi. Kết luận `ALERT` / `NORMAL` xem trên cửa sổ server, trên trang web hoặc trên Telegram.
4. Nếu gửi lỗi, agent **giữ lại** các sự kiện và gửi lại ở chu kỳ sau.
5. Khi không có sự kiện mới, cứ 30 giây agent gửi tín hiệu "còn sống" (heartbeat) để trang web hiển thị agent đang hoạt động.
6. Mọi hoạt động được ghi vào `client_agent.log`. Xem bằng `bat\view_log.bat`.
7. Lúc khởi động, agent ghi số PID của mình vào `client_agent.pid` ở thư mục gốc, và tự xóa file này khi dừng bình thường hoặc khi nhấn `Ctrl+C`.

## `stop_client.ps1` – tắt agent

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\ps1\stop_client.ps1
```

1. Đọc PID trong `client_agent.pid`, rồi tìm thêm các tiến trình PowerShell có dòng lệnh chứa `client_agent.ps1`. Bước tìm thêm dùng khi mất file `.pid`, hoặc khi agent được chạy từ bản cũ chưa ghi `.pid`.
2. **Chỉ tắt khi xác nhận đúng là agent.** Nếu Windows đã cấp lại số PID cũ cho chương trình khác, script sẽ bỏ qua, không tắt nhầm.
3. Xóa `client_agent.pid`. File chỉ được giữ lại khi có agent không tắt được (vẫn đang chạy).
4. Nếu agent chạy bằng quyền Admin mà script chạy bằng user thường, Windows sẽ từ chối. Khi đó hãy chạy `bat\stop_client.bat` bằng "Run as administrator".

**Lưu ý:**
- Chạy **không có quyền Admin** thì agent cảnh báo và chỉ đọc được PowerShell + System log. Khi đó sẽ không phát hiện được brute-force hay tạo tài khoản backdoor.
- Agent bỏ qua lỗi chứng chỉ tự ký và tự bật TLS 1.2, nên dùng được với `cert.pem` của server.
- Muốn có đủ log, trên máy client chạy [`bat/setup_client.bat`](../bat/HUONG_DAN_SU_DUNG_bat.md) một lần trước.

## `extract_evtx_fragments.ps1` – trích fragment từ EVTX thật

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\ps1\extract_evtx_fragments.ps1
```

| Tham số | Mặc định | Ý nghĩa |
|---|---|---|
| `-Dataset` | `dataset\EVTX-ATTACK-SAMPLES` | Thư mục chứa các file `.evtx` mẫu. |
| `-OutDir` | `data100_fragments\evtx` | Nơi xuất các fragment. |
| `-MinEvents` | `2` | Bỏ qua file `.evtx` có ít sự kiện hơn số này. |

- Chỉ lấy các sự kiện mà hệ thống hỗ trợ: 4624, 4625, 4648, 4688, 4104.
- Mỗi file `.evtx` cho ra `data100_fragments\evtx\<tên>\security.xml` và `powershell.xml`.
- Sau đó chạy `core\generate_data100.py` để ghép thành bộ kiểm thử. Xem [`core/`](../core/HUONG_DAN_SU_DUNG_core.md).
- Script chỉ **đọc** log có sẵn, không chạy bất kỳ nội dung tấn công nào.
- Thư mục `dataset/` không có trong git (khoảng 60MB). Cần tải bộ EVTX-ATTACK-SAMPLES về trước.
