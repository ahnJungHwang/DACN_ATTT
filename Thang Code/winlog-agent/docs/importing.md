# Nhập XML và chuẩn hóa

Từ thư mục winlog-agent, dùng Python trong môi trường đã cài:

```powershell
.\.venv\Scripts\python.exe -m app.import_logs --data-root data/demo --security tests/fixtures/synthetic-security.xml --synthetic
```

Đây là fixture **tổng hợp**, không phải số liệu thực nghiệm. Với log VM thật, thay đường dẫn hai file và bỏ `--synthetic`:

```powershell
.\.venv\Scripts\python.exe -m app.import_logs --data-root data/local --security C:\LabExport\security.xml --powershell C:\LabExport\powershell.xml
```

Có thể truyền `--config config.local.toml`. Mặc định tối đa 50 MiB/file, 100.000 sự kiện cho cả lần nhập, XML sâu 32 cấp. Hỗ trợ UTF-8 có/không BOM, UTF-16 LE/BE có BOM; từ chối DTD/entity, XML lỗi, sai nguồn/channel/ID. Vượt tổng số sự kiện thì không công bố lần nhập. Không tự lấy phần đầu file. `complete` nghĩa cả hai nguồn đã nhập, không bảo đảm đủ bằng chứng kịch bản; luôn đọc thêm missing_event_ids, counts_by_id và quality_errors.

Thiếu nguồn hiển thị `missing`; nguồn lỗi hiển thị `error` và giữ nguồn đã nhập được. File Events rỗng vẫn giữ nguyên byte với collection_status=no_events, không tạo ca NORMAL. File trùng hash bị từ chối và báo source_id cũ để tra lại, không âm thầm tạo bản sao. JSONL tại `data_root/normalized/<import_id>.jsonl`; raw XML trong `raw/` giữ nguyên byte và SHA256. Đọc event_ref qua Store.event lấy đúng nguồn/ordinal/XML, không dùng đường dẫn từ client.

## Các trường

JSONL có event_ref, import_id, time (UTC có offset), time_raw, host, channel, event_id, event_record_id, user (name/domain/sid/logon_id hoặc null), logon_type, source_address, logon_id, process_id, creator_process_id, execution_process_id, command_line và script_text. Trường thiếu là null; PID/logon ID được đổi hex/decimal thành số nguyên. `event_data` và `system_xml` giữ thông tin nguồn; raw file mới là bản byte gốc, XML từng sự kiện có thể đổi tiền tố namespace khi serialize.

Timestamp thiếu múi giờ hoặc không đọc được có time=null và quality_errors, không tự gán giờ máy thật. Message bản địa hóa không tham gia trích trường. Duplicate Data cùng Name bị đánh dấu và để null, tránh ghi đè tài khoản âm thầm.

4624/4625 lấy Target làm tài khoản; 4625 không tạo mã phiên thành công từ SubjectLogonId. 4688 giữ Subject/Target riêng, ưu tiên Target. Chỉ fallback Subject với phiên bản 0/1 hoặc version 2 có bộ trường Target rỗng S-1-0-0/0x0 xác định cùng ngữ cảnh; thiếu bộ trường này để chưa biết. NewProcessId là PID mới, ProcessId là PID cha, System/Execution là PID provider. 4104 lấy PID từ System/Execution. Đối chiếu [Microsoft 4688](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688).

`script_blocks` trong báo cáo ghép theo import/host/PID/ScriptBlockId và lần tạo tiến trình quan sát được. Giữ refs tất cả mảnh; mảnh trùng nội dung không lặp text. Thiếu/xung đột mảnh không có script_text hoàn chỉnh. Không thấy vòng đời PID thì không ghép nhiều mảnh thành một script chắc chắn; giữ riêng để tránh nhầm PID tái sử dụng. Đây là ghép bằng chứng, chưa là kết luận model.

## Kiểm chứng ngày 2026-10-24

48 kiểm thử Python đạt, gồm parser, chuẩn hóa, mảnh 4104, transaction, chống trùng và truy bằng chứng. Lệnh fixture ở trên chạy thành công trên thư mục thử riêng.

Đã nhập **bản sao** hai file log-test vào data/verify-original: 182 sự kiện gồm 51×4104, 8×4624, 9×4625, 114×4688. Cả hai nguồn đọc được, không thiếu bốn Event ID; không phát hiện lỗi chất lượng theo bộ kiểm tra hiện tại. Đã tra lại 182 event_ref. Hash log-test sau thử vẫn khớp docs/environment.md. Đây không chứng minh dữ liệu đủ kịch bản, nhãn đúng hoặc model phân tích tốt; chưa chạy model.

VMware xác nhận một VM đang chạy tại `D:\machine\win10\Windows 10 x64.vmx`, cửa sổ hiển thị desktop Windows 10 đã đăng nhập. Chưa thu lần mới bằng script/manifest nên task 3.4 vẫn chưa hoàn thành.
