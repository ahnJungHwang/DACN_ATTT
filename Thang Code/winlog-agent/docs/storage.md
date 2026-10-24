# Dữ liệu và phục hồi

SQLite `database.sqlite3` dùng schema version 1 (`PRAGMA user_version`), foreign keys và transaction. Import giữ thông tin lần thu; sources giữ trạng thái từng nguồn (`ready`, `no_events`, `missing`, `error`). Event giữ JSON chuẩn hóa và XML sự kiện. Case giữ snapshot cấu hình, liên kết và refs có hash. Request/Result phục vụ hàng chờ; Evaluation giữ manifest/nhãn chuẩn riêng.

`raw/` giữ nguyên byte file nhập; `normalized/`, `payloads/`, `exports/` dành cho bản xuất. Tất cả nằm trong data root ngoài Git. Tên người dùng đưa vào chỉ là metadata, không dùng làm đường dẫn.

File ghi vào `staging/`, flush/fsync, kiểm tra, đổi tên trong cùng data root rồi mới công bố bằng transaction. Nếu crash, `Store.recovery_report()` liệt kê staging, file mồ côi, thiếu file và sai hash. Không tự xóa. Giữ nguyên thư mục lỗi để đối chiếu; chỉ tiếp tục nhập khi đã kiểm tra báo cáo. Lỗi một nguồn không biến nguồn còn lại thành đầy đủ.

SHA256 phát hiện nguồn trùng: báo ID nguồn cũ để UI sau này xin lựa chọn tái sử dụng. Không tạo sự kiện bản sao. `event_ref` là import UUID + SHA256 file + ordinal bắt đầu từ 1, không dựa riêng EventRecordID. Mỗi lần đổi cách ghép tạo case ID mới; các snapshot cũ không sửa. Các thao tác nhập sự kiện và tạo case rollback toàn bộ khi lỗi.

## Sao lưu và khôi phục

Dừng dịch vụ và mọi tiến trình ghi dữ liệu trước khi chạy. Bản sao lưu chứa cả dữ liệu nhạy cảm như bản gốc, cần giữ local. Đích phải là thư mục mới và ở ngoài nguồn. Từ thư mục winlog-agent:

```powershell
.\.venv\Scripts\python.exe -m app.backup backup .\data .\backups\lan-01 --service-stopped
.\.venv\Scripts\python.exe -m app.backup restore .\backups\lan-01 .\data-restored --service-stopped
```

SQLite được sao lưu bằng backup API; các file đi kèm có manifest hash. Restore kiểm tra version/hash trước khi tạo đích, không ghi đè data hiện hữu. Đổi data_root sang đường dẫn khôi phục chỉ sau khi kiểm tra báo cáo không thiếu/sai hash; dùng phiên bản ứng dụng hỗ trợ schema tương ứng. Giữ bản cũ để rollback. File mồ côi/staging được giữ cả trong backup và báo cáo.

Kiểm thử tự động chỉ dùng dữ liệu tổng hợp: crash trước/sau đổi tên, rollback, nguồn trùng, snapshot bất biến, trùng EventRecordID, backup/restore đúng refs/hash. Chưa là kiểm chứng VM hoặc dịch vụ chạy thực tế.
