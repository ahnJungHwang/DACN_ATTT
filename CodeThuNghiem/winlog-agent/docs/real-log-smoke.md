# Kiểm tra kỹ thuật trên log đã có — 2026-10-26

Người dùng xác nhận nguồn `D:\DACN_ATTT\Thang Code\log-test`. Hai XML giữ nguyên hash so với bản nhập trước, chưa có manifest.json hoặc nhật ký thao tác. Không sửa nguồn, không tự tạo manifest hay gán nhãn chuẩn hồi tố.

Kho bản sao `data/verify-original` chứa 182 sự kiện (4624: 8; 4625: 9; 4688: 114; 4104: 51), chia thành 154 nhóm. Kiểm tra này chọn ca đầu tiên theo created_at/case_id của mỗi loại nhóm vượt kiểm tra context của cả hai model, giữ nguyên toàn bộ sự kiện trong ca. Đây là lựa chọn kiểm tra kỹ thuật, không phải mẫu đại diện đánh giá độ chính xác.

Ba ca được chọn: unassigned có 1 sự kiện; failed_logins có 2; successful_login có 5. Mỗi ca chạy một lần trên mỗi model qua Service/hàng chờ/SQLite, dùng tokenizer đã kiểm chứng, context 4096, dự trữ 256, tối đa 512 token đầu ra, temperature 0. Model được nạp tuần tự và giải phóng sau khi kiểm tra. Không chạy giao diện hoặc n8n trong lượt này.

- Qwen2.5 3B: unassigned UNKNOWN; failed_logins UNKNOWN; successful_login ALERT. Cả ba kết quả qua kiểm định định dạng.
- Llama3.2 3B: unassigned ALERT; failed_logins UNKNOWN với INVALID_MODEL_OUTPUT; successful_login ALERT. Hai kết quả qua kiểm định định dạng; một kết quả bị từ chối.
- Các evidence_refs trong kết quả hợp lệ đều truy lại được raw XML. Điều này xác nhận liên kết bằng chứng, không xác nhận lời giải thích của model đúng.

Lời giải thích có dấu hiệu suy diễn: thiếu ngữ cảnh/session bị coi là đáng ngờ; tên tiến trình bị gán ý nghĩa nguy hiểm khi chưa có chứng cứ đối chiếu. Không coi ALERT là kết luận tấn công, không tính precision/recall, không chọn model mặc định dựa trên sáu lượt này. Cần nhật ký thao tác và người chấm đối chiếu tài khoản/session/Event Viewer.

Kết quả đầy đủ, raw output, metadata, payload, request/result IDs và thời gian được lưu cục bộ trong `data/real-log-verification-5cf144eb-ee96-49c3-ae93-7b183457eea3.json` cùng database của kho bản sao; data bị Git ignore.

Kiểm tra cài mới: `.venv-handoff` Python 3.11 cài requirements.txt thành công; pip check không có lỗi; pytest 104 passed, một cảnh báo deprecation Starlette/httpx. Kiểm thử collection PowerShell 5.1 đạt với ExecutionPolicy Bypass chỉ cho tiến trình kiểm thử, không thay đổi policy lưu trên máy. OpenSpec strict validation đạt.

Tiến độ vẫn 58/66: chưa đủ bằng chứng đóng thu VM thật, tích hợp toàn hệ thống, offline, phục hồi và đánh giá 10/40 ca. Thu mới theo windows10-collection.md, chép cả XML/manifest/nhật ký, rồi chạy app.verify_collection trước khi nhập. Mẫu nhật ký nằm tại lab-journal-template.md.
