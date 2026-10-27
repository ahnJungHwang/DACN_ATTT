# Đối chiếu bàn giao — 2026-10-26

Biên bản này đối chiếu tám spec và ghi phần chưa đạt; không xác nhận nghiệm thu toàn hệ thống hoặc chất lượng phát hiện của SLM. Mã nguồn trong Thang Code/winlog-agent, giữ nguyên log-test và các thư mục thành viên khác. Không commit, push hoặc archive thay đổi.

## Cài mới và kiểm tra

Đã tạo môi trường Python 3.11 riêng .venv-handoff, cài requirements.txt theo setup.md; pip check không phát hiện dependency hỏng. Bộ pytest có 104 bài đạt, một cảnh báo deprecation từ Starlette/httpx. Node.js 24.12.0 phục vụ kiểm thử logic workflow. Bộ collection.tests.ps1 đạt trên Windows PowerShell 5.1; ExecutionPolicy Bypass chỉ áp dụng tiến trình thử, không thay policy lưu trên máy.

Đã xác minh config, chạy API bằng môi trường này trong kiểm tra n8n thật, kiểm tra auth, poll, truy XML và export JSONL. Ollama được cập nhật ngoài lượt triển khai từ 0.40.9 sang 0.40.11: đã đo lại 10/10 fixture tokenizer, giữ bản xác minh cũ. Image n8n 2.44.6 dùng digest cố định trong n8n.md. OpenSpec validate --strict đạt. Đây là cài mới môi trường Python trên máy hiện có Docker/model, chưa phải thử trên một máy Windows hoàn toàn mới.

## Đối chiếu tám khả năng

1. **windows-log-collection**: Export-WindowsLogs.ps1 và Collection.psm1 xuất XML/manifest theo khoảng đóng, báo partial/no_events; collection.tests.ps1 và test_verify_collection.py kiểm lỗi, hash, thời gian, host/count. Có hướng dẫn tiếng Việt và mẫu nhật ký. Ngày 2026-10-27 đã thu thật trên VMware (run a36f29e9, 157 sự kiện đủ 4 ID) sau khi sửa lỗi lệch múi giờ của bộ lọc Get-WinEvent; task 3.4 đã đóng, xem vm-collection-verification.md.
2. **windows-log-normalization**: xml_logs/normalize/import_logs/script_blocks cùng các test tương ứng kiểm encoding, namespace, DTD/entity, giới hạn, trường thiếu, vai trò Subject/Target, PID và mảnh 4104. Đã nhập bản sao 182 sự kiện thật, giữ refs và raw XML; hash nguồn không đổi. Tính đầy đủ của audit VM chưa được xác nhận.
3. **event-correlation**: correlation/cases và test_correlation/test_cases kiểm cửa sổ neo, ngưỡng, khác tài khoản/nguồn, TargetLogonId, PID tái sử dụng và quan hệ mơ hồ. Bản sao dữ liệu thật có 154 nhóm giữ 182 sự kiện. Đúng tài khoản/phiên của kịch bản thực tế vẫn cần nhật ký thao tác, chưa dùng nhóm tự tạo làm nhãn chuẩn.
4. **local-slm-analysis**: ollama/context_tokens/inference/payload/results có test local-only, model allowlist, không cloud fallback, context, đầu ra sai/ref sai, tuần tự và snapshot. Có 10/10 token fixture khớp Ollama hiện tại, smoke tổng hợp và hai đợt chạy log thật. JSON hợp lệ không chứng minh lý do đúng; model còn bất đồng/suy diễn. Xem real-log-smoke.md và real-n8n-verification.md.
5. **analysis-service**: service/api có test hàng chờ, singleton, idempotency, timeout, restart, HTTP, xác thực, CSRF và xuất dữ liệu. Workflow thật truy được kết quả/bằng chứng và gửi lại sau restart không tạo request mới. Đã thử thêm dừng tiến trình khi job running, client mất response và timeout 1 giây với Ollama thật, chặn model kế và khôi phục kết quả; xem recovery-verification.md.
6. **n8n-orchestration**: JSON bàn giao không nhúng token, Manual/Edit Fields/HTTP/Wait/Switch. test_workflow kiểm cấu trúc và biên JavaScript; 9 lượt n8n thật với backend tổng hợp kiểm nhãn/poll/lỗi. verify_real_n8n.py đã chạy hai model thật, so khớp API/refs/export và replay sau restart. Workflow n8n hằng ngày đã import nhưng chưa gán credential thật; không tự thay tài khoản hoặc volume.
7. **local-analysis-workspace**: giao diện Jinja2/static local có luồng upload, tái sử dụng nguồn, tạo ca, chọn hai model, trạng thái, XML và export; trình duyệt đã kiểm toàn luồng với mock và kiểm escape nội dung. Báo cáo đánh giá đã xem bằng trình duyệt trên dữ liệu mẫu. Chưa kiểm toàn luồng trình duyệt với nhật ký VM thật; không đánh dấu task 11.1 xong bằng kết quả API/n8n.
8. **slm-evaluation**: evaluation_data/runner/metrics/resources/reports và test_evaluation kiểm provenance/leakage, hai mode, ba repeat, khóa model/options, mẫu số, tài nguyên thiếu, rubric và export. Runner tổng hợp tạo 24 hàng mẫu, báo thiếu dữ liệu rõ ràng. Chưa có tập thật 10 development/40 evaluation đủ nhóm và chấm thủ công; chưa có cơ sở chọn model.

## Các cổng nghiệm thu còn mở

- Đã thu VMware ngày 2026-10-27 (run a36f29e9, task 3.4), xem vm-collection-verification.md. Còn thiếu edition/build/auditpol trong nhật ký thao tác.
- Toàn luồng giao diện + n8n trên lần thu đó, đối chiếu tài khoản và phiên.
- Phiên phân tích khi thực sự ngắt Internet sau chuẩn bị.
- Cập nhật: mục phục hồi 11.3 đã có kiểm chứng job running, timeout, client mất response và backup/restore SQLite/raw/volume n8n trong recovery-verification.md. Phần volume đối chiếu file/metadata, chưa thử đăng nhập n8n trên bản khôi phục.
- Tập dữ liệu thật có nhãn/split độc lập, chạy đối chứng hai model/hai mode/ba repeat, chấm phiên và khuyến nghị model từ số đo.

Không dùng dữ liệu tổng hợp, log cũ thiếu nhật ký hoặc sáu lượt smoke thay cho những cổng này. Không công bố accuracy/precision/recall hoặc model thắng khi chưa có đánh giá thật.

## Tài liệu vận hành

Bắt đầu từ setup.md → windows10-collection.md → tokenizers.md → ui.md/api.md → n8n.md. Theo storage.md để sao lưu dữ liệu; backup ứng dụng không bao gồm secrets, model, tokenizer, config hoặc volume n8n, cần bảo quản riêng. Theo evaluation.md để khóa dataset/chấm/chạy đối chứng. real-n8n-verification.md chỉ rõ vị trí bằng chứng local, phạm vi thử và các lần lỗi chuẩn bị.
