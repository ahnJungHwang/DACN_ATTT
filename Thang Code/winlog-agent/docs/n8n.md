# Workflow n8n local

File import: `workflows/windows-log-slm.json`. Được tạo từ scripts/build_workflow.py và workflows/classify-response.js. Không chứa token hoặc credential thật, không có node gửi mail/chat hay gọi AI cloud.

## Phiên bản đã kiểm chứng

n8n 2.44.6, image digest `n8nio/n8n@sha256:d02752c6ab446ae9db8deec2f9cc887c378f77cdcad31650814df936b7386dfb`. Đã import/chạy bằng CLI trên container kiểm thử riêng cùng image. Sau kiểm chứng, đã thêm workflow **Windows Log SLM - Local analysis**, ID `lTXxbQT2KcobpxxZ`, vào n8n đang dùng, chưa kích hoạt và chưa gán credential thật. Không ghi đè workflow/credential khác. Dữ liệu kiểm thử là tổng hợp và backend mock, chưa phải thực nghiệm Windows 10 → hai SLM → n8n.

Container dùng hằng ngày tên n8n, giao diện http://127.0.0.1:5678, volume n8n_data. Giữ volume và encryption key khi backup/restore; không dùng reset hoặc xóa volume để sửa lỗi. Xem thêm api.md về kết nối host.docker.internal.

## Import và cấu hình một lần

1. Chạy API theo api.md trên máy thật và mở giao diện để nhập log/tạo ca. Sao chép case_id của ca cần phân tích.
2. Đăng nhập n8n local bằng tài khoản đã có, mở **Windows Log SLM - Local analysis**. Khi cài trên máy khác mới cần tạo workflow rồi **Import from File**, chọn windows-log-slm.json. Workflow chỉ dùng Manual Trigger, không cần publish/activate lịch tự động.
3. Tạo credential kiểu **Header Auth**. Name của HTTP header là `Authorization`; Value là `Bearer ` theo sau bởi nội dung `data/secrets/api-token.txt` của API. Giữ token trong credential, không dán vào Edit Fields, node Code, JSON export hoặc chat.
4. Ở cả hai node **Submit** và **Poll**, chọn Generic Credential Type → Header Auth và gán credential vừa tạo. JSON bàn giao cố ý chưa gán credential máy cá nhân.
5. Trong **Edit Fields**, đặt base_url=`http://host.docker.internal:8000`, case_id thật, model là một trong hai tag được phép. Tạo UUID trong PowerShell bằng `[guid]::NewGuid().ToString()`, dán vào request_id. UUID này phải giữ nguyên nếu tra lại/gửi lại cùng ca và model.
6. Nhấn Execute Workflow. Lượt thử đầu tiên nên dùng ca mẫu được đánh dấu rõ trong giao diện. Muốn chạy model thứ hai, đợi lượt đầu xong, đổi model và dùng request_id mới.

## Đọc kết quả

Luồng: Manual Trigger → Edit Fields → Prepare → Submit → kiểm tra HTTP/schema → chờ hoặc rẽ nhánh nhãn. HTTP 202 giữ request_id/result_id; Wait 5 giây rồi GET /results/{result_id}. HTTP 200 completed mới đọc label. Pending không có nhãn mặc định.

- **NORMAL / ALERT / UNKNOWN**: output có summary, reason, evidence_refs, result_id và technical_error. UNKNOWN/TIMEOUT là lỗi kỹ thuật, khác UNKNOWN với technical_error=null.
- **HTTP Error**: lỗi kết nối/HTTP 4xx/5xx, không tự retry. Nếu POST mất response, trạng thái job chưa biết; giữ request_id, tra GET /requests/{request_id} hoặc chạy lại đúng key/body. 404 nghĩa là chưa tìm thấy job ở lần tra đó; không chứng minh lời gọi trước chắc chắn chưa đến server.
- **Schema Error**: HTTP thành công nhưng ID/state/label/lý do/refs không hợp lệ. Không coi đây là NORMAL.
- **Polling Limit**: đã đạt 120 lượt hoặc hạn 600 giây. Job phía Python có thể vẫn chạy. Giữ cả hai ID và tra tiếp theo api.md, không tự đổi request_id.

Request timeout của từng node HTTP là 30 giây; backend chỉ chờ đồng bộ tối đa 10 giây trước trả 202. Workflow timeout 660 giây dành phần dư cho lời gọi đang chạy. Mốc 600 giây bắt đầu trước POST; không phát poll mới sau hạn, nhưng một HTTP đang chờ có thể kết thúc sau hạn. Không bật retryOnFail. API chịu trách nhiệm chống suy luận trùng và khóa model; n8n không trực tiếp gọi Ollama.

Không dùng URL từ response để gọi tiếp: workflow tạo đường dẫn local từ result_id UUID đã kiểm tra. Các node HTTP không follow redirect.

## Lưu kết quả và phục hồi

Settings của workflow lưu manual executions, success và error trong n8n local. Execution có thể chứa lý do/bằng chứng; giữ database/volume trên máy. Không thêm node gửi ra dịch vụ ngoài. Bản export JSON không nhúng credential; nếu tự export sau khi cấu hình, kiểm tra lại trước chia sẻ.

Khi backend restart, tra lại key cũ: running cũ có thể thành UNKNOWN/INTERRUPTED, không tự phát lại. Khi n8n restart hoặc mất execution, request_id đã đặt trong Edit Fields là mã phục hồi; chạy lại cùng cấu hình sẽ truy job cũ. Đổi ca/model mà giữ key trả 409; chỉ tạo key mới khi chủ động bắt đầu lượt phân tích khác.

## Kiểm thử có thể tái lập

tests/verify_n8n.py dùng HTTP backend tổng hợp 127.0.0.1:18082 và credential giả trong container riêng winlog-n8n-verify. Các bản workflow thử và execution nằm ở data/n8n-verification, ngoài Git. Không dùng token API thật hoặc đọc log thật. summary.json ghi từng nhánh đã xác minh.

Ngày 2026-10-25 đã đạt 9 lượt: ba nhãn, UNKNOWN có lỗi kỹ thuật, 202 → Wait → poll → ALERT, thiếu label, HTTP 503, giới hạn polling và chạy lại cùng key giữ nguyên job/result. Test giới hạn đặt bộ đếm ban đầu 119 rồi thực hiện lượt poll 120 để kiểm tra nhanh; không tuyên bố đã chờ 600 giây thực. Biên thời gian 599999/600000 ms và lỗi transport được test riêng bằng JavaScript trong tests/test_workflow.py. Test JavaScript cần Node.js; máy kiểm chứng dùng Node 24.12.0. n8n dùng runtime riêng trong image đã chốt.

Kiểm thử này chứng minh điều phối và phân nhánh, không chứng minh model phát hiện đúng hành vi nguy hiểm. Ngày 2026-10-26 đã kiểm tra thêm workflow gọi hai model thật trên bản sao log-test, polling, gửi lại sau restart và backup/restore kết quả; xem [biên bản tích hợp thật](real-n8n-verification.md). Phiên offline, giao diện trên log thật và đối chiếu nhật ký VM vẫn còn trong nhóm 11.
