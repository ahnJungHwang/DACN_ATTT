# Tasks

Phạm vi triển khai: `Thang Code/winlog-agent/`. Giữ nguyên `Thang Code/log-test/`, phần của Lâm và Code Chinh. Danh sách này chưa cho phép bắt đầu code cho đến khi người dùng yêu cầu apply.

Các câu hỏi môi trường trong design chỉ ảnh hưởng cấu hình và bằng chứng kiểm chứng, không đổi kiến trúc; ghi nhận ở 1.1 và xác minh tại nhóm tương ứng. Task cần VM, model, n8n hoặc dữ liệu thật phải để chưa hoàn thành nếu thiếu điều kiện; không thay bằng mock để đánh dấu đạt.

Thứ tự phụ thuộc: 1 → 2; 3 và 4 dựa trên 1–2; 5 sau 4; 6 sau 5; 7 sau 2/5/6; 8–9 sau 7; 10 sau 6–8; 11 sau các nhóm trước. Mỗi nhóm tự bàn giao kiểm thử và tài liệu; nhóm 11 chỉ xác minh tích hợp/thực nghiệm.

## 1. Chuẩn bị môi trường và cấu trúc

- [x] 1.1 Ghi nhận Python/Ollama, RAM/CPU/GPU, Windows VM edition/build và n8n version/image digest bằng kiểm tra chỉ đọc hoặc thông tin người dùng; xác minh docs/environment.md phân biệt giá trị đo được và chưa xác nhận, không tự đổi policy hay cài lại môi trường.
- [x] 1.2 Tạo cấu trúc Thang Code/winlog-agent theo design và cấu hình ignore cho data, logs, secrets, .venv; kiểm tra git status không đưa log thật/bí mật vào thay đổi và log-test giữ nguyên.
- [x] 1.3 Khai báo dependencies và cài thử trong môi trường Python 3.11 riêng, chốt phiên bản đã kiểm chứng; xác minh cài lại từ lock/requirements và import các package thành công.
- [x] 1.4 Tạo cấu hình mẫu cho data root, allowlist model, windows/threshold, timeout, upload limit và bind mode; kiểm tra cấu hình sai bị từ chối, mặc định khớp design, viết hướng dẫn chạy một worker.

## 2. Lưu trữ và nguồn gốc dữ liệu

- [x] 2.1 Tạo schema SQLite có version cho Import, Event, Case, Request, Result và Evaluation; kiểm tra tạo database mới, ràng buộc unique và transaction rollback bằng integration test.
- [x] 2.2 Triển khai file staging, hash, đổi tên nguyên tử và trạng thái nguồn; kiểm tra crash mô phỏng không công bố file ghi dở và phát hiện file mồ côi không tự xóa.
- [x] 2.3 Tạo event_ref theo import/file/ordinal và case snapshot bất biến; kiểm tra trùng EventRecordID khác máy/channel, import lại file và thay cấu hình ghép không làm sai bằng chứng cũ.
- [x] 2.4 Viết tài liệu cấu trúc lưu trữ, backup và phục hồi database/file tương thích; kiểm tra backup/restore trên thư mục dữ liệu thử giữ đúng hash và refs.

## 3. Thu log trên Windows 10

- [x] 3.1 Viết hướng dẫn tiếng Việt bật bốn nguồn sự kiện, kiểm tra edition, policy, phiên PowerShell mới và khóa tài khoản; đối chiếu các bước với windows-log-collection/spec.md, phân biệt máy ảo/máy thật.
- [x] 3.2 Viết script PowerShell 5.1 xuất XML theo StartTime/EndTime có múi giờ và manifest trong thư mục riêng; kiểm tra cú pháp bằng parser 5.1 và test dữ liệu biên thời gian, không MaxEvents ngầm hoặc ghi đè lần thu trước.
- [x] 3.3 Xử lý no-events, thiếu quyền, khoảng thời gian sai và lỗi một nguồn/ghi file; kiểm tra từng trường hợp có trạng thái đúng và không báo đầy đủ khi partial.
- [ ] 3.4 Chạy một lần thu trên VM được phép, kiểm tra XML đọc được và manifest khớp số bản ghi/thời gian; lưu bằng chứng kiểm chứng và hướng dẫn chép file, để task chưa xong nếu chưa truy cập VM.

## 4. Nhập XML và chuẩn hóa

- [x] 4.1 Triển khai parser namespace/UTF-8/UTF-16 và giới hạn file 50 MiB, 100.000 sự kiện, depth 32 cấu hình được; kiểm tra fixture BOM, XML hỏng, entity/DTD và vượt từng giới hạn bị xử lý đúng.
- [x] 4.2 Chuẩn hóa đủ trường JSONL, UTC/null và lỗi chất lượng; kiểm tra timestamp thiếu timezone không tự gán, Message khác ngôn ngữ không làm thay đổi trường.
- [x] 4.3 Ánh xạ Subject/Target của 4624/4625/4688, NewProcessId/creator PID và Execution PID của 4104; kiểm tra tài khoản khác vai trò, PID hex/decimal và trường thiếu.
- [x] 4.4 Ghép mảnh 4104 theo ngữ cảnh và thứ tự, giữ refs; kiểm tra đủ/thiếu/trùng/xung đột mảnh không tạo script hoàn chỉnh sai.
- [x] 4.5 Triển khai nhập file với hash, trạng thái từng nguồn, báo cáo thống kê và xuất JSONL; kiểm tra nhập lại không âm thầm nhân đôi và event_ref mở đúng XML gốc.
- [x] 4.6 Viết hướng dẫn nhập, lỗi dữ liệu và schema; chạy lệnh mẫu trên fixture có nhãn dữ liệu tổng hợp, đối chiếu một bản sao log-test nếu có mà không sửa bản gốc.

## 5. Ghép sự kiện và tạo ca

- [x] 5.1 Gom 4625 theo khóa tài khoản/máy/loại/nguồn, cửa sổ neo 60 giây và ngưỡng 5 cấu hình được; kiểm tra mốc đúng biên, chuỗi kéo dài, khác nguồn và thiếu nguồn không bị hợp nhất sai.
- [x] 5.2 Tìm 4624 trong 300 giây sau thất bại cuối, đóng nhóm và lưu quan hệ; kiểm tra ngoài cửa sổ, nhiều ứng viên và SubjectLogonId của 4625 không được dùng làm phiên thành công.
- [x] 5.3 Liên kết 4688 theo tài khoản chạy/mã phiên và 4104 theo host/PID/thời gian; kiểm tra PID tái sử dụng, thiếu dữ kiện, khác tài khoản/phiên và giới hạn 300 giây sau đăng nhập.
- [x] 5.4 Tạo snapshot ca bình thường, nhóm thất bại nhỏ, sự kiện chưa gán và lô trộn có group_id; kiểm tra giữ thứ tự ổn định, không gán nhãn chuẩn hoặc gộp quan hệ khác phiên.
- [x] 5.5 Viết hướng dẫn lọc khoảng thu/tài khoản, tạo ca và giải thích ambiguous links; kiểm tra ví dụ normal, mixed và missing-data tái tạo được từ fixture.

## 6. Adapter SLM và kiểm tra ngữ cảnh

- [x] 6.1 Triển khai adapter Ollama local, allowlist hai tag, kiểm tra version/digest/template và model có sẵn; mock test model thiếu, lỗi kết nối, URL ngoài local bị từ chối và không fallback cloud.
- [x] 6.2 Tạo prompt/schema cố định và payload builder với refs trung tính; test payload không chứa nhãn chuẩn, tên file/kịch bản hoặc kết quả model kia và script injection không được thực thi.
- [x] 6.3 Chuẩn bị tokenizer/template offline cho cả hai model, ghi nguồn, hash và liên hệ digest; kiểm chứng đếm token toàn prompt trên fixture với prompt_eval_count Ollama, không đánh dấu hoàn thành nếu chưa xác minh khớp.
- [x] 6.4 Triển khai context preflight với 512 token đầu ra và 256 dự phòng, CONTEXT_UNVERIFIED/INPUT_TOO_LARGE; test biên và xác minh không lời gọi suy luận thật hoặc cắt log khi kiểm tra thất bại.
- [x] 6.5 Gọi chat với stream=false và JSON schema; kiểm tra strict label/reason/refs, ALERT thiếu bằng chứng, trường thừa, JSON cắt ngắn; mọi đầu ra sai lưu UNKNOWN cùng raw output/error.
- [x] 6.6 Lưu payload/options/prompt/model metadata và số đo cùng kết quả; test mở kết quả cũ sau thay cấu hình vẫn truy đúng đầu vào.
- [x] 6.7 Triển khai load/unload xác nhận và giữ model cho warm-up; kiểm tra không nạp model thứ hai trước khi model thứ nhất giải phóng, không tự dừng model do ứng dụng ngoài chạy.
- [x] 6.8 Chạy smoke test riêng Qwen và Llama trên ca tổng hợp, gồm sát giới hạn context; lưu response/metadata thực tế và hướng dẫn xử lý lỗi, không coi smoke test là đánh giá độ chính xác.

## 7. Hàng chờ và API phân tích

- [ ] 7.1 Triển khai singleton service, hàng chờ 20 yêu cầu và worker suy luận duy nhất; integration test nhiều client vẫn chỉ một tác vụ chạy và queue đầy trả 429.
- [ ] 7.2 Triển khai Idempotency-Key, payload hash và transaction nhận job; test gửi đồng thời cùng key chạy một lần, khác payload trả 409 và retry không tạo kết quả trùng.
- [ ] 7.3 Triển khai state queued/running/completed, timeout 300 giây và phục hồi INTERRUPTED; test restart không phát lại job running, timeout không mở khóa chạy model kế trước khi xác nhận Ollama dừng.
- [ ] 7.4 Cung cấp GET /health, /models, /cases, /cases/{case_id}, POST /analyze và GET /results/{result_id}; API tests phân biệt 404/422/503, UNKNOWN kỹ thuật và UNKNOWN thiếu bằng chứng.
- [ ] 7.5 Triển khai phản hồi 200/202 sau tối đa 10 giây, status_url và GET /requests/{request_id}; test client mất response tra lại được, queued/running không có nhãn mặc định.
- [ ] 7.6 Cung cấp POST /imports, GET /imports/{id}, POST /cases, GET /events/{event_ref} và export kết quả; test lookup ID không cho đọc đường dẫn tùy ý/traversal.
- [ ] 7.7 Triển khai token local cho API n8n, session UI và CSRF, bind loopback mặc định; test thiếu/sai token, CSRF và không bật CORS wildcard, viết hướng dẫn firewall chế độ Docker.
- [ ] 7.8 Viết tài liệu hợp đồng HTTP và ví dụ PowerShell đúng cú pháp, gồm polling/idempotency/lỗi; chạy ví dụ trên fixture và đối chiếu response với schema.

## 8. Giao diện và xuất kết quả

- [ ] 8.1 Tạo layout Jinja2/static local và luồng xác thực session; kiểm tra mở trang không tải CDN, log/script/reason được escape thay vì thực thi.
- [ ] 8.2 Tạo màn hình nhập XML, thống kê, dữ liệu thiếu/partial và lựa chọn tái sử dụng file trùng; kiểm tra file lỗi không tạo ca giả và thiếu PowerShell hiện rõ.
- [ ] 8.3 Tạo danh sách/chi tiết ca, quan hệ và bộ lọc; kiểm tra mở đúng refs và ca chưa chạy hiển thị chưa phân tích thay vì NORMAL.
- [ ] 8.4 Tạo chọn một/hai model, submit có key và polling; kiểm tra queued/running/completed/error, hai kết quả không trộn và gửi lặp không tạo job trùng.
- [ ] 8.5 Tạo trang kết quả, XML bằng chứng và xuất JSONL/CSV; kiểm tra công thức CSV kể cả sau whitespace được neutralize, JSONL giữ nguyên và dữ liệu mẫu gắn nhãn.
- [ ] 8.6 Viết hướng dẫn sử dụng giao diện; kiểm tra bằng trình duyệt toàn luồng upload → tạo ca → chạy mock → mở bằng chứng → export, ghi rõ mock không là đo model thật.

## 9. Workflow n8n

- [ ] 9.1 Xác nhận n8n version/image digest thực tế và Docker truy cập API có token; kiểm tra health từ container và ghi cách cấu hình host.docker.internal, không mở dịch vụ công khai.
- [ ] 9.2 Tạo JSON workflow Manual Trigger/Edit Fields/HTTP Request, giữ request_id và phân loại HTTP 200/202; import thử đúng n8n version và kiểm tra payload/header không chứa bí mật nhúng.
- [ ] 9.3 Thêm Wait/poll có giới hạn 600 giây/120 lần, giữ ID khi hết hạn; kiểm thử 202 đến hoàn tất, timeout và gửi lại cùng key không tạo job mới.
- [ ] 9.4 Thêm Switch ba nhãn, nhánh lỗi HTTP/schema và output summary/result_id; thử NORMAL/ALERT/UNKNOWN, label thiếu và 5xx bằng backend kiểm thử.
- [ ] 9.5 Xuất workflow đã kiểm chứng và hướng dẫn import/credential/chạy/khôi phục, cấu hình lưu execution local; kiểm tra JSON không có token hoặc node gửi ra ngoài, ghi trạng thái chưa kiểm chứng nếu môi trường không cho thử.

## 10. Công cụ đánh giá hai SLM

- [ ] 10.1 Tạo manifest dataset với run/session provenance, split, nhóm, nhãn, rubric và hash; test kiểm tra leakage giữa split gồm ca trộn dùng chung nguồn/ref/hash.
- [ ] 10.2 Tạo runner qua dịch vụ hàng chờ theo model/mode/case/repeat, khóa prompt/options/digest; test thay digest/cấu hình làm dừng đối chứng và không chạy song song ngoài khóa.
- [ ] 10.3 Triển khai single-event và grouped modes, tổng hợp ALERT → UNKNOWN → NORMAL, lô rỗng UNKNOWN; unit tests phủ log trộn và lỗi một sự kiện.
- [ ] 10.4 Triển khai warm-up ngoài tập chấm và ba repeat, thời gian load/wall/prompt/eval riêng; test single mode cộng thời gian theo ca và repeat thiếu không báo đủ ba mẫu.
- [ ] 10.5 Đo RSS API/cây Ollama theo 200 ms và VRAM theo PID khi có công cụ; test metric thiếu là null/lý do, không thay bằng RAM toàn máy hoặc số 0 giả.
- [ ] 10.6 Tính TP/FP/FN, Precision/Recall/F1, coverage, UNKNOWN/lỗi, JSON valid/response và response/attempt; test mẫu số 0, UNKNOWN trên ca ALERT tính FN và trên ca NORMAL không tính đúng.
- [ ] 10.7 Thêm rubric chấm tài khoản/phiên thủ công có người chấm, xuất JSONL/comparison.csv theo model/mode/repeat; test chưa chấm là null, bảng chính repeat 1 và không biến repeat thành ca độc lập.
- [ ] 10.8 Viết hướng dẫn thu/gán nhãn/split, chạy và đọc chỉ số; kiểm tra runner với dataset nhỏ có nhãn tổng hợp, báo thiếu so với mục tiêu 10+40 thay vì tạo số liệu giả.
- [ ] 10.9 Tạo trang báo cáo local dùng dữ liệu đánh giá đã lưu; kiểm tra báo cáo chưa đủ dữ liệu không tuyên bố model tốt nhất và dữ liệu mẫu không lẫn số liệu thật.

## 11. Xác minh tích hợp và thực nghiệm bàn giao

- [ ] 11.1 Chạy toàn bộ integration trên dữ liệu VM thật: XML → chuẩn hóa → ca → hai SLM → kết quả/bằng chứng qua UI và n8n; đối chiếu thủ công tài khoản/phiên và lưu nhật ký kiểm chứng, không đánh dấu xong bằng fixture/mock.
- [ ] 11.2 Kiểm tra một phiên phân tích khi ngắt Internet sau chuẩn bị dependencies/model/tokenizer, gồm giao diện và n8n; xác nhận không tải tài nguyên ngoài hoặc fallback cloud.
- [ ] 11.3 Kiểm tra phục hồi toàn hệ thống khi backend restart, Ollama timeout và client mất response; xác nhận không trùng suy luận, không mất raw evidence và thao tác rollback bảo toàn database/volume.
- [ ] 11.4 Thu và đối chiếu bộ ca thật hướng tới 10 phát triển/40 đánh giá theo bốn nhóm, khóa split/prompt trước test; lưu manifest và kết quả kiểm tra leakage, giữ task chưa hoàn thành nếu dữ liệu thực tế chưa đủ.
- [ ] 11.5 Chạy đánh giá hai model/hai mode/ba repeat trên tập đã khóa và chấm phiên theo rubric; kiểm tra số ca, số response, lỗi và số đo khớp kết quả gốc, xuất báo cáo thật không điền số thiếu.
- [ ] 11.6 Đề xuất model mặc định từ báo cáo thật với đánh đổi bỏ sót/cảnh báo nhầm/tài nguyên; xác minh mọi nhận định truy được số liệu và nêu giới hạn thực nghiệm.
- [ ] 11.7 Đối chiếu bàn giao với tám specs, chạy kiểm tra cài mới theo tài liệu và OpenSpec validate --strict; tổng hợp bằng chứng kiểm thử/phần chưa đạt, chỉ đóng các task đã xác minh, không tự commit/push/archive.

