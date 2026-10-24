# Design

## Context

Xem proposal.md và tám spec của change để biết phạm vi và hợp đồng hành vi. Project hiện có tài liệu nhóm, cấu hình OpenSpec và dữ liệu chưa được xác minh trong Thang Code/log-test; chưa có ứng dụng để kế thừa. Thiết kế dành cho một người vận hành trên máy thật Windows, một VM Windows 10 thu log và n8n trong Docker Desktop. RAM/GPU, edition của VM và phiên bản n8n thực tế chưa được xác nhận.

Mã nguồn sẽ nằm trong Thang Code/winlog-agent; log-test được giữ nguyên. Các quyết định dưới đây là thiết kế triển khai, chưa phải tính năng đã chạy hoặc số liệu đo được.

## Goals / Non-Goals

**Goals:** Một tiến trình dịch vụ điều phối dữ liệu và suy luận, giao diện/API dùng chung quy tắc; mỗi kết luận truy được tới đầu vào bất biến; lỗi có trạng thái xác định; so sánh model không bị rò rỉ đáp án.

**Non-Goals:** Không thêm hàng đợi phân tán, tài khoản đa người dùng, vector database, framework agent tự chủ hoặc frontend cần chuỗi build riêng. Không tự động cài lại môi trường, đổi policy, xóa dữ liệu hay chỉnh firewall trong bước lập kế hoạch.

## Decisions

### 1. Một dịch vụ Python và giao diện cùng origin

Chọn Python 3.11, FastAPI/Uvicorn, Pydantic, httpx, Jinja2, python-multipart, defusedxml; pytest cho kiểm thử và psutil cho đo tài nguyên. Giao diện server-rendered kèm JavaScript nhỏ, CSS/font phục vụ local, không CDN. FastAPI hỗ trợ template và static assets [tài liệu chính thức](https://fastapi.tiangolo.com/advanced/templates/).

Một Uvicorn worker duy nhất sở hữu hàng chờ và khóa suy luận; các tác vụ đọc/parse nặng chạy ngoài event loop. Không dùng nhiều worker khi chưa có khóa liên tiến trình. n8n chỉ gọi API, không trực tiếp đọc database hay gọi model.

Lựa chọn này tránh thêm server UI như Streamlit và tránh bộ build React cho đồ án nhỏ, đồng thời bảo đảm kiểm tra đầu vào được dùng chung. Chốt phiên bản dependency bằng môi trường cài thử sạch khi triển khai, lưu lock/requirements đã kiểm chứng; không đoán số phiên bản trong design.

Cấu trúc dự kiến: app/ (API, UI, dữ liệu, ghép ca, adapter Ollama, hàng chờ), scripts/ (PowerShell và CLI nhập/đánh giá), templates/, static/, workflows/, prompts/, tests/, docs/, config.example.toml. Entry point đánh giá dùng cùng dịch vụ suy luận để không chạy song song ngoài khóa.

### 2. SQLite lưu trạng thái, file giữ bằng chứng và bản xuất

Chọn SQLite cho transaction và unique constraints; JSONL/CSV là định dạng xuất, không là hàng đợi/trạng thái chính. Chỉ dùng file JSONL sẽ khó chống trùng và phục hồi khi ghi dở; PostgreSQL tạo thêm dịch vụ chưa cần thiết.

Thư mục data/ bị loại khỏi Git, gồm raw/, normalized/, payloads/, exports/ và database. Upload lưu theo ID do hệ thống tạo, không dùng tên file người dùng làm đường dẫn. Quy trình ghi file tạm → kiểm tra → đổi tên nguyên tử → transaction đánh dấu sẵn sàng. File mồ côi do crash được phát hiện khi khởi động và ghi báo cáo, không tự xóa bằng chứng.

Các thực thể:
- Import: import_id, hash file, tên gốc, encoding, khoảng thu, thống kê, trạng thái từng nguồn.
- Event: event_ref, các trường chuẩn hóa, dữ liệu Subject/Target và System/EventData gốc, ordinal trong file, lỗi chất lượng.
- Case: case_id ngẫu nhiên, danh sách refs theo thứ tự, liên kết có mức xác định, cấu hình ghép, version/hash và run_id thực nghiệm.
- Request: request_id, payload_hash, trạng thái, thời điểm, result_id.
- Result: đầu ra model gốc, đầu ra đã kiểm tra, label/error, payload thực gửi, prompt/options/model digest và số đo.
- Evaluation: manifest phiên bản tập dữ liệu, split, ground truth và rubric chấm phiên. Phần này tách khỏi dữ liệu được model đọc.

event_ref dựa trên import_id + file hash + ordinal, không chỉ EventRecordID. Nhập lại file được phát hiện bằng hash, cho phép tái sử dụng nguồn với xác nhận rõ trên UI; không tự nhân đôi sự kiện trong cùng ca. Case là snapshot bất biến; chỉnh lọc hoặc quy tắc tạo version/ca mới.

### 3. Thu log và nhập dữ liệu có kiểm tra

Script Windows PowerShell 5.1 nhận StartTime/EndTime có offset hoặc yêu cầu múi giờ rõ, xuất hai nguồn theo khoảng đóng [start,end], ghi manifest gồm máy, thời gian UTC/local, số lượng và lỗi từng nguồn. Không MaxEvents mặc định. Giữ kết quả nguồn thành công khi nguồn kia lỗi; lần thu mang trạng thái partial. File đầu ra mỗi lần có timestamp và thành phần ngẫu nhiên tránh ghi đè.

Hướng dẫn ưu tiên Windows 10 Pro/Enterprise với policy editor; edition thiếu công cụ phải chuyển sang edition phù hợp trước khi theo lab, không cung cấp thủ thuật bật editor không được hỗ trợ. Kiểm tra audit thực tế và sự kiện mới trước khi thu; hướng dẫn không tuyên bố bật policy sẽ bổ sung log quá khứ.

UI upload tối đa 50 MiB/file, 100.000 sự kiện/lần nhập, độ sâu XML tối đa 32; các giới hạn cấu hình được và công bố. Khi vượt giới hạn từ chối nhập đầy đủ, không lấy phần đầu âm thầm. Từ chối DTD/entity, file hỏng; hỗ trợ BOM/encoding trong specs. Thời gian hỏng lưu bản ghi với cờ chất lượng, không đưa vào ghép theo thời gian.

Đọc theo tên trường XML. 4624/4625 lấy TargetUserName/Domain/SID; 4688 giữ creator và target riêng, ưu tiên target hợp lệ, chỉ fallback creator khi phiên bản/trường nguồn cho thấy cùng tài khoản, nếu không ghi chưa biết. 4688 dùng NewProcessId cho tiến trình mới và ProcessId cho creator; 4104 lấy PID từ System/Execution, không dùng PID provider của 4688 như PID mới.

4104 ghép theo host, ngữ cảnh tiến trình, ScriptBlockId và MessageNumber/MessageTotal. Mảnh trùng nội dung không nhân đôi; mảnh cùng số nhưng khác nội dung đánh dấu conflict; thiếu mảnh không tạo script hoàn chỉnh. Giữ refs từng mảnh để kết quả không trỏ vào bằng chứng tổng hợp không tồn tại.

### 4. Ghép ca xác định được và giữ mẫu bình thường

Sắp xếp theo UTC, rồi event_ref để ổn định thứ tự khi trùng giờ. Nhóm 4625 theo host, domain/user hoặc SID nếu hợp lệ, logon_type và nguồn. Nhóm dùng cửa sổ neo tại thất bại đầu tiên tối đa 60 giây, không nối chuỗi vô hạn chỉ vì mỗi cặp cách nhau dưới 60 giây. Ngưỡng mặc định 5 lần là metadata ứng viên, không phải nhãn chuẩn. Nhóm dưới ngưỡng vẫn tồn tại.

Nguồn thiếu không là wildcard để hợp nhất các nguồn khác nhau. Tìm 4624 tương thích trong 300 giây sau thất bại cuối, ưu tiên ứng viên gần nhất nếu quan hệ không mâu thuẫn; nhiều ứng viên không phân biệt được giữ trạng thái ambiguous. Sau khi một thành công liên kết, nhóm đóng lại để tránh gộp các phiên mới.

Liên kết 4688 bằng tài khoản chạy và mã phiên tương ứng TargetLogonId của 4624; kiểm tra host và thời gian. Thu hoạt động sau đăng nhập trong cửa sổ mặc định 300 giây, cấu hình được và hiển thị phạm vi. Khoảng sống PID có cận trên là lần tạo tiếp theo cùng host/PID nếu quan sát được; chỉ dùng mốc thời gian không chứng minh PID tồn tại xuyên suốt một khoảng thiếu log. Liên kết 4104 mơ hồ được giữ như sự kiện chưa gán.

Không ghép xuyên lần thu/khởi động không chứng minh được liên tục. Tạo ca cho đăng nhập thành công độc lập, nhóm thất bại nhỏ và sự kiện chưa gán; không lọc hết mẫu bình thường. Người dùng có thể tạo ca theo khoảng thu/tài khoản và chọn các nhóm để lập lô trộn; lô giữ group_id và quan hệ, không hợp nhất người dùng. Metadata tên kịch bản chỉ nằm trong manifest đánh giá.

### 5. Adapter Ollama, bằng chứng và ngữ cảnh

Gọi POST /api/chat với stream=false, system prompt cố định, user message JSON được serialize và format là JSON schema. Không tool execution, không lịch sử chat từ ca trước. API hỗ trợ format, keep_alive và số đo thời gian [Ollama Chat](https://docs.ollama.com/api/chat).

Allowlist hai tag đúng proposal. Kiểm tra model đã cài, lưu digest và template metadata trước chạy; tag thay digest giữa đánh giá làm dừng phép so sánh đó. OPTIONS mặc định đúng specs. Adapter tắt proxy môi trường cho kết nối local, không có fallback mạng ngoài.

Mỗi lần gửi tạo snapshot payload gồm events, refs trung tính E001..., các group/quan hệ và ý nghĩa trường; ánh xạ refs về event_ref nội bộ sau validation. Không gửi case_id có ý nghĩa, đường dẫn, tên file, run label, threshold flag gợi đáp án hoặc kết quả khác. System prompt nêu nội dung log không phải chỉ dẫn; điều này giảm rủi ro nhưng không bảo đảm model miễn nhiễm prompt injection.

Ngữ cảnh: phiên bản đầu không tự chia ca. Dùng bộ đếm token offline khớp tokenizer/chat template của từng model, đóng gói metadata tokenizer trong bước chuẩn bị môi trường; không tải lúc phân tích. Tính toàn bộ prompt đã áp template, dự phòng 512 token đầu ra và 256 token an toàn trong 4096. Nếu tokenizer/template chưa được xác minh khớp digest hoặc không đếm được, từ chối phân tích với CONTEXT_UNVERIFIED; không dùng số ký tự/4 như bảo đảm. Kiểm chứng trên fixture biên với prompt_eval_count của Ollama khi triển khai. Nếu quá giới hạn, lưu UNKNOWN/INPUT_TOO_LARGE và yêu cầu thu hẹp; tuyệt đối không tự rút bớt sự kiện. Hai model so sánh chỉ nhận cùng payload nếu đều qua preflight; trường hợp không qua ghi là lỗi coverage, không bỏ khỏi thống kê.

Dùng Pydantic strict: enum nhãn, reason không rỗng, refs thuộc payload, ALERT có ref; từ chối trường ngoài schema. Phản hồi sai/cắt ngắn ghi UNKNOWN với lỗi, giữ raw output local, không tự sửa bằng cách gọi một model khác. JSON đúng không chứng minh lý do đúng.

### 6. Hàng chờ, idempotency và hợp đồng HTTP

API phân tích nhận body case_id/model và header Idempotency-Key (UUID); UI và n8n luôn gửi header. Client không gửi header được cấp request_id nhưng không có bảo đảm chống trùng giữa hai request độc lập. Hash payload gồm ca/version, model và cấu hình suy luận snapshot. Unique key trong SQLite bảo đảm cùng key/payload chỉ chạy một lần; key khác payload trả 409.

Một worker suy luận trong service xử lý hàng chờ tuần tự; tối đa 20 yêu cầu chờ, đầy trả 429. Khóa dùng chung cho UI, n8n và đánh giá. Trạng thái queued → running → completed; completed có label và technical_error nullable. Preflight sai schema/ID/model trả 422/404; Ollama/model chưa sẵn sàng trả 503 trước khi nhận job. Sự cố sau nhận job có result UNKNOWN và mã lỗi.

POST /analyze chờ kết quả tối đa 10 giây: xong trả 200; chưa xong trả 202 với request_id/result_id và status_url. Đây là chi tiết giao thức cho phép client nhận trạng thái theo spec, không thay đổi schema kết quả hoàn tất. GET /results/{result_id} trả envelope state cho queued/running, chưa có label; hoàn tất có result. Bổ sung GET /requests/{request_id} cho phục hồi khi POST timeout trước nhận result_id. Cùng key gửi lại trả trạng thái hoặc kết quả hiện tại.

Timeout suy luận mặc định 300 giây, cấu hình được và lưu. Sau timeout không bắt đầu model kế ngay nếu Ollama có thể còn xử lý: đợi tác vụ kết thúc hoặc unload xác nhận; nếu không xác nhận được, đánh dấu service suy giảm và dừng hàng chờ chờ người dùng xử lý. Crash/restart đánh dấu job running còn sót UNKNOWN/INTERRUPTED, không tự phát lại; queued chỉ tiếp tục sau kiểm tra model. Khởi động yêu cầu khóa singleton, không cho hai service đồng thời dùng cùng data root.

Giữ model trong RAM cho chuỗi đo warmed; khi chuyển model yêu cầu unload bằng API keep_alive=0 và xác nhận trước khi nạp tiếp. API generate cung cấp điều khiển keep_alive [Ollama Generate](https://docs.ollama.com/api/generate). Nếu model khác do ứng dụng ngoài đang nạp, báo người dùng thay vì tự dừng tác vụ không thuộc hệ thống.

### 7. Hợp đồng UI và n8n

UI dùng chung origin API, không mở CORS wildcard. Các route hỗ trợ thêm: POST /imports (multipart); GET /imports/{id}; POST /cases (tạo snapshot từ import/filter/refs); GET /events/{event_ref}; GET /results/{id}/export?format=jsonl|csv. Mọi lookup dùng ID đã đăng ký, không nhận đường dẫn.

Trang chính: nhập dữ liệu và chất lượng; danh sách/chi tiết ca và quan hệ; trạng thái suy luận; kết quả/evidence; báo cáo đánh giá. UI gọi API phân tích và poll trạng thái, nút chọn hai model tạo hai yêu cầu riêng chạy tuần tự. Không bắt buộc UI gọi qua n8n: workflow là client điều phối độc lập của cùng API, tránh nhân đôi logic.

Workflow: Manual Trigger → Edit Fields (case_id/model/request_id) → HTTP Request → phân loại status HTTP. Response 202 đi Wait và poll GET results có giới hạn tổng 600 giây/120 lần mặc định; 200 hoàn tất kiểm tra schema rồi Switch NORMAL/ALERT/UNKNOWN. Lỗi HTTP, response sai và hết thời gian poll có output riêng; không coi status queued là UNKNOWN hoặc NORMAL. Poll hết hạn không hủy kết quả backend, giữ ID để tra cứu. Retry POST mặc định tắt; phục hồi thủ công dùng cùng key.

n8n gọi host.docker.internal:8000. Workflow xuất từ phiên bản n8n thực tế sau khi kiểm thử, ghi version và image digest; không dùng stable trôi nổi làm bằng chứng tái lập. Chỉ core nodes, không credential nhúng hay node gửi ra ngoài. UI kết quả là nơi lưu bằng chứng lâu dài, execution log n8n chỉ nên giữ summary/result_id và có chính sách lưu cục bộ giới hạn.

### 8. Bảo vệ dữ liệu local và vận hành

Mặc định dịch vụ bind loopback. Chế độ Docker truy cập bind 0.0.0.0 theo cấu hình rõ, Windows Firewall chỉ cho phạm vi Docker/host cần thiết; không hướng dẫn mở toàn bộ mạng. UI đọc/ghi yêu cầu session local và CSRF token; API cho n8n dùng token ngẫu nhiên trong cấu hình ngoài Git, lưu qua credential/header khi import. Không hard-code token vào workflow. Các tuyến trạng thái công khai nếu có chỉ trả thông tin tối thiểu.

Escape XML, reason và script bằng template autoescape/textContent; không render raw HTML hoặc dùng eval/subprocess trên dữ liệu. CSV neutralize ô có ký tự công thức đầu ô (kể cả sau whitespace); JSONL/raw giữ nguyên. Giới hạn upload và kiểm tra đường dẫn nội bộ chống traversal. Data/logs/secrets/.venv không vào Git; fixture tổng hợp có nhãn rõ. Cài dependency/model/tokenizer khi chuẩn bị, sau đó kiểm tra phân tích khi ngắt Internet.

### 9. Đánh giá và khả năng tái lập

Manifest ca có run_id, session provenance, split, nhóm kịch bản, nhãn đã đối chiếu và rubric gán phiên. Check leakage theo run/session/ref/hash, bao gồm ca trộn có nhiều nguồn; cùng thành phần nguồn không được qua hai split. Khóa manifest/prompt/options trước tập test. 10/40 và bốn nhóm là mục tiêu dữ liệu, thiếu thì báo không đủ, không sinh ca giả.

Chạy theo model, mode, case và repeat; cùng prompt/schema, khác duy nhất phạm vi events theo mode. Single mode tổng hợp ALERT ưu tiên, rồi UNKNOWN/lỗi, rồi NORMAL; lô rỗng UNKNOWN. Lưu ba repeat riêng. Chất lượng báo từng repeat và tổng hợp có ghi số lượt, không coi 120 lượt là 120 ca độc lập; không bỏ phiếu 3 lần để làm đẹp kết quả. Bảng chính chọn repeat 1 định trước, báo độ biến thiên các repeat còn lại.

Warm-up một ca trung tính ngoài tập chấm, đo lần nạp riêng. Thu perf_counter wall time, Ollama load/prompt/eval durations; thời gian một ca single mode là tổng các lời gọi của ca. Ghi nhận cache có thể ảnh hưởng repeat, không tuyên bố num_ctx/temperature=0 bảo đảm mọi kết quả giống nhau.

Đo peak RSS tiến trình API và cây tiến trình Ollama riêng, khoảng lấy mẫu 200 ms; VRAM qua công cụ GPU sẵn có nếu xác định được PID, không có ghi null/lý do. Không coi RAM toàn máy là RAM riêng model. Mẫu lỗi không đưa vào median thành công mà báo successful_repeats; thiếu ba lần không công bố median ba lần.

TP là chuẩn ALERT/dự đoán ALERT, FP chuẩn NORMAL/dự đoán ALERT, FN chuẩn ALERT/dự đoán khác ALERT. UNKNOWN trên NORMAL không là đúng/TN; báo riêng coverage và số UNKNOWN/lỗi. Mẫu số zero trả null. Tỷ lệ JSON hợp lệ dùng số response model nhận được làm mẫu số, đồng thời báo response/attempt coverage để lỗi kết nối không bị che. Chấm sai tài khoản/phiên thủ công theo rubric và bằng chứng, ghi người chấm; chưa chấm là null.

Xuất comparison.csv riêng model/mode và JSONL chi tiết, kèm manifest hashes. Đề xuất model dựa ưu tiên bỏ sót thấp rồi false positives và tài nguyên, không chọn bằng một câu trả lời minh họa.

### 10. Kiểm chứng theo lớp

Kiểm thử fixture tổng hợp cho XML UTF/namespace/entity, mất mảnh, vai trò Subject/Target, PID tái sử dụng, cửa sổ biên và khác tài khoản. Mock adapter để kiểm tra timeout, JSON sai, ref giả, context vượt và không có cloud fallback. API integration kiểm tra ID/path, idempotency đồng thời, restart, queue full và polling. UI kiểm tra escaping và trạng thái chưa chạy. Workflow thử cả ba nhãn, 202/poll, HTTP lỗi và response sai trên n8n thực tế.

Smoke test hai SLM thật và một lần thu VM là cổng xác minh tích hợp, tách khỏi unit tests. Kiểm tra đầu vào sát giới hạn context với đúng digest/tokenizer là điều kiện cho phép phân tích thật; không thay bằng phỏng đoán. Lưu bằng chứng kiểm thử và phần chưa kiểm chứng, không suy ra kết quả thực nghiệm từ mock.

## Risks / Trade-offs

- SLM 3B có thể suy luận sai hoặc không theo prompt → giữ bằng chứng, validation cấu trúc, tập test độc lập và đánh giá thủ công; không tự phản ứng lên máy.
- Mất log/thiếu session hoặc PID tái sử dụng → giữ unknown links, không gán chắc chắn; thiếu dữ liệu không đồng nghĩa an toàn.
- Tokenizer/template lệch Ollama → khóa digest và kiểm chứng số token; fail closed CONTEXT_UNVERIFIED thay vì cắt ngầm.
- Context 4096 không đủ ca lớn → người dùng thu hẹp phạm vi có ghi nhận, báo lỗi coverage trong đánh giá; chưa thêm tóm tắt vì có thể mất bằng chứng.
- Một worker giới hạn thông lượng → phù hợp máy cá nhân; UI vẫn đáp ứng nhờ hàng chờ và poll. Chưa hỗ trợ nhiều người dùng.
- Timeout HTTP không chứng minh Ollama đã dừng → khóa trạng thái suy luận và không nạp model kế cho đến xác nhận.
- Đo tài nguyên khác phần cứng → công bố phương pháp, sampling và số liệu thiếu; không so sánh như benchmark phần cứng chuẩn.
- SQLite/file không commit nguyên tử cùng nhau → file staging và manifest trạng thái, kiểm tra phục hồi trước công bố dữ liệu.
- Windows edition/policy khác → hướng dẫn kiểm tra sự kiện thật; không khẳng định VM hiện tại đã thu đủ.

## Migration Plan

Không có schema ứng dụng cũ cần migrate. Khi được yêu cầu apply: tạo cấu trúc trong Thang Code/winlog-agent, cấu hình ignore và môi trường; xây thu/nhập/chuẩn hóa/ghép ca; nối một SLM và kiểm chứng context; thêm API/UI, n8n; hoàn thiện so sánh hai model. Tasks sẽ ghi tiêu chí cụ thể, không triển khai ở bước design.

Cài môi trường có version lock, chỉ copy dữ liệu lab vào data/raw, không di chuyển/xóa log-test. Lưu schema_version SQLite và backup trước mọi migration sau này. Rollback bằng dừng service/container và quay về phiên bản app/database backup tương thích; giữ raw logs và Docker volume n8n, không reset repository hoặc xóa dữ liệu để sửa lỗi.

Trước demo: ghi phiên bản n8n, Ollama, Python, model digest/tokenizer; kiểm tra mạng Docker → API → Ollama; chạy offline smoke test; chỉ công bố kết quả đánh giá đã đo.

## Open Questions

- RAM, CPU, GPU thực tế để điều chỉnh timeout và khả năng đo VRAM; không đổi nguyên tắc chạy tuần tự.
- Edition/build Windows 10 và số sự kiện hợp lệ trong log-test để điền hướng dẫn môi trường và kế hoạch thu bổ sung.
- Phiên bản/image digest n8n đang chạy để xuất và kiểm chứng workflow; core-node flow giữ nguyên.

