# Proposal

## Why

Phân tích thủ công các sự kiện Windows rời rạc khó nhận ra chuỗi đăng nhập đáng ngờ và dễ gán nhầm hoạt động giữa tài khoản hoặc phiên. Đồ án cần một hệ thống phân tích log Windows 10 bằng SLM chạy cục bộ, có bằng chứng truy xuất được và phép đánh giá thực nghiệm để chọn model phù hợp mà không gửi log ra dịch vụ AI bên ngoài.

## What Changes

- Bổ sung hướng dẫn cấu hình audit và script xuất log trên Windows 10 bằng Windows PowerShell 5.1, theo khoảng thời gian xác định. Thu Security 4624/4625/4688 và PowerShell Operational 4104 thành XML; báo rõ thiếu quyền, không có sự kiện hoặc xuất thất bại, không xóa log hay âm thầm giới hạn bản ghi.
- Nhập XML trên máy thật, giữ dữ liệu gốc và chuẩn hóa JSONL có mã tham chiếu bằng chứng. Xử lý namespace, encoding, múi giờ, trường thiếu, vai trò tài khoản, PID và các mảnh script block; không dựa chủ yếu vào chuỗi Message hoặc thực thi nội dung log.
- Tạo ca phân tích bằng quy tắc ghép theo máy, tài khoản, loại đăng nhập, nguồn, thời gian và quan hệ phiên/tiến trình. Cửa sổ ban đầu là 60 giây cho thất bại và 5 phút tìm thành công tiếp theo; các ngưỡng cấu hình được. Quan hệ thiếu bằng chứng được ghi rõ, không tự gán chung phiên.
- Phân tích bằng `qwen2.5:3b-instruct-q4_K_M` và `llama3.2:3b-instruct-q4_K_M` qua Ollama local, chọn một model hoặc chạy lần lượt cả hai. Trả `NORMAL`, `ALERT`, `UNKNOWN` cùng lý do và `evidence_refs`; kiểm tra cấu trúc và tham chiếu, lưu lỗi riêng, không đổi lỗi thành NORMAL. Giới hạn đầu vào minh bạch, không âm thầm cắt sự kiện hoặc đưa nhãn chuẩn vào prompt.
- Cung cấp FastAPI cho kiểm tra dịch vụ/model, danh sách và chi tiết ca, yêu cầu phân tích, truy xuất kết quả. Chỉ nhận mã ca đã đăng ký và model cho phép, không nhận đường dẫn tùy ý để đọc file trên máy.
- Cung cấp workflow n8n JSON để import: Manual Trigger → Edit Fields → HTTP Request tới Python → rẽ nhánh ba nhãn và lỗi kỹ thuật. Có timeout phù hợp, không retry vô hạn hoặc tạo kết quả trùng ngoài ý muốn; không gửi log/cảnh báo ra dịch vụ ngoài.
- Cung cấp giao diện local để nhập XML, xem thống kê và lỗi dữ liệu, chọn ca/model, theo dõi phân tích, đọc bằng chứng gốc và xuất JSONL/CSV. Phân biệt dữ liệu mẫu, dữ liệu thật và trạng thái chưa phân tích.
- Đánh giá hai SLM trên cùng dữ liệu, prompt và cấu hình ban đầu `temperature=0`, `num_ctx=4096`, `num_predict=512`, theo hai chế độ đọc riêng lẻ và đọc nhóm. Dự kiến 10 ca phát triển và 40 ca đánh giá chia theo lần thực nghiệm độc lập; đo phát hiện ALERT, cảnh báo nhầm, bỏ sót, UNKNOWN/lỗi, JSON hợp lệ, nhầm tài khoản/phiên, thời gian và tài nguyên. Chạy lặp 3 lần lấy trung vị, tách thời gian nạp model và lưu định danh môi trường; chọn model mặc định từ số liệu thật.
- Bàn giao hướng dẫn tiếng Việt phân biệt thao tác máy ảo/máy thật, cấu hình mẫu, dependency và kiểm thử cho chuẩn hóa, liên kết phiên, kiểm tra bằng chứng và lỗi API.

Phạm vi phiên bản đầu là agent theo luồng phân tích có kiểm soát, không tuyên bố có khả năng tự chủ chọn công cụ. Không bao gồm huấn luyện/fine-tuning, thu log thời gian thực, phản ứng tự động lên hệ điều hành, AI cloud, triển khai công khai hoặc tool calling tự chủ; bổ sung các phần này cần thống nhất riêng. ALERT là dấu hiệu cần kiểm tra, không phải khẳng định máy nhiễm mã độc.

## Capabilities

### New Capabilities

- `windows-log-collection`: Cấu hình và xuất bằng chứng Windows 10 trong lab theo thời gian, với kết quả thu thập minh bạch.
- `windows-log-normalization`: Nhập XML an toàn, chuẩn hóa sự kiện và lưu nguồn gốc để truy xuất bằng chứng.
- `event-correlation`: Tạo ca phân tích theo quan hệ tài khoản, phiên và tiến trình, biểu diễn rõ dữ liệu hoặc liên kết thiếu.
- `local-slm-analysis`: Phân tích bằng hai SLM qua Ollama local, quản lý model/ngữ cảnh và kiểm tra đầu ra có bằng chứng.
- `analysis-service`: Cung cấp API ca phân tích, trạng thái dịch vụ/model và kết quả với phân loại lỗi rõ ràng.
- `n8n-orchestration`: Điều phối yêu cầu phân tích qua workflow import được, xử lý ba nhãn và lỗi kỹ thuật.
- `local-analysis-workspace`: Giao diện local nhập dữ liệu, kiểm tra ca, chọn model, xem kết quả/bằng chứng và xuất dữ liệu.
- `slm-evaluation`: Đánh giá tái lập hai model và hai chế độ đầu vào, chống rò rỉ đáp án và báo cáo chỉ số thực nghiệm.

### Modified Capabilities

Không có; project hiện chưa có spec chức năng được đăng ký.

## Impact

- Mã nguồn, kiểm thử, script lab, workflow và hướng dẫn triển khai mới nằm trong `Thang Code/`; tài liệu thay đổi nằm trong change OpenSpec này. Không sửa `Lam Code/` hoặc `Code Chinh/`; giữ nguyên dữ liệu đang có trong `Thang Code/log-test/`.
- Thêm các endpoint `GET /health`, `GET /models`, `GET /cases`, `GET /cases/{case_id}`, `POST /analyze`, `GET /results/{result_id}`. Python dùng Ollama tại `http://127.0.0.1:11434`; n8n trong Docker Desktop gọi Python qua `http://host.docker.internal:8000`.
- Cần Python, FastAPI, kiểm tra schema bằng Pydantic hoặc tương đương, Ollama với hai model và n8n/Docker Desktop. Thư viện XML, giao diện, lưu trữ, đo tài nguyên và phiên bản cụ thể sẽ được chốt trong design dựa trên môi trường thực tế.
- Máy ảo chỉ tạo log; máy thật xử lý và suy luận, có thể tắt VM sau khi chép dữ liệu. Nếu API lắng nghe trên mọi interface để Docker truy cập, hướng dẫn giới hạn firewall tương ứng.
- Chưa có backend hoặc giao diện ứng dụng trong các file project đã kiểm tra. Log lab có sẵn chưa được xác minh tính đầy đủ; kết quả đánh giá chỉ được tạo khi có dữ liệu thực tế. Không commit log nhạy cảm, mật khẩu hoặc bí mật; không công bố số đo hoặc trạng thái kiểm thử chưa thực hiện.
