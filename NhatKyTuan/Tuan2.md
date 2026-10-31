# Nhật Ký Tuần 2

- **Thời gian thực hiện**: [Từ ngày 19/10/2026 đến ngày 25/10/2026]
- **Thành viên tham gia**: Lâm, Thắng

---

#  BÁO CÁO BÀI THỰC HÀNH TUẦN 2

Môn học: Đồ Án Chuyên Ngành An Toàn Thông Tin


#  1 TỔNG QUAN TRIỄN KHAI

Hệ thống được triển khai để thu thập sự kiện trên máy Windows, chuyển dữ liệu về máy chủ và sử dụng mô hình ngôn ngữ nhỏ chạy cục bộ để hỗ trợ nhận diện hoạt động đáng ngờ. Kết quả phân tích được điều phối qua n8n hoặc xử lý trong luồng nhận log của máy chủ và thông báo tới Telegram. Báo cáo trình bày các thao tác cấu hình, diễn biến thử nghiệm và giới hạn của kết quả quan sát được.

##  1.1 Mô hình và vai trò các thành phần



| Thành phần | Vị trí và vai trò |
| --- | --- |
| Client Windows | DESKTOP-D3804BR, IP 192.168.153.147; ghi sự kiện và chạy agent thu thập. |
| Máy chủ phân tích | IP 192.168.153.1, cổng 8000; tiếp nhận /ingest, kiểm tra /health và cung cấp /analyze. |
| Ollama và SLM | Chạy trên máy chủ; ảnh cấu hình sử dụng Qwen2.5 3B tại API loopback cổng 11434. |
| n8n | Chạy workflow theo lịch; gọi API Python và rẽ nhánh theo nhãn phân tích. |
| Telegram | Nhận nội dung cảnh báo; đây là kênh thông báo bên ngoài mạng nội bộ. |


##  1.2 Luồng dữ liệu và phạm vi thực nghiệm

Agent trên client quét log theo chu kỳ 15 giây và gửi về địa chỉ http://192.168.153.1:8000/ingest. Trong cấu hình n8n, Schedule Trigger gọi /analyze mỗi 3 phút. Hai cơ chế này có chu kỳ khác nhau: 15 giây là chu kỳ thu log, còn 3 phút là chu kỳ kích hoạt phân tích trong workflow. Đây là xử lý gần thời gian thực theo chu kỳ, có thêm độ trễ truyền và suy luận AI.

Ảnh workflow sử dụng case_demo_02, trong khi ảnh máy chủ thể hiện phân tích khi tiếp nhận log qua /ingest. Cần lưu mã ca và mã lần chạy để phân biệt hai đường xử lý; các ảnh không đủ để khẳng định chúng cùng dùng một tập sự kiện hoặc chỉ có một cơ chế gửi cảnh báo.

#  2 CÁU HÌNH THU THẬP LOG TRÊN WINDOWS

##  2.1 Ghi nhận đăng nhập thành công và thất bại

Trên client, mở secpol.msc bằng tài khoản quản trị. Truy cập Advanced Audit Policy Configuration → System Audit Policies → Logon/Logoff → Audit Logon và bật cả Success, Failure.



Hình 1. Bật Audit Logon cho cả Success và Failure

Cấu hình trong hình cho phép Windows ghi nhận cả đăng nhập thành công và thất bại, là nguồn dữ liệu để đối chiếu các sự kiện 4624 và 4625. Hai lựa chọn đã được đánh dấu; sau khi lưu, cần tạo một lần đăng nhập thử và kiểm tra kênh Security trong Event Viewer.

##  2.2 Ghi nhận sự kiện tạo tiến trình



Hình 2. Bật Audit Process Creation

Trong nhóm Detailed Tracking, Audit Process Creation được bật ở chế độ Success để ghi sự kiện 4688 khi tiến trình mới được tạo. Sự kiện này giúp xác định chương trình và

ngữ cảnh khởi chạy; riêng việc xuất hiện 4688 chưa chứng minh lệnh đã thực hiện thành công chức năng của nó.

#  2.3 Ghi dòng lệnh trong sự kiện tiến trình

Mở gpedit.msc, truy cập Computer Configuration → Administrative Templates → System → Audit Process Creation, sau đó bật Include command line in process creation events.



Hình 3. Bổ sung CommandLine vào sự kiện 4688

Tùy chọn Enabled trong hình bổ sung dòng lệnh khi đã bật Audit Process Creation. Nhờ đó, hệ thống có thể nhận diện tham số gọi PowerShell hoặc lệnh quản lý tài khoản. Đây là bằng chứng về lệnh được khởi chạy; cần đối chiếu sự kiện quản lý tài khoản hoặc trạng thái thực tế để xác nhận tác động. [1]

#  2.4 Ghi nội dung PowerShell script block



Hình 4. Bật PowerShell Script Block Logging

Trong Windows Components → Windows PowerShell, bật Turn on PowerShell Script Block Logging để thu nội dung script block ở kênh Microsoft-Windows-PowerShell/Operational, thường qua sự kiện 4104. Sau khi áp dụng chính sách, mở một phiên Windows PowerShell mới và chạy lệnh thử. Việc có nội dung script trong log không tự chứng minh script thực thi thành công.

gpupdate /force

#  3 THIẾT LẬP WORKFLOW PHÂN TÍCH VÀ CẢNH BÁO

##  3.1 Kích hoạt workflow theo chu kỳ

Workflow gồm Schedule Trigger, HTTP Request, If và Telegram. Schedule Trigger được cấu hình Trigger Interval là Minutes và Minutes Between Triggers bằng 3. Trong giai đoạn kiểm tra có thể chạy thủ công từng node, sau đó lưu và Publish để lịch tự động có hiệu lực.



Hình 5. Cấu hình Schedule Trigger chạy mỗi 3 phút

Hình thể hiện khoảng cách giữa hai lần kích hoạt là 3 phút và một bản ghi đầu ra của trigger. Trường Timezone đang là America/New_York; nên chuyển về Asia/Ho_Chi_Minh hoặc Asia/Bangkok để thuận tiện đối chiếu với thời gian trên client. Một lần chạy thủ công thành công chưa chứng minh lịch tự động đã được Publish và hoạt động liên tục. [4]

Để kiểm tra lịch, theo dõi ít nhất hai lần thực thi tự động trong mục Executions và ghi thời điểm bắt đầu, kết thúc. Nếu thời gian phân tích kéo dài hơn chu kỳ, cần kiểm soát chạy chồng; nếu không có dữ liệu mới thì tránh phân tích lại cùng ca và gửi lặp cảnh báo.

#  3.2 Gọi API phân tích bằng HTTP Request

Thiết lập phương thức POST và URL http://host.docker.internal:8000/analyze. Tên host.docker.internal được dùng trong Docker Desktop để container n8n truy cập dịch vụ Python chạy trên máy thật. Cổng 8000 phải truy cập được từ container; 0.0.0.0 là địa chỉ bind của dịch vụ, không phải địa chỉ đích để client gửi yêu cầu.



Hình 6. Cấu hình HTTP Request gọi API Python

Hình cho thấy Send Body được bật với Body Content Type là JSON. Phần đầu ra trả case_id là case_demo_02, mô hình Qwen2.5 3B và analysis_status là OK, thể hiện API đã trả kết quả cho lần gọi này. Trạng thái OK không thay cho đánh giá đúng sai của kết luận AI. Phần body không hiển thị đầy đủ trong ảnh nên cần kiểm tra schema tại /docs trước khi cấu hình.

Với API nhận case_id và model dạng bí danh như thiết kế ban đầu, nội dung yêu cầu có thể dùng mẫu dưới đây. Nếu mã nguồn đã thay đổi, phải theo schema đang được máy chủ công bố; không suy ra yêu cầu đầu vào từ tên mô hình đầy đủ xuất hiện ở đầu ra.

```
{
        "case_id": "case_demo_02",
        "model": "qwen"
}
```

#  3.3 Rẽ nhánh theo kết quả phân tích



Hình 7. Điều kiện gửi nhãn ALERT sang nhánh true

Node If đang so sánh {{{$json.verdict.label}} với ALERT và chuyển một item sang nhánh true. Nên bổ sung điều kiện analysis_status bằng OK theo phép AND để tách lỗi xử lý khỏi cảnh báo nghiệp vụ. NORMAL, UNKNOWN và lỗi cần được lưu hoặc đưa sang nhánh theo dõi riêng; nhánh false không đồng nghĩa máy an toàn.

#  3.4 Cấu hình nội dung gửi Telegram



Hình 8. Gửi cảnh báo Telegram bằng dữ liệu đầu ra

Node sử dụng Resource là Message và Operation là Send Message. Chat ID xác định cuộc trò chuyện nhận thông báo; các biểu thức lấy case_id, verdict label, elapsed_seconds và verdict reason từ kết quả Python. Token bot được lưu trong credential. Nội dung cảnh báo có thể gửi ra ngoài qua Telegram dù suy luận AI vẫn chạy cục bộ.

Nên dùng nội dung ngắn, hiển thị đúng mã ca và thời điểm. Nếu reason chứa chuỗi ký tự \n thay vì xuống dòng thật, cần chuẩn hóa trước khi gửi. Cảnh báo nên kèm mã bằng chứng và đường dẫn kết quả nội bộ để người vận hành đối chiếu, không chỉ có diễn giải của mô hình.

#  4 KHỞI ĐỘNG VÀ KIỂM TRA KẾT NỐI

##  4.1 Chạy agent trên máy client

Trên máy Windows có IP 192.168.153.147, mở thư mục C:\winlog-client. Kiểm tra tệp cấu hình và địa chỉ máy chủ trước khi chạy run_client bằng Run as administrator để agent có quyền đọc các log cần thiết.



Hình 9. Các tệp triển khai agent trên client

Thư mục trong hình gồm client_agent dạng Windows PowerShell script và hai tệp batch run_client, setup_client. Giao diện đang ẩn phần mở rộng nên cần bật File name extensions để tránh chọn nhầm. Ảnh chỉ cho biết tên và loại tệp, chưa xác nhận nội dung cấu hình, cơ chế lưu vị trí đọc hay việc tự chạy sau khi khởi động Windows.



| Thông số | Giá trị quan sát trong thực nghiệm |
| --- | --- |
| Client | DESKTOP-D3804BR / 192.168.153.147 |
| API tiếp nhận | http://192.168.153.1:8000/ingest |
| Kiểm tra dịch vụ | GET /health |
| Chu kỳ quét | 15 giây/lần |


Agent cần thông báo kết nối thành công trước khi tạo kịch bản. Khi không có sự kiện mới, trạng thái chờ là bình thường. Khi gửi lỗi, cần giữ lô chưa được xác nhận và có cơ chế thử lại; việc có bảo đảm này hay không phải kiểm tra từ mã nguồn hoặc thử nghiệm đối soát.

#  4.2 Khởi động API máy chủ và dịch vụ AI

Trên máy chủ, khởi động Ollama và kiểm tra tên mô hình đã tải. Sau đó chạy FastAPI tại thư mục dự án. Lệnh dưới đây tương ứng cách khởi động xuất hiện trong ảnh; tùy chọn --reload chỉ nên dùng khi phát triển.

.\venv\Scripts\python.exe -m uvicorn app:app
--host 0.0.0.0 --port 8000 --reload

```
\lancer\AI_agent_ollama\winlog-agent> .\.venv\Scripts\python.exe -m uvicorn app:app --host 0.0.0.0 --port 8000 --reload
Will watch for changes in these directories: ['D:\Freelancer\AI_agent_ollama\winlog-agent']
Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
Started reloader process [16860] using StatReload
Started server process [28508]
Waiting for application startup.
Application startup complete.
127.0.0.1:37399 - "GET / HTTP/1.1" 404 Not Found
127.0.0.1:37399 - "GET /favicon.ico HTTP/1.1" 404 Not Found
127.0.0.1:28462 - "GET /HTTP/1.1" 404 Not Found
127.0.0.1:28462 - "GET /favicon.ico HTTP/1.1" 404 Not Found
127.0.0.1:48831 - "GET /docs HTTP/1.1" 200 OK
127.0.0.1:48831 - "GET /openapi.json HTTP/1.1" 200 OK
127.0.0.1:2133 - "POST /analyze HTTP/1.1" 200 OK
127.0.0.1:3810 - "POST /analyze HTTP/1.1" 200 OK
127.0.0.1:45212 - "GET /docs HTTP/1.1" 200 OK
127.0.0.1:45212 - "GET /openapi.json HTTP/1.1" 200 OK
StatReload detected changes in 'realtime_monitor.py'. Reloading...
  Shutting down
Waiting for application shutdown.
Application shutdown complete.
Finished server process [28508]
Started server process [14308]
Waiting for application startup.
Application startup complete.
StatReload detected changes in 'realtime_monitor.py'. Reloading...
  Shutting down
Waiting for application shutdown.
Application shutdown complete.
Finished server process [14308]
Started server process [2844]
Waiting for application startup.
Application startup complete.
StatReload detected changes in 'realtime_monitor.py'. Reloading...
```

Hình 10. Máy chủ FastAPI lắng nghe trên cổng 8000

Dòng Application startup complete cho biết API đã khởi động. Các yêu cầu GET /docs, GET /openapi.json và POST /analyze trả 200 OK. Hai yêu cầu GET / và /favicon.ico trả 404 chỉ cho biết chưa có route tương ứng. Các lần StatReload làm dịch vụ khởi động lại khi tệp Python thay đổi, vì vậy không phù hợp để chứng minh vận hành không gián đoạn.

Ảnh này xác nhận FastAPI hoạt động, không trực tiếp xác nhận Ollama đã sẵn sàng. Cần kiểm tra riêng API Ollama và một lần suy luận thành công. Với client ở máy khác, giới hạn Windows Firewall cho địa chỉ cần truy cập cổng 8000; API loopback của Ollama chỉ cần cho tiến trình phân tích trên máy chủ.


#  5 ẢNH CUỘC GẶP ONLINE QUA GOOGLE MEET

