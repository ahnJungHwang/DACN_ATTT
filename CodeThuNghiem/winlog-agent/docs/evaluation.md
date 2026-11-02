# Đánh giá hai SLM

Công cụ này đo kết quả của tập ca đã đối chiếu nhãn; không huấn luyện model. Chạy local bằng cùng lớp Service/hàng chờ/singleton của API, không gọi Ollama song song ngoài khóa. Đầu vào model vẫn là payload cố định, không có nhãn chuẩn hoặc rubric.

## 1. Chuẩn bị ca thật

Thu các lần lab độc lập trên VMware Windows 10 theo windows10-collection.md. Ghi run_id, máy, lần khởi động, tài khoản, phiên và thao tác/thời gian. Nhập hai XML, tạo ca trên UI. Đối chiếu XML gốc và thao tác trước khi gán NORMAL/ALERT; không lấy dự đoán AI làm nhãn chuẩn. Không coi PowerShell đơn thuần là tấn công.

Mục tiêu: 10 ca development và 40 ca evaluation, gồm 10 ca mỗi nhóm normal, password_guessing, mixed_same_session, mixed_different_session. Thêm đúng một ca warmup trung tính ngoài hai tập, nhãn NORMAL. File/nguồn và lần thu của warmup cũng phải độc lập. Thiếu dữ liệu vẫn có thể kiểm tra pipeline nhưng báo cáo nêu thiếu từng nhóm, không tự thêm ca cho đủ.

Manifest JSON do người vận hành lập, lưu ngoài Git, ví dụ data/dataset.json:

```json
{
  "version": 1,
  "name": "Windows 10 lab - dataset v1",
  "synthetic": false,
  "rubric_version": "account-session-v1",
  "entries": [
    {
      "case_id": "THAY_CASE_ID_WARMUP",
      "split": "warmup",
      "group": "normal",
      "label": "NORMAL",
      "run_ids": ["THAY_RUN_ID_LAN_THU"],
      "session_keys": ["TEN_VM/BOOT_ID/TAI_KHOAN/LOGON_ID"],
      "annotator": "Thang",
      "rationale": "THAY_MO_TA_THAO_TAC_VA_DOI_CHIEU_LOG",
      "expected_accounts": ["TEN_VM\\lab_demo"],
      "expected_sessions": ["0x123"],
      "evidence_refs": ["THAY_EVENT_REF_TRONG_CA"]
    }
  ]
}
```

Thêm từng ca development/evaluation theo cùng cấu trúc; ví dụ trên chỉ minh họa schema và chưa đủ để chạy. run_ids phải liệt kê tất cả lần thu cấu thành ca trộn. session_keys là định danh toàn cục do người thu đối chiếu (host/boot/account/logon), không dùng riêng `0x123` cho mọi máy. Khi không có logon_id nhưng nguồn chứng minh được một ngữ cảnh độc lập, mô tả định danh ngữ cảnh thu với máy/boot/run và ghi giới hạn trong rationale; không đoán phiên. expected_accounts/expected_sessions ghi đáp án chấm, cho phép danh sách rỗng nếu không xác định được. Khi chấm không được phạt model vì từ chối suy đoán thông tin thật sự thiếu.

evidence_refs phải thuộc ca và không rỗng. Hệ thống tự lấy case hash, file hash, import ID, refs và hash sự kiện chuẩn hóa. Cùng run/session/ref/file/import/sự kiện xuất hiện qua split khác nhau sẽ bị từ chối, kể cả ca trộn. Vì chính sách chia theo nguồn/lần thu, không tách hai ca từ cùng XML vào development và evaluation. Các ID phiên do người ghi vẫn cần đối chiếu thủ công: kiểm tra tự động không chứng minh nhật ký lab là đúng.

Dữ liệu mẫu đặt synthetic=true và phải được nhập với cờ mẫu. Dữ liệu thật và mẫu không được trộn trong một dataset. Fixture có sẵn trong repository được nhận diện bằng hash để tránh coi là dữ liệu thật chỉ vì lần nhập cũ thiếu cờ.

## 2. Khóa và chạy

Chuẩn bị tokenizer theo tokenizers.md. Dừng API bằng Ctrl+C trong cửa sổ đang chạy API, rồi từ winlog-agent:

```powershell
.\.venv\Scripts\python.exe -m app.evaluation_runner .\data\dataset.json --config config.example.toml
```

Không chạy thêm API/runner dùng cùng data_root trong lúc đánh giá: khóa service.lock từ chối chủ sở hữu thứ hai. Runner dùng đúng Service và worker suy luận đang có trong code; CLI là tiến trình sở hữu dịch vụ trong phiên đánh giá. Không tự dừng một tiến trình khác nếu khóa đang bận. Sau đánh giá, mở lại API với cùng cấu hình để xem /reports.

Runner khóa manifest, prompt/schema hash, options và digest/template/Ollama version của cả hai model. Thay các giá trị này sẽ dừng đối chứng và lưu trạng thái failed. Bằng chứng raw được kiểm hash đầu và cuối. Mỗi payload phải qua preflight của cả hai model; lỗi coverage được giữ như UNKNOWN/COMPARISON_PREFLIGHT_FAILED, không cắt sự kiện.

Chạy tuần tự theo model → mode → case → repeat 1/2/3. Single tạo snapshot con một sự kiện, grouped giữ ca gốc. Nhãn single là ALERT nếu có ALERT hợp lệ, nếu không thì UNKNOWN khi có lỗi/UNKNOWN, chỉ NORMAL khi mọi sự kiện hợp lệ đều NORMAL; lô rỗng UNKNOWN. Hai model nhận cùng các snapshot theo mode.

Mỗi model có một warmup ngoài tập chấm, sau unload có xác nhận. Báo riêng wall dành cho bước load, wall gọi chat sau load và Ollama load_duration/prompt_eval_duration/eval_duration (nanosecond). Single cộng thời gian các lời gọi. Một repeat lỗi không được dùng tính trung vị đủ ba lần; xem successful_repeats. Cache có thể ảnh hưởng kết quả thời gian.

Lỗi sau nhận job vẫn giữ result trong database. Nếu runner thất bại, báo cáo chứa những hàng đã hoàn tất và nguyên nhân; không tự chạy lại. Xem requests/results trước khi quyết định một phiên đánh giá mới. Running job chưa chắc đã dừng trên Ollama; vẫn áp dụng service degraded và khóa model theo api.md.

## 3. Tài nguyên

### Đối chứng chỉ luật (rules-only)

Runner tự chạy `baseline_rules` trên cùng tập evaluation, theo cả hai mode `single` và `grouped`. Single dùng cùng snapshot một sự kiện như SLM rồi tổng hợp nhãn bằng cùng quy tắc; grouped dùng nguyên refs và nhóm đã lưu trong snapshot ca. Không lấy nhãn chuẩn để tạo dự đoán, không đưa nhãn luật vào payload SLM và không gọi Ollama cho baseline.

Bộ luật xác định chạy một lần mỗi mode, đánh dấu repeat 1; không nhân bản thành ba repeat. Các hàng nằm trong `baseline_rows`, tách khỏi `rows` của hai SLM. Báo cáo/API/CSV gộp các chỉ số theo tên `rules-only`; JSONL có bản ghi `baseline_result`, gồm nhãn, luật khớp, evidence_refs và thời gian. Số lượt SLM không tăng. Báo cáo cũ không tự được thêm baseline bằng phiên bản luật hiện tại.

Hash mã nguồn baseline lưu tại `lock.baseline_sha256` và được kiểm tra cùng khóa thí nghiệm. Chỉ so sánh chất lượng cùng mode và repeat 1. Baseline không có giới hạn context/token; lỗi context của SLM vẫn giữ UNKNOWN trong mẫu số, cần xem Coverage để hiểu khác biệt. Thời gian baseline chỉ đo phần phân loại bằng luật, không bao gồm tải/nạp model; không coi đây là phép đo cùng loại tài nguyên. JSON hợp lệ/response không áp dụng cho luật (không có response model). Không dùng kết quả luật làm ground truth.

Với fixture hai ca evaluation: có 24 hàng SLM (2 model × 2 mode × 3 repeat × 2 ca) và thêm 4 hàng baseline (2 mode × 2 ca), không phải 28 ca độc lập.

Lấy mẫu mục tiêu mỗi 200 ms: RSS tiến trình Service hiện tại (trong CLI gồm overhead coordinator) và tổng RSS cây tiến trình Ollama, tránh đếm PID hai lần. Không dùng RAM toàn máy làm RAM model. Peak là đỉnh quan sát được, có thể bỏ qua spike giữa hai mẫu. samples/valid_samples/reasons được lưu.

VRAM lấy theo PID bằng nvidia-smi nếu có và đọc được. WDDM, GPU không hỗ trợ, tiến trình không xác định hoặc truy vấn lỗi giữ null kèm lý do, không thay bằng 0. Giá trị RSS/VRAM của lượt mock chỉ phục vụ kiểm tra pipeline, không phải tài nguyên suy luận SLM thật.

## 4. Đọc báo cáo và chấm phiên

Đăng nhập UI rồi chọn **Mở báo cáo đánh giá đã lưu**. Báo cáo tách từng evaluation và đánh dấu mẫu; không tự trộn số liệu nhiều tập. Bảng chính cố định repeat 1; repeat 2–3 báo riêng, không biến 40 ca thành 120 ca độc lập.

TP: chuẩn ALERT, dự đoán ALERT. FP: chuẩn NORMAL, dự đoán ALERT. FN: chuẩn ALERT, dự đoán khác ALERT, kể cả UNKNOWN. UNKNOWN trên NORMAL không tính TN/đúng. Coverage là số ca có nhãn NORMAL/ALERT chia tổng ca. Báo riêng ca có lỗi kỹ thuật, JSON hợp lệ/response nhận được và response/attempt. Mẫu số 0 cho null, luôn giữ tử/mẫu số.

### AI Performance Metrics (phiên bản 2)

- Accuracy = (TP + TN) / tổng ca, bao gồm UNKNOWN trong mẫu số.
- Precision = TP / (TP + FP): tỷ lệ cảnh báo đúng trong các cảnh báo đã đưa ra.
- Recall = TP / (TP + FN): tỷ lệ ca ALERT được phát hiện; UNKNOWN trên ALERT là bỏ sót.
- F1-Score = 2TP / (2TP + FP + FN): trung bình điều hòa Precision và Recall khi xác định được.
- Ma trận 2 × 3 có hàng là nhãn chuẩn NORMAL/ALERT, cột là dự đoán NORMAL/ALERT/UNKNOWN. Giữ riêng UNKNOWN trên NORMAL; không ép thành TN hoặc FP.

Trang `/reports` hiển thị phần trăm, tử/mẫu số và ma trận riêng cho mỗi model/mode/repeat. Accuracy không thay thế Recall/F1/Coverage, đặc biệt khi số ca bình thường áp đảo. Với báo cáo đang chạy hoặc thất bại, số liệu chỉ tính trên các hàng đã lưu; không so sánh hai model nếu tập ca chưa đồng nhất hoặc chưa hoàn tất.

mAP chưa áp dụng: đầu ra không có điểm tin cậy để xếp hạng tính Average Precision; hệ thống không có tác vụ phát hiện hộp vật thể. MAE/MSE/RMSE chưa áp dụng vì không dự đoán đại lượng số. Không biến nhãn thành số để tạo các chỉ số hồi quy giả. Các chỉ số không áp dụng được giải thích trên UI, không xuất điểm 0.

API đọc báo cáo và export JSONL/CSV tính lại chỉ số từ các hàng kết quả đã lưu, nên báo cáo cũ cũng có Accuracy và ma trận mà không phải chạy model lại hoặc sửa bằng chứng trong database. CSV giữ tỷ số dạng JSON (numerator, denominator, value); API/JSONL giữ cùng cấu trúc. `metrics_version=2`, `positive_label=ALERT` xác định quy ước chấm. Chỉ dùng ca thuộc tập evaluation; warmup/development không đưa vào điểm chính.

Rubric account-session-v1: đọc reason và XML mà model viện dẫn, đối chiếu expected_accounts/expected_sessions và quan hệ trong ca. incorrect=true nếu lý do gán một hoạt động/phiên cho sai tài khoản, gộp hai phiên độc lập hoặc khẳng định quan hệ không được bằng chứng hỗ trợ. incorrect=false khi không có các lỗi đó; đây không thay thế chấm nhãn ALERT. Ghi người chấm, diễn giải và refs đã kiểm tra. Chưa chấm giữ null, không coi là đúng. Các lần sửa lưu review_history.

Chấm qua POST /evaluations/{evaluation_id}/reviews với token theo api.md, body:

```json
{"case_id":"THAY_ID","model":"qwen2.5:3b-instruct-q4_K_M","mode":"grouped","repeat":1,"annotator":"Thang","incorrect":false,"rationale":"THAY_DOI_CHIEU_CU_THE","evidence_refs":["THAY_REF"]}
```

Tải JSONL đầy đủ để truy nguồn, warmup, mọi attempt, metrics và timing; comparison.csv tách model/mode/repeat và giữ tỷ số tử/mẫu. Khi chưa đủ dữ liệu/chấm, không đề xuất model tốt nhất. Đề xuất cuối cùng phải dựa bỏ sót, cảnh báo nhầm, coverage và tài nguyên thực tế của tập đã khóa.

## 5. Kiểm thử tổng hợp

```powershell
.\.venv\Scripts\python.exe tests/run_evaluation_fixture.py
```

Lệnh tạo thư mục mới dưới data/evaluation-mock, in evaluation_id/data_root. Có 1 warmup, 1 development, 2 evaluation; báo thiếu 9 development và 38 evaluation cùng nhóm còn thiếu. Hai model giả lập, hai mode, ba repeat cho 24 hàng chấm và 2 warmup. Output được đánh dấu synthetic, không có giá trị so sánh SLM. results.jsonl/comparison.csv/verification.json nằm trong thư mục vừa tạo. Muốn xem UI mẫu, dùng một config riêng có data_root trỏ store vừa in; không chuyển các hàng mẫu sang dataset thật.

## Prompt theo model

Cấu hình `prompt_version` chọn prompt Qwen; `llama_prompt_version` chọn prompt Llama. Các giá trị được phép là `v1` và `v4`; mặc định đều `v1` để tái lập protocol cũ. Payload và kết quả lưu phiên bản/hash prompt; runner khóa riêng hash của hai prompt. Hai model nhận cùng dữ liệu nhưng nếu chọn prompt khác nhau, phép đo là so sánh hai cấu hình hệ thống, không còn cô lập riêng ảnh hưởng của model. Không gộp vào các lượt dùng prompt giống nhau.
