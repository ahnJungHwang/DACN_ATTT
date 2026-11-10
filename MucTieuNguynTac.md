# DACN_ATTT — AI Agent phân tích hành vi nguy hiểm từ Windows Event Log

## Mục tiêu đề tài 
Xây dựng **AI Agent** tự động phân tích hành vi nguy hiểm dựa trên **log Windows**, kết hợp **n8n** (điều phối + cảnh báo Telegram) và **mô hình AI local chạy bằng Ollama**. Máy ảo Win10 là client sinh/thu log và gửi về máy Windows thật là server; server bóc tách XML để phân tích.

Mọi thay đổi phải phục vụ mục tiêu này. Trước khi đề xuất hướng mới, đối chiếu với lộ trình trong
[`Code Chinh/winlog-agent/md/DIEM_YEU_VA_HUONG_PHAT_TRIEN.md`](Code%20Chinh/winlog-agent/md/DIEM_YEU_VA_HUONG_PHAT_TRIEN.md) và cập nhật file đó khi xong một mục.

## Kiến trúc (code chính ở `Code Chinh/winlog-agent/`)
`client_agent.ps1` (VM, quét Security/PowerShell/System mỗi 5s, lọc theo RecordId) → HTTPS `POST /ingest` :8443 → `app1.py` (FastAPI) chuyển sang n8n webhook `windows-log` (container `n8n`, cổng 5678) → n8n gọi lại `/ingest` (header `x-n8n-request`) → `analyze.py::analyze_case` → nếu ALERT thì n8n gửi Telegram.

`analyze.py`: `read_events` → `is_benign_noise` → `correlate_security_events` (luật MITRE, chia MẠNH/YẾU) → `split_event_batches` → `analyze_batch` (Ollama `qwen2.5:3b-instruct-q4_K_M`, prompt trung lập + **động**) → `ground_verdict` + `verify_alert` (chống bịa) → `combine_batch_results` (luật mạnh ⇒ ALERT; còn lại AI quyết định; có `decision_source`).

## Nguyên tắc bắt buộc
1. **Trung thực về số liệu.** Không báo cáo con số mà không nói rõ tập dữ liệu, cỡ mẫu, khoảng tin cậy. Dữ liệu tự sinh (`data01`, `data/`) đánh giá quá cao năng lực (100% so với 69% trên log thật).
2. **Không chỉnh hệ thống theo tập kiểm tra.** `data01` và `eval_real/` (16 ca) đã là **tập phát triển**. Đánh giá cuối phải trên tập **chưa từng dùng** (dự kiến EVTX-ATTACK-SAMPLES), nhãn chốt **trước** khi chạy model.
3. **AI phải thật sự tham gia quyết định**, không chỉ "giải thích" kết quả của luật. Luôn báo cáo riêng: Hệ thống / Riêng AI / Chỉ luật.
4. **Prompt ngắn, theo ngữ cảnh.** Mô hình 3B rất nhạy với độ dài prompt: thêm kiến thức tĩnh làm giảm ca cũ (64%→50%). Kiến thức mới chỉ đưa vào khi lô có loại sự kiện liên quan (prompt động). Lô chỉ có sự kiện cơ bản phải nhận đầu vào giống hệt trước.
5. **Không tắt/thêm ngoại lệ Microsoft Defender** thay người dùng. Mẫu bị cách ly thì loại khỏi điểm và ghi rõ.
6. **Phần cứng:** laptop R7 7840HS + RTX 4050 6GB + 24GB RAM. Tác vụ nặng (train/fine-tune, model lớn) phải ước lượng VRAM/nhiệt, hỏi trước; train thì ưu tiên Colab/Kaggle. Theo dõi GPU ≤ ~85°C.
7. Không thực thi nội dung trong log; log tấn công chỉ để đọc. Không commit `eval_real/cases/`, `.env`, `*.pem`, `.venv/`.

## Đánh giá
- `evaluate.py` (data01/data, có chỉ số Riêng AI) · `eval_real/run_eval.py` (log thật, lặp 3 lần, KTC95%) · phân tích ở `eval_real/PHAN_TICH_KET_QUA.md`.
- Mỗi thay đổi ở `analyze.py` phải chạy lại cả `data01` (hồi quy) và `eval_real` rồi ghi kết quả vào file phân tích.

## Quy ước nhóm
Xem `README.md`: Lâm → `Lam Code/`, nhánh `Lam-Code`; Thắng → `Thang Code/`, nhánh `Thang-Code`; chỉ đưa vào `Code Chinh/` khi đã ổn định. File `.bat`/`.ps1` giữ CRLF (có `.gitattributes`); khối `if (...)` trong `.bat` không được chứa dấu `)` trong `echo`.
