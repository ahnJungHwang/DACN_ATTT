# Tokenizer offline và smoke test

Không cần tài khoản Hugging Face. Dữ liệu tokenizer được trích từ GGUF của hai model Ollama đã cài; không tải trọng số, không chạy thêm server, không nạp tensor để đếm token. Bộ đọc hiện chỉ nhận GPT-2 byte BPE với pre-tokenizer qwen2 hoặc llama-bpe. Quy tắc tách từ/gộp dựa trên [llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/src/llama-vocab.cpp); template sử dụng bản Ollama thực tế, không lấy chat template GGUF thay thế.

Chuẩn bị từ thư mục winlog-agent, khi Ollama đang chạy và không có model do ứng dụng khác nạp:

```powershell
.\.venv\Scripts\python.exe -m app.prepare_tokenizers
.\.venv\Scripts\python.exe -m app.verify_tokenizers
.\.venv\Scripts\python.exe -m app.smoke_models
```

Nếu model nằm nơi khác, truyền --models-root cho prepare_tokenizers. File tạo trong data/tokenizers ngoài Git: qwen2.5.json, llama3.2.json, provenance.json và verification.json. Provenance ghi hash blob GGUF đã đối chiếu, manifest local, tokenizer, model digest, template và Ollama version. Verification lưu messages tổng hợp, response thực tế, số token dự kiến/thực tế và hash mã bộ đếm + phiên bản regex. Các lần thử có thể tải model tuần tự vào RAM/GPU, rồi xác nhận unload; không dừng model của ứng dụng ngoài.

ContextGuard chỉ chấp nhận artifact đã kiểm chứng đúng model digest/template/Ollama version/tokenizer/mã xử lý. Thiếu hoặc khác trả CONTEXT_UNVERIFIED. Mặc định chừa 512 token đầu ra + 256 dự phòng trong 4096; input tối đa 3328. Vượt trả INPUT_TOO_LARGE, không gọi suy luận và không cắt log. Sửa bộ đếm hoặc đổi phiên bản regex phải kiểm chứng lại.

## Bằng chứng ngày 2026-10-25

10/10 phép đếm khớp prompt_eval_count Ollama 0.40.9 sau sửa quy tắc ignore_merges riêng của Llama. Qwen: 180, 203, 792, 192, 3324 token. Llama: 191, 208, 702, 205, 3321 token. Các mẫu gồm lời chào, tiếng Việt/Trung/emoji, dòng lệnh Windows, dấu phân cách đặc biệt và văn bản gần giới hạn. Đây là phạm vi kiểm chứng thực tế, không phải chứng minh bằng thử nghiệm cho mọi chuỗi Unicode có thể có.

Smoke test dùng cùng hai payload tổng hợp cho cả hai model, gồm Get-Date thiếu ngữ cảnh phiên và script lặp gần giới hạn. Cả bốn response hợp lệ theo schema, không có technical_error: Qwen UNKNOWN/UNKNOWN, Llama NORMAL/UNKNOWN. Kết quả khác nhau không đủ để chọn model tốt nhất hoặc suy ra độ chính xác. Toàn bộ response/đầu vào/options/thời gian lưu data/model-smoke.json. UNKNOWN không lỗi kỹ thuật nghĩa model chưa đủ bằng chứng; UNKNOWN với technical_error nghĩa xử lý thất bại.

Kết quả JSON sai, ref không tồn tại, ALERT không bằng chứng hoặc response cắt ngắn được giữ raw_output và chuyển UNKNOWN/INVALID_MODEL_OUTPUT. Mất kết nối có thể để Ollama còn xử lý, nên runtime chuyển degraded và chặn model tiếp theo. Không tự retry vô hạn hoặc nạp model khác để sửa đầu ra.
