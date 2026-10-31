# Trạng thái tích hợp Ollama

Adapter chỉ chấp nhận http://127.0.0.1:11434 và hai tag đã định, tắt proxy môi trường/redirect, không tải model hoặc fallback cloud. Đọc /api/version, /api/tags và /api/show để ghi phiên bản/digest/template. Hợp đồng [Ollama API](https://docs.ollama.com/api/chat) hỗ trợ stream=false và format JSON schema; phần chạy suy luận đầy đủ vẫn đang triển khai.

Ngày 2026-10-25 đã khởi động dịch vụ Ollama có sẵn và kiểm tra metadata thực tế:

- Ollama 0.40.9.
- Qwen digest: 357c53fb659c5076de1d65ccb0b397446227b71a42be9d1603d46168015c9e4b.
- Llama digest: a80c4f17acd55265feec403c7aef86be0c25983ab279d83f3bcd3abbcb5b8b72.
- Metadata đầy đủ lưu local ở data/model-metadata.json, ngoài Git.

Prompt cố định trong prompts/windows-log-v1.txt. Payload chỉ lấy các trường bằng chứng cho phép, thay refs bằng E001... và nhóm bằng G001...; mapping về event_ref gốc nằm ngoài messages. Không gửi tên file, nhãn chuẩn, group_id có ý nghĩa hoặc kết quả model khác. Script trong log chỉ được serialize thành chuỗi, không chạy.

Đã xác minh tokenizer/template offline trên bộ mẫu tổng hợp khớp prompt_eval_count; xem [quy trình và bằng chứng](tokenizers.md). Template Llama có đoạn Cutting Knowledge Date riêng. Không dùng độ dài ký tự/4 làm bảo đảm 4096 token.

Nguồn Hugging Face trả HTTP 401 khi không xác thực. Đã dùng GGUF local và kiểm chứng riêng thuật toán/template theo lựa chọn tiếp tục của người dùng; không tải tokenizer từ nguồn cần đăng nhập.
