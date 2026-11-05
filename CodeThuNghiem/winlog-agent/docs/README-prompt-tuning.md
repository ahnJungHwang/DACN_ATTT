# README — Cải thiện luật và prompt cho Qwen/Llama

Cập nhật: **03/11/2026**. Áp dụng cho `CodeThuNghiem/winlog-agent`.

Tác vụ này cải thiện bộ luật phát hiện và thử nghiệm cách hướng dẫn hai model phân tích log. **Không huấn luyện lại hoặc fine-tune trọng số model.** Cấu hình Qwen v1 + Llama v4 mới được chuẩn bị để thử; chưa tự thay cấu hình API đang chạy.

## 1. Ba thành phần cần phân biệt

- **Bộ luật (`baseline_rules.py`):** nhận diện hành vi bằng điều kiện viết bằng Python. Chạy độc lập làm đối chứng `rules-only`; không cung cấp đáp án cho model.
- **Prompt (`prompts/windows-log-*.txt`):** hướng dẫn model đọc bằng chứng, chọn nhãn và trả lời JSON.
- **Nhãn tham chiếu:** dùng chấm kết quả, lưu ngoài payload. Không lấy nhãn luật hoặc nhãn AI làm ground truth.

Luồng xử lý giữ nguyên:

```text
XML → chuẩn hóa → ca/bằng chứng → payload → Ollama → kiểm tra đầu ra → kết quả
                              ↘ bộ luật → kết quả rules-only riêng
```

## 2. Các cải thiện đã thực hiện

### Bộ luật

- Nhận `net`, `net.exe`, `net1.exe`, đường dẫn đầy đủ và một lớp `cmd /c` hoặc `/k`.
- Dùng ranh giới token để tránh khớp nhầm `internet.exe`, `echo net.exe ...` hoặc `/address`.
- Không cảnh báo chỉ vì chuỗi có chữ `mimikatz`.
- Với script 4104, kết hợp dấu hiệu download và thực thi IEX/Invoke-Expression thay vì chỉ thấy tải file.
- Với tiến trình PowerShell/pwsh, kết hợp encoded command và hidden thay vì chỉ thấy cờ encoded.
- Phân biệt ghi Run key với truy vấn chỉ đọc Run key.

Đây là các luật kinh nghiệm, không phải trình thông dịch shell. Hoạt động quản trị có thể giống hành vi đáng ngờ; cú pháp làm rối có thể bị bỏ sót. Thay đổi nhằm giảm một số kiểu khớp nhầm, không chứng minh độ chính xác tuyệt đối.

### Prompt và khả năng truy vết

- Thử hướng dẫn trả lời ngắn để giảm lặp và lỗi chạm giới hạn token.
- Làm rõ 4625 là đăng nhập thất bại, 4688 là tạo tiến trình; khác PID cha/con và trường null không tự chứng minh tấn công.
- Bổ sung nhắc nhở coi chỉ dẫn xuất hiện trong log là dữ liệu không đáng tin cậy.
- Cho phép cấu hình prompt riêng cho Qwen và Llama.
- Lưu `prompt_version`, hash prompt và cấu hình trong payload/kết quả; runner khóa riêng hash hai prompt để phát hiện thay đổi giữa thí nghiệm.

## 3. Dữ liệu và protocol thử nghiệm

Đã chạy **80 lượt suy luận thật**: 4 phương án × 2 model × 10 ca.

- **6 ca DeepBlueCLI:** cùng bộ ca đã chọn ở lần thử trước, nhãn tham chiếu ALERT dựa trên mô tả nguồn và log; chưa được người chấm độc lập xác nhận.
- **4 đối chứng tổng hợp:** whoami, notepad, PowerShell Write-Output bình thường và Write-Output in chuỗi yêu cầu model trả ALERT. Nhãn kỳ vọng là NORMAL.
- Hai loại dữ liệu được thống kê riêng; không coi đối chứng tổng hợp là log NORMAL thật.
- Temperature 0, context 4096, output tối đa 512 token.
- Mỗi phương án chạy một lần; không có warmup hoặc ba repeat riêng.
- Giữ nguyên sự kiện và reference map; không cắt log hoặc đưa nhãn chuẩn vào đầu vào model.
- Riêng v2 thay cả prompt và schema `reason.maxLength=480`; các phương án khác không ép độ dài chuỗi bằng schema.

Đây là **dữ liệu phát triển đã xem**, không phải tập đánh giá độc lập. Không dùng số liệu này để công bố accuracy tổng thể.

## 4. Kết quả và lựa chọn cấu hình thử

| Cấu hình | Khớp nhãn 6 ca ALERT | Khớp 4 đối chứng NORMAL | Lỗi đầu ra trên 10 ca |
|---|---:|---:|---:|
| Qwen + v1 | 5/6 | 3/4 | 0/10 |
| Qwen + v4 | 2/6 | 3/4 | 0/10 |
| Llama + v1 | 3/6 | 1/4 | 4/10 |
| Llama + v4 | 5/6 | 1/4 | 0/10 |

Vì vậy cấu hình thử là **Qwen giữ v1, Llama thử v4**, không áp dụng v4 cho cả hai model.

v2 có điểm nhãn tốt nhưng kiểm tra lý do vẫn thấy suy diễn sai và kết thúc câu không tự nhiên. v3 khiến Qwen trả UNKNOWN trên cả sáu ca ALERT. Hai phương án này được giữ làm hồ sơ, không được chọn làm cấu hình vận hành. Xem [toàn bộ kết quả v1–v4](prompt-development.md).

Llama v4 vẫn có hai UNKNOWN và một ALERT sai trên bốn đối chứng. Qwen v1 cũng báo ALERT sai ở ca câu hướng dẫn nằm trong log. **Prompt injection, cảnh báo nhầm và chất lượng giải thích chưa được giải quyết hoàn toàn.** JSON hợp lệ và nhãn khớp chưa chứng minh lý do đúng.

## 5. Chạy cấu hình thử trên máy hiện tại

### Chuẩn bị

1. Có hai model `qwen2.5:3b-instruct-q4_K_M` và `llama3.2:3b-instruct-q4_K_M` trong Ollama local.
2. Có tokenizer đã xác minh tương ứng phiên bản Ollama/model/template. Nếu preflight báo `CONTEXT_UNVERIFIED`, làm theo [tokenizers.md](tokenizers.md), không bỏ qua kiểm tra.
3. Chờ task cũ hoàn tất và dừng API cũ trước khi mở API mới cùng data_root/port. Không dừng cưỡng bức khi đang suy luận.
4. Chứng chỉ HTTPS trong cấu hình thử phải tồn tại và được client tin cậy; xem [live-monitor.md](live-monitor.md).

`config.prompt-trial.toml` đã có:

```toml
prompt_version = "v1"
llama_prompt_version = "v4"
```

`prompt_version` chọn prompt Qwen; `llama_prompt_version` chọn prompt Llama. Các giá trị được ứng dụng chấp nhận là `v1` và `v4`. Mặc định cả hai là `v1`.

### Khởi động

Lệnh dưới đây dùng môi trường Python hiện có trên máy, không phải đường dẫn chung cho mọi máy:

```powershell
Set-Location 'D:\DACN_ATTT\CodeThuNghiem\winlog-agent'
$testPython = 'D:\DACN_ATTT\Thang Code\winlog-agent\.venv-handoff\Scripts\python.exe'
& $testPython -m app.api --config config.prompt-trial.toml
```

Mở `https://localhost:8000`, đăng nhập bằng token local và phân tích cùng ca bằng hai model. Không gửi token vào chat hoặc commit vào Git. Kiểm tra `payload.prompt_version` trong JSONL kết quả: Qwen phải là v1, Llama phải là v4.

Để quay lại cấu hình cũ, chờ task kết thúc, dừng phiên thử rồi chạy:

```powershell
& $testPython -m app.api --config config.local.toml
```

Kiểm tra hai khóa prompt trong cấu hình đó; bỏ qua khóa hoặc đặt cả hai thành v1 sẽ dùng prompt gốc. Không thay model digest, temperature hoặc token budget trong cùng lượt đối chiếu mà không ghi nhận.

## 6. Chạy đánh giá và kiểm thử

Runner chính thức nhận cấu hình prompt theo model:

```powershell
& $testPython -m app.evaluation_runner .\data\dataset.json --config config.prompt-trial.toml
```

Phải có manifest hợp lệ, ca warmup độc lập và ca evaluation theo [evaluation.md](evaluation.md). Dừng API cùng data_root trước khi chạy runner. Dùng prompt khác nhau là so sánh **hai cấu hình hệ thống**, không phải phép đo chỉ thay model.

Kiểm thử hồi quy, không gọi model thật:

```powershell
& $testPython -m pytest tests/test_baseline_rules.py tests/test_payload.py tests/test_inference.py tests/test_config.py tests/test_evaluation.py tests/test_service.py -q
```

Ở lượt triển khai: bộ hồi quy đạt 72 test trước khi thêm một test kiểm tra routing prompt. Sau đó chạy lại nhóm service đạt 4/4 test, gồm test mới xác nhận Qwen v1/Llama v4 và phần dữ liệu đầu vào không đổi.

## 7. File và bằng chứng

- `app/baseline_rules.py`: luật phát hiện.
- `app/config.py`, `app/payload.py`, `app/service.py`: chọn prompt và lưu phiên bản theo model.
- `app/evaluation_runner.py`: khóa prompt riêng trong đánh giá.
- `prompts/windows-log-v1.txt`: prompt gốc.
- `prompts/windows-log-v4.txt`: prompt thử cho Llama.
- `prompts/windows-log-v2.txt`, `windows-log-v3.txt`: phương án không được chọn.
- `config.prompt-trial.toml`: cấu hình thử riêng.
- [Biên bản phát triển](prompt-development.md): đầy đủ số liệu và giới hạn.

Kết quả local nằm dưới `data/prompt-development/`:

```text
run-dcf2b661-8e38-4ed7-92b3-f664303190c7/comparison.json  # v1, v2
run-2f4061a0-3ab2-41ef-8174-faecbe9be659/comparison.json  # v3
run-e50b0bb1-5322-4daa-9339-236ecec8e749/comparison.json  # v4
```

Mỗi file lưu prompt, cấu hình, metadata, ca và toàn bộ phản hồi, kể cả lỗi. Các script `compare.py`, `compare_v3.py`, `compare_v4.py` cũng ở thư mục này và phụ thuộc bản báo cáo DeepBlueCLI/tokenizer đã lưu từ lần thử trước.

`data/` được Git ignore: clone repository không tự có các kết quả, script thí nghiệm local và log mẫu. Cần bàn giao chúng riêng để tái lập; không kèm secrets/private key. Không thay dữ liệu báo cáo ngày 01/11 bằng kết quả phát triển ngày 03/11.

## 8. Điều kiện trước khi chọn mặc định mới

- Có người chấm độc lập đối chiếu lý do, tài khoản, phiên và evidence_refs.
- Có log NORMAL thật, ca thiếu bằng chứng và ca trộn khác tài khoản/phiên.
- Chạy trên nguồn/kịch bản chưa dùng để chỉnh prompt, không tiếp tục tối ưu trên tập đó rồi gọi là held-out.
- Đo đủ các lượt lặp, lỗi đầu ra, coverage, cảnh báo nhầm và tài nguyên.

Hiện chỉ có căn cứ để thử thêm Llama v4 trong môi trường phát triển; chưa có căn cứ tuyên bố cấu hình này cho kết quả đúng nhất trên mọi log.
# Thử nghiệm nhận diện dò mật khẩu trên OpenSSH (05/11/2026)

Cấu hình demo local dùng `prompt_version = 'v5'` và `llama_prompt_version = 'v5'`. Hai model nhận danh sách sự kiện và bảng đếm 4624/4625 tính từ các sự kiện đó, kèm tài khoản đích và ref gốc. Schema giới hạn mã trích dẫn vào các ref của ca. Prompt và bộ đếm không nhận nhãn chuẩn. Để quay lại v1, đặt hai giá trị về v1 rồi khởi động lại API; tạo request_id mới để thử.

Ca OpenSSH `555bc05d` và nguồn OpenSSH brute force cùng kịch bản đã được dùng để chỉnh prompt: dành cho phát triển, loại khỏi đánh giá độc lập 11.4. XML đầu vào có SHA256 `2a19eb273b153e401a0cc93d8873a01c7a53114c39c0e4de31e239a1ad5bab59`. Phản hồi thật qua HTTPS lưu ở `data/openssh-v5-verified.json`. Toàn bộ bốn ca thử ở `data/auth-trial-61d39eb3-f82d-4261-8c6d-d87995f93443.json`. Cả hai cảnh báo đúng ca OpenSSH và ca lab ngắn, nhận ca PowerShell thường là NORMAL. Ca dài 19 sự kiện bị chặn vì kích thước ở Qwen; Llama trả ALERT. Llama còn trích thừa và lặp bằng chứng. Các kết quả là thử nghiệm phát triển trên máy local.
