# Test hai model với log mẫu DeepBlueCLI

Biên bản thực nghiệm ngày **01/11/2026**, thực hiện trong `CodeThuNghiem/winlog-agent`.

**Phạm vi:** 6 ca trích từ log công khai, cùng nhãn tham chiếu ALERT, chạy thật qua hai model Ollama, mỗi model một lượt trên mỗi ca. Tổng cộng **12 kết quả**. Đây là thử nghiệm thăm dò trên dữ liệu bên ngoài, chưa phải nghiệm thu bộ dữ liệu chính thức của đồ án.

## 1. Mục tiêu

- Kiểm tra khả năng phát hiện các kịch bản tấn công từ log có sẵn.
- So sánh Accuracy, Precision, Recall, F1-Score, Coverage và thời gian xử lý.
- Giữ lại UNKNOWN, lỗi kỹ thuật và đầu ra gốc để kết quả không bị thiên lệch do loại bỏ lượt thất bại.
- Lưu nguồn dữ liệu, hash, Record ID, case ID và result ID để truy lại bằng chứng.

Không dùng nhãn do model dự đoán làm nhãn chuẩn. Nhãn tham chiếu ở đợt này do trợ lý đối chiếu mô tả kịch bản DeepBlueCLI và các sự kiện được chọn; **chưa được người chấm độc lập xác nhận**.

## 2. Nguồn dữ liệu và định dạng

- Repository: [sans-blue-team/DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI).
- Phiên bản đã tải: `2eecc65698e8666408ece67525577c895676d579`.
- [Thư mục EVTX tại phiên bản đó](https://github.com/sans-blue-team/DeepBlueCLI/tree/2eecc65698e8666408ece67525577c895676d579/evtx).
- Đã tải 25 file EVTX, tổng 29.986.816 byte, khoảng 28,6 MiB.
- File gốc và tài liệu nguồn nằm dưới `data/external/deepbluecli/2eecc65698e8666408ece67525577c895676d579/`.
- `download-manifest.json` lưu commit, thời điểm tải, URL nguồn và SHA256 từng file. Script đánh giá kiểm lại hash của sáu file được sử dụng.

Project hiện nhận XML sự kiện gốc, nên dùng `Get-WinEvent -Path ... -Oldest` và `ToXml()` để tạo bản XML riêng. Không chạy nội dung lệnh hay PowerShell xuất hiện trong log.

Chỉ giữ các sự kiện được bộ nhập hỗ trợ:

- Security: **4624**, **4625**, **4688**.
- Microsoft-Windows-PowerShell/Operational: **4104**.

Số lượng sự kiện theo file và theo channel/Event ID được lưu trong `data/deepblue-evaluation/inventory.json`. Một số mẫu chỉ có System, Application, Sysmon hoặc ID ngoài phạm vi nên không dùng trực tiếp cho model hiện tại. Ví dụ, không suy ra mọi file có tên “password” đều chứa 4625 phù hợp.

Hai bản XML chuyển đổi của `Powershell-Invoke-Obfuscation-encoding-menu` và `Powershell-Invoke-Obfuscation-many` từng không đọc được và sau đó không còn hiện diện. Không xác định nguyên nhân trong đợt này, không vượt qua cơ chế bảo vệ và không dùng hai bản đó để tính điểm.

## 3. Sáu ca được cố định trước khi chạy

| Ca | File EVTX | EventRecordID được chọn | Số sự kiện | Cơ sở nhãn ALERT |
|---|---|---|---:|---|
| SMB password guessing | `smb-password-guessing-security.evtx` | 2456–2460 | 5 | Năm lần thất bại liên tiếp của Administrator trong mẫu dò mật khẩu được nguồn mô tả. |
| Metasploit native PsExec | `metasploit-psexec-native-target-security.evtx` | 13678–13680 | 3 | Toàn bộ sự kiện được hỗ trợ của mẫu native target: executable, rundll32 và lệnh named pipe. |
| Metasploit PowerShell | `metasploit-psexec-powershell-target-security.evtx` | 13278 | 1 | Lệnh launcher đầu tiên chứa thực thi ẩn và payload Base64 nén trong kịch bản PowerShell target. |
| PowerSploit launcher | `powersploit-security.evtx` | 13488 | 1 | Lệnh PowerShell mã hóa đầu tiên trong mẫu PowerSploit. |
| PSAttack execution | `psattack-security.evtx` | 13348 | 1 | Thực thi PSAttack.exe trong mẫu tấn công được nguồn mô tả; tên file đơn lẻ không đủ chứng minh hành vi độc hại ngoài ngữ cảnh này. |
| Obfuscated PowerShell | `Powershell-Invoke-Obfuscation-string-menu.evtx` | 710848, 714840, 719151, 719154 | 4 | Bốn script block làm rối, chứa nội dung tải/chạy Invoke-Mimikatz để dump credentials. |

Tổng cộng **15 sự kiện trong 6 ca**, không phải toàn bộ sự kiện của 25 file. Mỗi file nguồn đóng góp một ca trong đợt thử này. Không cắt nội dung command line/script của sự kiện đã chọn để vừa context.

Các đoạn log được chọn thủ công theo tiêu chí ghi ở trên trước khi nhận kết quả model. Các nhóm do `correlate()` tạo chỉ giữ quan hệ được bộ ghép chứng minh; việc nhiều sự kiện cùng thuộc một ca không mặc nhiên khẳng định chúng cùng phiên. Ca có mode **`excerpt`**, không phải kết quả chạy cả hai mode `single` và `grouped` của runner chính thức.

Nhãn, tên file nguồn và diễn giải gán nhãn được lưu ngoài payload. `build_payload()` chỉ gửi các trường sự kiện và nhóm được phép cho model.

## 4. Môi trường và cấu hình

- Windows, Python 3.11; Ollama **0.40.13**, endpoint local `http://127.0.0.1:11434`.
- Qwen: `qwen2.5:3b-instruct-q4_K_M`.
- Llama: `llama3.2:3b-instruct-q4_K_M`.
- `temperature=0`, `num_ctx=4096`, `num_predict=512`, `context_reserve=256`.
- Prompt/schema theo mã nguồn project; mỗi kết quả lưu payload, metadata và cấu hình thực tế.
- Một lượt/model/ca; chạy tuần tự Qwen hết 6 ca rồi đến Llama.
- Không có warmup riêng cho đợt DeepBlueCLI; không chạy ba repeat.
- Kiểm tra tokenizer bằng bản xác minh từ lượt pilot trước đó. Bản này đã đối chiếu 10/10 mẫu đếm token với Ollama; `ContextGuard` tiếp tục kiểm metadata và fingerprint khi chạy.
- Model đang được tiến trình khác nạp sẽ khiến script từ chối bắt đầu, tránh đụng workload khác.

Digest model đã ghi nhận:

```text
Qwen: 357c53fb659c5076de1d65ccb0b397446227b71a42be9d1603d46168015c9e4b
Llama: a80c4f17acd55265feec403c7aef86be0c25983ab279d83f3bcd3abbcb5b8b72
```

Giới hạn 512 token được giữ nguyên cho cả hai model. Không tăng giới hạn riêng cho model lỗi rồi gộp kết quả vào bảng này.

## 5. Kết quả thực tế

Run: `run-ffe7bcf3-d39e-4636-92fb-13b0e3a898f6`.

| Chỉ số | Qwen 2.5 3B | Llama 3.2 3B |
|---|---:|---:|
| Số ca | 6 | 6 |
| TP — phát hiện đúng ALERT | 5 | 3 |
| FN — ALERT không được phát hiện, gồm UNKNOWN | 1 | 3 |
| Dự đoán NORMAL | 0 | 0 |
| Dự đoán UNKNOWN | 1 | 3 |
| Accuracy | 83,33% | 50,00% |
| Precision trên tập chỉ có ALERT | 100,00% | 100,00% |
| Recall | 83,33% | 50,00% |
| F1-Score | 90,91% | 66,67% |
| Coverage | 83,33% | 50,00% |
| Ca có lỗi kỹ thuật | 0/6 | 3/6 |
| Đầu ra hợp lệ / response | 6/6 | 3/6 |
| Thời gian trung bình/ca | 2,83 giây | 7,51 giây |
| Trung vị thời gian của 6 ca | 2,02 giây | 7,80 giây |
| False-positive rate | Chưa xác định | Chưa xác định |

FP và TN đều bằng 0 do tập thử **không có ca NORMAL**. Precision 100% chỉ là kết quả công thức trên tập chọn này; không chứng minh model ít cảnh báo nhầm. Trung vị thời gian ở đây là trung vị của sáu ca khác nhau, không phải trung vị ba lần chạy cùng một ca.

| Ca | Qwen | Thời gian Qwen | Llama | Thời gian Llama |
|---|---|---:|---|---:|
| SMB password guessing | ALERT | 7,34 s | ALERT | 7,65 s |
| Metasploit native PsExec | UNKNOWN, không lỗi kỹ thuật | 1,96 s | ALERT | 3,03 s |
| Metasploit PowerShell | ALERT | 1,83 s | UNKNOWN, đầu ra bị cắt | 14,01 s |
| PowerSploit launcher | ALERT | 1,44 s | UNKNOWN, đầu ra bị cắt | 8,02 s |
| PSAttack execution | ALERT | 2,07 s | ALERT | 4,41 s |
| Obfuscated PowerShell | ALERT | 2,33 s | UNKNOWN, đầu ra bị cắt | 7,95 s |

Ba ca lỗi của Llama có `done_reason=length`, `eval_count=512`, được hệ thống ghi `technical_error=INVALID_MODEL_OUTPUT`. Không sửa đầu ra bị cắt thành JSON hợp lệ để tính đúng. UNKNOWN của Qwen có `done_reason=stop`, không có lỗi kỹ thuật: đó là phản hồi không kết luận, khác với lỗi sinh đầu ra.

## 6. Cách tính điểm

Lớp dương là ALERT. Các công thức dùng số ca, không dùng số sự kiện:

```text
Accuracy  = (TP + TN) / tổng ca
Precision = TP / (TP + FP)
Recall    = TP / (TP + FN)
F1        = 2TP / (2TP + FP + FN)
Coverage  = số ca có dự đoán ALERT hoặc NORMAL / tổng ca
```

UNKNOWN trên ca ALERT tính là FN và vẫn nằm trong mẫu số Accuracy. Mẫu số 0 giữ `null`/chưa xác định. Không loại lỗi kỹ thuật ra khỏi bảng điểm.

Đầu ra JSON hợp lệ chỉ chứng minh đáp ứng schema và quy tắc tham chiếu, không chứng minh giải thích đúng tài khoản/phiên. Chưa có chấm thủ công account/session cho đợt này, nên `account_session_error` chưa xác định.

mAP chưa áp dụng vì không có đầu ra xếp hạng theo điểm tin cậy hoặc tác vụ phát hiện vật thể. MAE/MSE/RMSE chưa áp dụng vì đầu ra là nhãn phân loại, không phải đại lượng số.

## 7. Báo cáo, biểu đồ và bằng chứng

Thư mục kết quả tương đối từ project:

```text
data/deepblue-evaluation/run-ffe7bcf3-d39e-4636-92fb-13b0e3a898f6/
```

- [report.html](../data/deepblue-evaluation/run-ffe7bcf3-d39e-4636-92fb-13b0e3a898f6/report.html): báo cáo có bộ lọc model và phần mở rộng từng ca.
- [metrics.png](../data/deepblue-evaluation/run-ffe7bcf3-d39e-4636-92fb-13b0e3a898f6/metrics.png), `metrics.svg`: biểu đồ chỉ số và số lượng nhãn.
- [latency.png](../data/deepblue-evaluation/run-ffe7bcf3-d39e-4636-92fb-13b0e3a898f6/latency.png), `latency.svg`: thời gian theo ca.
- [metrics-flat.csv](../data/deepblue-evaluation/run-ffe7bcf3-d39e-4636-92fb-13b0e3a898f6/metrics-flat.csv): chỉ số dạng số, tỷ lệ trong khoảng 0–1.
- `results.csv`: các tỷ số có tử/mẫu số ở dạng JSON trong ô CSV.
- `results.jsonl`: kết quả, metadata và các attempt để truy bằng chứng.
- `report.json`: tài liệu đầy đủ gồm manifest, cấu hình, từng phản hồi và điểm tổng hợp.
- `summary.json`: điểm và thời gian tổng hợp cho hai model.
- `dataset-locked.json`: sáu ca, lý do gán nhãn, Record ID, refs, URL nguồn và hash; được ghi trước khi suy luận.
- `store/`: SQLite, raw XML, kết quả và tokenizer của riêng lượt chạy.

Các file trong `data/` được Git ignore. README này được theo dõi trong Git; **clone repository không tự có các log, script thử nghiệm local hoặc báo cáo trên**. Khi bàn giao cần cung cấp bộ dữ liệu/bằng chứng riêng và kiểm tra hash; không đưa token hay thư mục secrets vào gói chia sẻ.

## 8. Tái chạy trên máy hiện tại

Các lệnh dưới đây dành cho môi trường local đã dùng trong đợt thử. Không phải bộ cài tự chứa cho máy mới. Chuẩn bị Python/dependency và tokenizer trên máy khác theo [setup.md](setup.md) và [tokenizers.md](tokenizers.md).

### 8.1. Chọn thư mục làm việc và Python

```powershell
Set-Location 'D:\DACN_ATTT\CodeThuNghiem\winlog-agent'
$testPython = 'D:\DACN_ATTT\Thang Code\winlog-agent\.venv-handoff\Scripts\python.exe'
Test-Path $testPython
```

`evaluate.py` nằm trong `data/deepblue-evaluation/`. Script dùng dữ liệu DeepBlueCLI tại commit nêu trên và sao chép tokenizer từ:

```text
data/pilot-20261101/689977f6-c601-4b1d-af80-02b9a0302003/store/tokenizers/
```

Nếu thiếu bộ script local hoặc tokenizer đó, cần khôi phục từ bộ bàn giao hoặc điều chỉnh đường dẫn sang tokenizer đã xác minh trước khi chạy. Không sửa bản ghi xác minh để bỏ qua kiểm tra.

### 8.2. Kiểm tra nguồn và Ollama

```powershell
Test-Path '.\data\external\deepbluecli\2eecc65698e8666408ece67525577c895676d579\download-manifest.json'
ollama list
ollama ps
```

Cả hai model phải có sẵn. Nếu model đang được tiến trình khác sử dụng, chờ workload đó kết thúc; script không tự dừng workload bên ngoài.

Script tải local `data/external/deepbluecli/download.py` lấy nhánh `master` ở thời điểm tải. **Không dùng tải lại master để giả định tái lập đúng phiên bản này**: phải đối chiếu commit và hash. Nếu commit đổi, đó là một nguồn dữ liệu khác cần ghi nhận.

### 8.3. Chuyển EVTX sang XML nếu chưa có

```powershell
& '.\data\deepblue-evaluation\convert.ps1'
```

Chạy bằng PowerShell trên Windows; nếu hệ điều hành từ chối đọc EVTX do quyền, dùng cửa sổ có quyền phù hợp. Script đọc các file lưu trữ, tạo XML và inventory; không thu log mới từ máy. Nếu XML đã có và đã xác minh thì không cần chuyển lại. Không tắt cơ chế bảo vệ để ép đọc file bị chặn.

### 8.4. Chạy hai model

```powershell
& $testPython -u '.\data\deepblue-evaluation\evaluate.py'
```

Script tạo thư mục `run-<UUID>` mới và in đường dẫn `OUTPUT`. Ca được chọn từ hằng `SELECTIONS` theo Record ID. Cả hai model dùng cùng sáu ca. Kết quả được lưu sau mỗi lượt; khi thành công in `COMPLETE`. Giữ nguyên cả lượt failed để điều tra, không chỉ giữ các lượt đẹp.

Không tự bỏ ca bị quá context, UNKNOWN hoặc lỗi khỏi mẫu số. Khi đổi ca, prompt, model, tokenizer hoặc cấu hình token, phải coi đó là một thí nghiệm mới và ghi rõ khác biệt.

### 8.5. Xuất biểu đồ và báo cáo

Thư viện vẽ được cài riêng vào `data/deepblue-evaluation/chart-libs`, không thay requirements của ứng dụng. Đợt này dùng Matplotlib 3.11.2. Nếu chưa có:

```powershell
& $testPython -m pip install --target '.\data\deepblue-evaluation\chart-libs' 'matplotlib==3.11.2'
```

Đặt `$testRun` thành đường dẫn `OUTPUT` của lượt muốn xuất. Ví dụ xuất lại báo cáo đã hoàn thành, không gọi model lại:

```powershell
$testRun = '.\data\deepblue-evaluation\run-ffe7bcf3-d39e-4636-92fb-13b0e3a898f6'
& $testPython '.\data\deepblue-evaluation\render_report.py' $testRun
Start-Process (Join-Path $testRun 'report.html')
```

Renderer hiện được viết cho chính protocol sáu ca/hai model này và kiểm tra đủ 12 hàng. Nếu thay quy mô, phải cập nhật kiểm tra và chú thích biểu đồ. Ngày báo cáo và nội dung chú thích trong renderer hiện cố định cho đợt 01/11/2026; cần cập nhật khi dùng cho đợt khác.

## 9. Giới hạn và hướng đánh giá tiếp

1. Chỉ có 6 ca ALERT; chưa có cơ sở đo false-positive rate hoặc accuracy tổng thể trên sử dụng thực tế.
2. Các ca là đoạn chọn từ một repository và có thể dùng chung môi trường/phương pháp tạo log. Không coi sáu ca là sáu môi trường hoàn toàn độc lập.
3. Nhãn dựa vào kịch bản nguồn; một số thông tin ngoài log giúp người gán nhãn nhưng không xuất hiện trong payload. UNKNOWN có thể phản ánh việc bằng chứng quan sát được chưa đủ, không nhất thiết là suy luận vô lý.
4. Mỗi ca chạy một lần. Thời gian bao gồm nạp model khi cần và cả lượt lỗi; không phải benchmark đã warmup hay đo ổn định ba lần.
5. Chưa đo tài nguyên RAM/VRAM cho đợt DeepBlueCLI này và chưa chấm đúng/sai phần giải thích theo tài khoản/phiên.
6. Chưa thay thế các task dữ liệu có nhãn, đánh giá hai mode/ba repeat hoặc lựa chọn model mặc định trong [quy trình đánh giá chính thức](evaluation.md).

Kết quả chỉ cho thấy: **với sáu đoạn log và cấu hình đang dùng, Qwen đưa ra nhiều nhãn ALERT hợp lệ hơn và thời gian trung bình thấp hơn; Llama gặp ba lần cắt đầu ra**. Để kết luận rộng hơn cần thêm ca NORMAL đã đối chiếu, người chấm độc lập, chia tập theo nguồn/kịch bản và thực hiện các lần lặp theo protocol chính thức.
