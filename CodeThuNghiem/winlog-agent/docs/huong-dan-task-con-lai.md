# Hướng dẫn 6 task còn lại (3.4, 11.1, 11.2, 11.4, 11.5, 11.6)

Các bước dưới đây là phần **người thực hiện phải tự làm**: thao tác trong VM, nhập mật khẩu, bật policy, ngắt mạng, gán nhãn và chấm điểm. Sau mỗi task, báo lại Claude (kèm đường dẫn thư mục/ID) để kiểm chứng, ghi bằng chứng và đánh dấu tasks.md. Không ghi mật khẩu, PIN hay token vào nhật ký hoặc chat.

Quy ước:
- **[VM]**: chạy trong VM Windows 10 (`D:\machine\win10`), Windows PowerShell 5.1 **Run as administrator**.
- **[Host]**: chạy trên máy thật, PowerShell mở tại `D:\DACN_ATTT\Thang Code\winlog-agent`.
- File cần chép vào VM đã có sẵn ở `data\to-vm\` (kéo-thả qua VMware Tools).

---

## Task 3.4 — Một lần thu log trên VM

### Bước 1 [VM] — Ghi môi trường

```powershell
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, LastBootUpTime
$PSVersionTable.PSVersion
hostname
whoami
Get-Date -Format o
Get-TimeZone
net accounts
```

Chép kết quả vào nhật ký (mẫu `data\to-vm\lab-journal-template.md`). Ghi lại `Lockout threshold`: số lần nhập sai ở bước 3 phải **nhỏ hơn** ngưỡng này.

Cần tài khoản lab riêng (ví dụ `lab_demo`). Nếu chưa có, tạo trong VM (bạn tự đặt mật khẩu khi được hỏi):

```powershell
$pw = Read-Host -AsSecureString 'Mat khau lab_demo'
New-LocalUser -Name 'lab_demo' -Password $pw -Description 'Tai khoan lab thu log'
```

### Bước 2 [VM] — Bật 4 nguồn sự kiện

Mở `gpedit.msc` → Computer Configuration:

1. Windows Settings → Security Settings → Advanced Audit Policy Configuration → System Audit Policies → **Logon/Logoff → Audit Logon** → tick Success + Failure.
2. Cùng cây → **Detailed Tracking → Audit Process Creation** → Success.
3. Administrative Templates → System → Audit Process Creation → **Include command line in process creation events** → Enabled.
4. Administrative Templates → Windows Components → Windows PowerShell → **Turn on PowerShell Script Block Logging** → Enabled.

Áp dụng và kiểm tra:

```powershell
gpupdate /force
auditpol /get /subcategory:"Logon","Process Creation"
Get-WinEvent -ListLog 'Microsoft-Windows-PowerShell/Operational' | Select-Object LogName, IsEnabled
```

`Logon` phải là `Success and Failure`, `Process Creation` là `Success`, `IsEnabled` là `True`. Sau đó **đóng PowerShell và mở cửa sổ admin mới**.

### Bước 3 [VM] — Chép script và làm kịch bản

Kéo thư mục `data\to-vm\LabTools` vào `C:\LabTools` trong VM. Trong cửa sổ admin mới (giữ cửa sổ này đến hết bước 4):

```powershell
$start = [DateTimeOffset]::Now.ToString('o'); $start
```

Mở **một cửa sổ PowerShell thường khác** và làm kịch bản, ghi giờ từng thao tác:

```powershell
# Lần 1..N: cố ý gõ SAI mật khẩu (N nhỏ hơn Lockout threshold, nên >= 5 lần trong 60 giây)
runas /user:$env:COMPUTERNAME\lab_demo "powershell.exe -NoProfile"
# Lần cuối: gõ ĐÚNG mật khẩu
runas /user:$env:COMPUTERNAME\lab_demo "powershell.exe -NoProfile"
```

Trong cửa sổ PowerShell mới mở bằng `lab_demo` (trong vòng 5 phút sau khi đăng nhập đúng):

```powershell
whoami
Get-Date
Get-Process | Select-Object -First 5
Start-Process notepad.exe
```

Đóng Notepad, rồi đóng cửa sổ `lab_demo`.

Kiểm tra trong Event Viewer: Security có 4625 (sai), 4624 (đúng), 4688 (whoami/notepad); PowerShell → Operational có 4104. Ghi RecordID của vài sự kiện vào nhật ký.

### Bước 4 [VM] — Xuất XML và manifest

Quay lại cửa sổ admin có `$start`:

```powershell
$end = [DateTimeOffset]::Now.ToString('o'); $end
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\LabTools\Export-WindowsLogs.ps1 -StartTime $start -EndTime $end -OutputRoot C:\Lab
$run = Get-ChildItem C:\Lab -Directory | Sort-Object LastWriteTime | Select-Object -Last 1
$run.FullName
Get-Content (Join-Path $run.FullName 'manifest.json')
Get-FileHash (Join-Path $run.FullName 'security.xml'), (Join-Path $run.FullName 'powershell.xml') -Algorithm SHA256
```

Ghi `run_id`, trạng thái từng nguồn, `counts_by_id` và hai hash vào nhật ký. Mã thoát 2 = partial: vẫn giữ nguyên, không xóa.

### Bước 5 [Host] — Chép về và kiểm tra

Kéo cả thư mục `C:\Lab\<timestamp>-<UUID>` từ VM vào `data\incoming\`. Đặt nhật ký đã điền cùng thư mục (tên `journal.md`). Rồi chạy:

```powershell
$dir = (Get-ChildItem .\data\incoming -Directory | Sort-Object LastWriteTime | Select-Object -Last 1).FullName
Get-FileHash "$dir\security.xml", "$dir\powershell.xml" -Algorithm SHA256
.\.venv\Scripts\python.exe -m app.verify_collection $dir
```

Hash phải giống bước 4. **Báo Claude đường dẫn thư mục** → Claude kiểm chứng và đóng 3.4.

---

## Task 11.1 — Toàn luồng trên lần thu VM thật

### Bước 1 [Host] — Khởi động dịch vụ

1. Mở **Docker Desktop**, đợi trạng thái Running.
2. Cửa sổ PowerShell 1 (giữ mở):

   ```powershell
   .\.venv\Scripts\python.exe -m app.api --config config.example.toml
   ```

3. Cửa sổ PowerShell 2:

   ```powershell
   docker start n8n
   ollama list
   ```

### Bước 2 — Giao diện (http://127.0.0.1:8000)

1. Đăng nhập bằng token: mở `data\secrets\api-token.txt` và dán vào ô đăng nhập (không gửi token lên chat).
2. **Nhập log** → chọn `security.xml` + `powershell.xml` của lần thu ở 3.4. Không tick dữ liệu mẫu → **Nhập và kiểm tra**.
3. **Tạo ca từ lần nhập**. Mở ca chứa nhóm đăng nhập sai/đúng của `lab_demo`, nhấn các mã sự kiện để xem XML.
4. Chọn **cả hai model** → **Phân tích ca đã chọn**. Đợi completed.
5. Mở XML bằng chứng model viện dẫn. Nhấn **Tải JSONL** và **Tải CSV**.
6. Ghi vào nhật ký: case_id, result_id từng model, nhãn và lý do, đối chiếu **tài khoản/phiên** model nói với nhật ký thao tác (đúng/sai, vì sao).

### Bước 3 — n8n (http://127.0.0.1:5678)

1. Mở workflow **Windows Log SLM - Local analysis**.
2. Lần đầu: tạo credential **Header Auth**, Name `Authorization`, Value `Bearer <nội dung api-token.txt>`. Gán cho node **Submit** và **Poll**.
3. Node **Edit Fields**: `base_url` = `http://host.docker.internal:8000`, `case_id` = ca ở bước 2, `model` = `qwen2.5:3b-instruct-q4_K_M`, `request_id` = UUID mới:

   ```powershell
   [guid]::NewGuid().ToString()
   ```

4. **Execute Workflow** → ghi execution ID, request_id, nhãn.
5. Đổi `model` = `llama3.2:3b-instruct-q4_K_M` và tạo **request_id mới** → chạy lại.

**Báo Claude**: case_id, các result_id/request_id, nhật ký đối chiếu → Claude kiểm tra API/refs/export khớp nhau và viết biên bản 11.1.

---

## Task 11.2 — Chạy khi ngắt Internet

### Bước 1 [Host] — Chuẩn bị khi còn mạng

```powershell
ollama list
docker image ls n8nio/n8n
Get-ChildItem .\data\tokenizers
```

Phải thấy đủ hai model, image n8n và thư mục tokenizer.

### Bước 2 — Ngắt mạng

Tắt Wi-Fi / rút cáp mạng **của máy thật** (để chế độ máy bay hoặc tắt adapter trong Settings). Kiểm tra:

```powershell
Test-NetConnection 1.1.1.1 -Port 443 -InformationLevel Quiet
Resolve-DnsName example.com
```

Lệnh đầu phải trả `False`, lệnh sau phải lỗi. Ghi giờ ngắt mạng.

### Bước 3 — Phân tích offline

1. Khởi động lại API (cửa sổ 1) và `docker start n8n` nếu đã tắt.
2. Trong trình duyệt, mở DevTools (F12) → tab **Network** → tick *Preserve log*, rồi đăng nhập UI.
3. Tạo một ca (có thể dùng lại lần nhập ở 11.1), phân tích bằng cả hai model, mở bằng chứng, export.
4. Chạy workflow n8n một lượt với request_id mới.
5. Trong tab Network, lọc và xác nhận mọi request chỉ tới `127.0.0.1`. Chụp ảnh màn hình.
6. Ghi giờ, case_id, result_id, kết quả/lỗi. n8n có thể báo không kiểm tra được bản cập nhật: ghi lại nguyên văn, đây là n8n chứ không phải ứng dụng.

Bật lại mạng. **Báo Claude** các ID và ảnh → Claude kiểm tra log và viết biên bản 11.2.

---

## Task 11.4 — Bộ ca thật 10 phát triển + 40 đánh giá

### Kế hoạch thu

Mục tiêu 51 ca: 1 warmup + 10 development + 40 evaluation (10 ca cho mỗi nhóm dưới đây). Mỗi ca nên từ **một lần thu riêng** (lặp lại 3.4 bước 3–5), tốt nhất khởi động lại VM giữa các lần để có phiên độc lập.

| Nhóm | Kịch bản gợi ý | Nhãn |
|---|---|---|
| normal | Đăng nhập đúng `lab_demo`, chạy lệnh vô hại (`Get-Date`, `notepad`) | NORMAL |
| password_guessing | ≥ 5 lần sai trong 60 giây (dưới ngưỡng khóa), có hoặc không có lần đúng sau đó | ALERT |
| mixed_same_session | Sai nhiều lần → đúng → chạy lệnh PowerShell trong **cùng phiên** đó | ALERT |
| mixed_different_session | Hai tài khoản/phiên khác nhau: một phiên bình thường + một phiên thử sai | ALERT nếu có phần tấn công |

Nhãn là do **bạn** quyết định sau khi đối chiếu nhật ký và XML, không lấy từ kết quả model. Bảng trên chỉ là gợi ý. Nếu không đủ 51 ca, cứ dùng số thực tế: báo cáo sẽ ghi thiếu, không bịa thêm.

### Lập dataset.json

1. Nhập từng lần thu qua UI, tạo ca, ghi `case_id`.
2. Lấy refs của ca:

   ```powershell
   $token = (Get-Content .\data\secrets\api-token.txt -Raw).Trim()
   $h = @{ Authorization = "Bearer $token" }
   Invoke-RestMethod -Uri "http://127.0.0.1:8000/cases/THAY_CASE_ID" -Headers $h | ConvertTo-Json -Depth 8
   ```

3. Tạo `data\dataset.json` theo mẫu ở evaluation.md mục 1. Mỗi ca có `case_id`, `split` (warmup/development/evaluation), `group`, `label`, `run_ids`, `session_keys` (`TEN_VM/LastBootUpTime/TAI_KHOAN/LOGON_ID`), `annotator`, `rationale`, `expected_accounts`, `expected_sessions`, `evidence_refs`.
4. Chia split **theo lần thu**: cùng một XML không được nằm ở cả development và evaluation.
5. Sau khi chốt thì **không sửa dataset.json nữa**. Báo Claude → Claude chạy kiểm tra leakage và khóa manifest.

---

## Task 11.5 — Chạy đánh giá và chấm

### Bước 1 [Host] — Chạy runner

Dừng API (Ctrl+C ở cửa sổ 1). Không chạy API cùng lúc với runner.

```powershell
.\.venv\Scripts\python.exe -m app.evaluation_runner .\data\dataset.json --config config.example.toml
```

Runner chạy 2 model × 2 mode × 3 repeat cho mọi ca, có thể mất nhiều giờ: cắm sạc, tắt sleep máy. Ghi `evaluation_id` in ra. Nếu runner báo lỗi, **không chạy lại ngay**, báo Claude trước.

### Bước 2 — Chấm phiên/tài khoản

Mở lại API, vào http://127.0.0.1:8000 → **Mở báo cáo đánh giá đã lưu**. Với mỗi hàng (ít nhất repeat 1 của mọi ca evaluation, cả hai model và hai mode), đọc lý do model + XML và quyết định:

- `incorrect = true` nếu model gán hoạt động cho sai tài khoản/phiên, gộp hai phiên độc lập hoặc khẳng định quan hệ không có bằng chứng.
- `incorrect = false` nếu không có các lỗi đó.

Gửi điểm chấm:

```powershell
$token = (Get-Content .\data\secrets\api-token.txt -Raw).Trim()
$h = @{ Authorization = "Bearer $token" }
$evalId = 'THAY_EVALUATION_ID'
$body = @{
  case_id = 'THAY_CASE_ID'; model = 'qwen2.5:3b-instruct-q4_K_M'; mode = 'grouped'; repeat = 1
  annotator = 'Thang'; incorrect = $false
  rationale = 'THAY_DOI_CHIEU_CU_THE'; evidence_refs = @('THAY_REF')
} | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/evaluations/$evalId/reviews" -Headers $h -ContentType 'application/json' -Body $body
```

Nếu muốn, có thể ghi điểm chấm vào một file CSV (case_id, model, mode, repeat, incorrect, rationale, ref) rồi nhờ Claude viết vòng lặp gửi hàng loạt.

### Bước 3 — Xuất

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:8000/evaluations/$evalId/export?format=jsonl" -Headers $h -OutFile ".\data\exports\$evalId.jsonl"
Invoke-WebRequest -Uri "http://127.0.0.1:8000/evaluations/$evalId/export?format=csv" -Headers $h -OutFile ".\data\exports\$evalId-comparison.csv"
```

**Báo Claude** `evaluation_id` → Claude đối chiếu số ca, số response, lỗi và số đo với kết quả gốc.

---

## Task 11.6 — Chọn model mặc định

Sau 11.5, Claude viết đề xuất từ báo cáo thật (bỏ sót = FN, cảnh báo nhầm = FP, coverage, UNKNOWN, thời gian, RAM/VRAM) kèm giới hạn thực nghiệm. Việc của bạn: **đọc và duyệt** đề xuất, kiểm tra mỗi con số khớp với báo cáo `/reports` và file `comparison.csv`.
