# Thiết kế: test Qwen / Llama trên toàn bộ log máy thật, có hướng dẫn nhận biết nhiễu (25/11/2026)

## 1. Mục đích

- Hiện mô hình chỉ thấy 12 Event ID agent thu (1.429 sự kiện bình thường trong log của Lâm). Log thật có **33.017 sự kiện**, phần lớn là sự kiện nền của Windows.
- Muốn biết: khi đưa **toàn bộ log**, Qwen và Llama có phân biệt được nhiễu với dấu hiệu tấn công không, báo nhầm bao nhiêu, và có bỏ sót thêm tấn công không.
- Yêu cầu của nhóm: **mô hình không được học vẹt.** Hướng dẫn về nhiễu không được rút ra từ log dùng để chấm điểm.

## 2. Mục tiêu / không làm / thất bại nếu

**Mục tiêu**
- Báo nhầm của Qwen, Llama, luật, Sigma mô phỏng, DeepBlueCLI, Hayabusa trên phần kiểm tra (22–24/11).
- Tỉ lệ bắt 19 ca tấn công có nhãn (14 `scored` + 2 `coverage` + 3 `observational`) với prompt đã khoá, so với lượt 24/11 (Qwen 10/14, Llama 11/14).
- **Đối chứng:** cùng ca kiểm tra + 19 ca tấn công, prompt **không có** phần hướng dẫn nhiễu mới → chứng minh hướng dẫn có tác dụng (hoặc không).

**Không làm (lượt này)**
- Không sửa `client_agent.ps1` (agent vẫn thu 12 ID). Đây là thí nghiệm offline; muốn đưa vào hệ thống thật thì bàn với Lâm sau.
- Không thêm luật MẠNH mới (giữ tính chất 0 báo nhầm của luật). Không fine-tune mô hình.
- Không đưa tên phần mềm cụ thể thấy trong log của Lâm vào danh sách bỏ qua (Claude Code, wpsupdate, Zalo, bash...).

**Thất bại nếu**
- Báo nhầm giảm nhưng tỉ lệ bắt tấn công giảm so với lượt 24/11.
- Sửa hướng dẫn sau khi đã nhìn kết quả phần kiểm tra.
- Bộ lọc nhiễu bỏ mất sự kiện mà kẻ tấn công tạo ra (ví dụ `net.exe` dò nhóm Administrators bị coi là nhiễu).
- GPU vượt 75°C.

## 3. Ràng buộc

- Qwen / Llama chạy trên **Google Colab** (mục 7b). Nếu phải chạy trên laptop: dùng lại bộ canh nhiệt của `run_combined_eval.py` (chờ ≤ 58°C trước mỗi lần gọi, hạ ngưỡng nếu ≥ 68°C, dừng ở 75°C).
- `core/analyze.py` dùng chung với Lâm: thay đổi phải **chỉ cộng thêm**. Ca chỉ có 12 ID cũ phải cho kết quả y như trước (kiểm bằng ảnh chụp kết quả luật trên 1.071 ca + 35 test).
- Log của Lâm chỉ ở máy local (Ollama chạy local), nằm trong `eval_real/cases/` (đã gitignore), không đưa lên GitHub.

## 4. Các cách đã cân nhắc

| Cách | Đổi lại | Chọn? |
|---|---|---|
| 1. Hướng dẫn lấy từ tài liệu Microsoft, test trên cả 4 ngày | Đơn giản, nhưng người viết hướng dẫn đã xem log nên dễ bị ảnh hưởng | Không |
| **2. Cách 1 + chia theo thời gian: chỉnh trên phần trước 22/11, khoá, test trên 22–24/11** | Tập kiểm tra nhỏ hơn, nhưng tách bạch chỉnh / chấm | **Có — nhóm chọn, mốc 22/11** |
| 3. Cho mô hình đọc cả 33.000 sự kiện, không lọc bằng code | 1–2 ngày GPU mỗi mô hình; mô hình 3B rối khi đầu vào toàn nhiễu | Không |

## 5. Dữ liệu

| Phần | Khoảng thời gian | Tổng | Nhiễu bỏ bằng code | Đưa vào luật + AI | Số cửa sổ 10 phút (= số ca) |
|---|---|---|---|---|---|
| Chỉnh (dev) | 12/11 → 21/11 23:59 | 10.340 | 9.459 | 881 | 98 |
| **Kiểm tra (test)** | 22/11 → 24/11 | **22.677** | 20.821 | **1.856** | **62** |

(Đếm ngày 25/11 với đúng bộ lọc ở mục 5–6. Phần kiểm tra còn lại: 4624×585, 4798×362, 4104×330, 400×131, 4648×112, 4672×110, 5382×70, 4797×42, 4799×37, 4738×27, 4688×23, khác < 10.)
- 62 ca bình thường là ít → khoảng tin cậy của tỉ lệ báo nhầm rộng (ví dụ 0/62 vẫn là 0%–6%). Ghi rõ trong báo cáo.

- Nguồn: `D:\tailieuDACN\WindowsLog_extract\Windows Log\NHAN-LAM-LAPTOP_20261124_193235\` (Security.evtx, Microsoft-Windows-PowerShell_Operational.evtx, Windows PowerShell.evtx).
- Log của Lâm **không có tấn công** → phần kiểm tra chỉ đo báo nhầm. Khả năng bắt tấn công đo bằng 19 ca có nhãn (bộ DeepBlueCLI + EVTX-to-MITRE).
- Phân loại Event ID (theo tài liệu Microsoft "Audit ..." và MITRE ATT&CK, không theo tần suất trong log):

| Nhóm | Event ID | Lý do |
|---|---|---|
| **Nhiễu — code bỏ hẳn** | 5379, 4907, 5058, 5059, 5061, 4634, 4608, 4826, 4902, 4904, 4905, 5024, 5033, 6417, 4696; PowerShell 40961, 40962, 53504, 600, 403, 300, 4100, 4102 | Đọc Credential Manager, đổi SACL khi cập nhật, thao tác khoá mã hoá, đăng xuất, khởi động / dịch vụ audit, PowerShell bật / tắt. Không chứa lệnh hay tiến trình đáng ngờ |
| **Mới — đưa cho luật + AI** | 4798, 4799 (dò tài khoản / nhóm), 4672 (đặc quyền khi đăng nhập), 5382 (đọc vault), 4797 (dò mật khẩu trống), 4738 (sửa tài khoản), 4647 (đăng xuất chủ động), 4616 (đổi giờ hệ thống), 1100 (dịch vụ log tắt), 4719 (đổi chính sách audit, nếu có); PowerShell 4103, 400, 800 | Có trong ATT&CK: T1087/T1069 trinh sát, T1555 đánh cắp mật khẩu, T1098 sửa tài khoản, T1070.006 đổi giờ, T1562.002 tắt log, T1059.001 PowerShell (400 chứa `HostApplication` = dòng lệnh đầy đủ) |
| Giữ như cũ | 12 ID agent thu | |

- Hạn chế ghi vào báo cáo: bỏ 5379 thì không thấy được kiểu đánh cắp Credential Manager chỉ để lại 5379 (5379 không có tên tiến trình, chỉ có PID, nên không lọc chi tiết được).

## 6. Thay đổi code

**a. `eval_real/build_normal_cases.ps1`**
- Thêm tham số chọn bộ Event ID (mặc định = 12 ID như cũ; chế độ mới = 12 ID + nhóm "Mới") và đọc thêm `Windows PowerShell.evtx` (ghi vào `powershell.xml`).
- Chỉ tạo ca cho cửa sổ 10 phút có ≥ 1 sự kiện sau khi bỏ nhiễu. Số cửa sổ chỉ toàn nhiễu ghi riêng vào báo cáo (không tính là "đúng NORMAL" cho công cụ nào).
- `manifest.json` thêm `split: dev | test` (theo `window_start` < 2026-11-22) và `category: normal_full`. Tiền tố ca: `lam_full_`.
- evtx gốc từng cửa sổ (đủ mọi sự kiện, cho DeepBlueCLI / Hayabusa) ở `cases/_full_evtx/<case_id>/`.

**a2. Ca tấn công cũng phải có đủ Event ID mới**
- 19 ca tấn công hiện chỉ chứa 12 ID cũ. Vì prompt động, nếu giữ nguyên thì prompt mới không bao giờ được thử trên ca tấn công → phép kiểm "không bỏ sót thêm" vô nghĩa.
- Dựng lại 19 ca từ evtx gốc (nguồn trong `labels.json`) với bộ ID mới, lưu thành bản riêng (`<case_id>_full`), giữ nguyên bản cũ. Sửa `eval_real/build_cases.ps1` thêm cùng tham số chọn bộ ID.

**b. `core/analyze.py` (chỉ cộng thêm)**
- `SUPPORTED_EVENT_IDS` thêm nhóm "Mới"; `FIELDS` thêm `CallerProcessName`, `PrivilegeList`, `HostApplication`, `SchemaFriendlyName`, `Resource`, `Identity` và các trường cần thiết của 4738.
- Sự kiện PowerShell cổ điển (400 / 800) có `<Data>` không tên: tách `HostApplication=...` / `CommandLine=...` từ chuỗi văn bản.
- `is_benign_noise` thêm:
  - 4672 của SYSTEM / LOCAL SERVICE / NETWORK SERVICE (giống quy tắc 4624 LogonType 5 đang có).
  - 4798 / 4799 khi `CallerProcessName` là tiến trình dịch vụ Windows (`svchost.exe`, `VSSVC.exe`, `taskhostw.exe`, `LogonUI.exe`, `dllhost.exe`, `explorer.exe`, `SearchIndexer.exe`) **và** nằm dưới `C:\Windows\`. `net.exe`, `net1.exe`, `whoami.exe`, `powershell.exe`, `cmd.exe`... **không** bao giờ là nhiễu.
- `EVENT_MEANING` + `EXTENDED_SIGNS` thêm mô tả cho nhóm "Mới" (dấu hiệu tấn công + hoạt động bình thường), viết theo tài liệu. Prompt động sẵn có → lô chỉ có 12 ID cũ nhận prompt y như cũ.
- Không thêm luật tương quan mới.

**c. `eval_real/run_combined_eval.py`, `run_hayabusa.py`, `run_deepblue.ps1`**
- Tham số chọn tập ca (`normal_full` + `split`) và thư mục evtx (`_full_evtx`); tag riêng cho từng lượt.
- Ca mà sau `is_benign_noise` không còn sự kiện nào: **không gọi mô hình** (hiện `analyze_case` sẽ gửi lại toàn bộ sự kiện khi lọc hết — `filtered or events`), ghi là "chỉ nhiễu" và đếm riêng.
- Báo cáo mới `SO_SANH_TOAN_BO_LOG_<tag>.md`: phễu số liệu (33.017 → 22.677 → 3.109 → số cửa sổ), báo nhầm từng công cụ trên phần kiểm tra, tỉ lệ bắt 19 ca tấn công, mã băm prompt đã khoá, phần "hạn chế" (mục 8).

## 7. Quy trình chạy

1. **Kiểm tra không phá cái cũ:** 35 test + ảnh chụp luật trên 1.071 ca phải giống hệt trước khi sửa. Thêm test cho: `net.exe` dò Administrators (4799) không bị lọc; 400 có `-enc` / `DownloadString` bị luật hoặc AI bắt.
2. **Chỉnh (dev):** chạy luật + Qwen + Llama trên ca `split=dev`. Đọc các ca báo nhầm / UNKNOWN, sửa lời hướng dẫn **theo hướng tổng quát** (không ghi tên phần mềm cụ thể). Tối đa 2 vòng; vòng 2 chỉ chạy lại các ca bị báo nhầm / UNKNOWN ở vòng 1. Không chạy ca tấn công trong giai đoạn này.
3. **Khoá:** ghi mã băm SHA-256 của `analyze.py` và của prompt mẫu vào báo cáo. Từ đây không sửa `analyze.py`.
4. **Kiểm tra (test):** luật, Sigma mô phỏng, Qwen, Llama trên ca `split=test`; DeepBlueCLI, Hayabusa trên evtx gốc của cùng các cửa sổ; Qwen, Llama, luật trên 19 ca tấn công bản `_full`.
5. **Đối chứng:** Qwen, Llama trên ca `split=test` + 19 ca `_full` với prompt bỏ phần hướng dẫn nhiễu mới (chỉ giữ nghĩa của Event ID). Bật bằng một tham số (ví dụ biến môi trường `NOISE_GUIDANCE=0`), không sửa `analyze.py` sau khi khoá.
6. **Báo cáo** + đối chiếu với lượt 24/11 và lượt đối chứng.

Thời gian trên laptop (có chờ nguội, ~1 phút/ca): tổng khoảng 10–15 tiếng. Trên Colab T4 (không chờ nguội): ước chừng 3–5 tiếng cho cả dev + kiểm tra + đối chứng + ca tấn công. Script chạy tiếp từ chỗ dừng nên chia nhiều phiên được.

## 7b. Chạy trên Google Colab

| Bước | Chạy ở |
|---|---|
| Cắt log thành ca, ẩn danh, đóng gói | Laptop (cần Windows để đọc evtx) |
| Luật, Sigma mô phỏng (không cần GPU) | Laptop |
| DeepBlueCLI, Hayabusa | Laptop (chỉ chạy trên Windows) |
| **Qwen, Llama: dev, kiểm tra, đối chứng, 19 ca tấn công** | **Colab Pro, GPU T4** |
| Ghép kết quả, viết báo cáo | Laptop |

- **Trước khi đưa lên:** Lâm đồng ý đưa log (đã ẩn danh) lên Google. Ẩn danh thêm `TargetUserName`, `SubjectUserName`, `MemberName`, `SamAccountName`, `Workstation` (trừ tài khoản hệ thống SYSTEM / LOCAL SERVICE / NETWORK SERVICE / tên kết thúc bằng `$`) và SID dạng `S-1-5-21-...` → nhãn cố định (`USER01`, `S-1-5-21-X-1001`...) để luật vẫn ghép được cùng một tài khoản. Chỉ đưa XML + `manifest.json`, **không** đưa evtx. Lượt kiểm tra lại 1.071 ca dùng cùng bước ẩn danh này để chắc nó không làm đổi kết quả luật.
- **Gói tải lên** (`colab_pack.zip`): ca `lam_full_*` + 19 ca `_full`, `core/`, `eval_real/run_combined_eval.py` và các file nó cần, `labels.json`, `requirements.txt`, notebook `eval_real/colab_run.ipynb`.
- **Notebook** (chạy lần lượt): gắn Google Drive (bạn tự bấm cho phép) → cài Ollama, bật `ollama serve` chạy nền → tải `qwen2.5:3b-instruct-q4_K_M`, `llama3.2:3b-instruct-q4_K_M` và **so mã model** với máy (Qwen `357c53fb659c`, Llama `a80c4f17acd5`) → cài thư viện → chạy `run_combined_eval.py --no-gpu-guard`, ghi CSV thẳng vào Drive.
- **Bị ngắt phiên:** chạy lại các ô; script bỏ qua ca đã có trong CSV trên Drive.
- **Ghi vào báo cáo:** phiên bản Ollama trên Colab (máy đang dùng 0.40.18), loại GPU, mã model. Lượt 24/11 chạy trên laptop → khi so với nó phải ghi là khác máy; mọi lượt của thí nghiệm này chạy cùng trên Colab.
- **Bạn làm:** đăng nhập Google trong Chrome, bấm cho phép Drive, tải file kết quả về máy (hoặc cho phép mình tải khi mình hỏi).
- **Mình làm:** tạo notebook, chọn GPU, tải gói lên, chạy các ô, theo dõi, nối lại khi bị ngắt.

## 8. Hạn chế phải ghi trung thực trong báo cáo

- Người viết hướng dẫn đã xem **thống kê tổng** (số lượng theo Event ID, tiến trình gọi 4798/4799) của cả 4 ngày trước khi chia. Danh sách nhiễu dựa trên tài liệu, nhưng không loại trừ hoàn toàn ảnh hưởng.
- Log của một máy, một người dùng, 4 ngày, không có tấn công.
- Agent thật chưa thu các ID mới → kết quả là thí nghiệm offline.
- Mô hình chạy trên Colab, khác máy với lượt 24/11.
- Bỏ 5379 (mục 5).

## 9. Để người làm tự quyết

- Câu chữ cụ thể của mô tả trong `EXTENDED_SIGNS`, miễn là tổng quát và theo tài liệu.
- Cách tách chuỗi cho sự kiện PowerShell cổ điển; cách đặt tên tham số / tag.
- Ca dev rỗng sau lọc (nếu có) xử lý như cửa sổ chỉ toàn nhiễu.
