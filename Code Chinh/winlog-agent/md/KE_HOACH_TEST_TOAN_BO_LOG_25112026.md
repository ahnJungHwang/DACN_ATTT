# Kế hoạch triển khai: test Qwen / Llama trên toàn bộ log máy thật

> **Cho người / agent thực hiện:** dùng superpowers:executing-plans hoặc superpowers:subagent-driven-development, làm từng task theo thứ tự. Bước có ô `- [ ]` để đánh dấu.

**Mục tiêu:** đưa thêm Event ID có giá trị (ngoài 12 ID agent thu) vào luật + Qwen / Llama, có hướng dẫn nhận biết nhiễu viết theo tài liệu, chỉnh trên log trước 22/11, khoá, rồi đo trên log 22–24/11 và 19 ca tấn công; mô hình chạy trên Google Colab.

**Kiến trúc:** dữ liệu cắt và ẩn danh trên laptop (PowerShell + Python) → gói zip → Colab (Ollama + `run_combined_eval.py`) ghi CSV vào Drive → tải về → DeepBlueCLI / Hayabusa chạy trên laptop → báo cáo gộp. `core/analyze.py` chỉ được cộng thêm; ca 12 ID cũ cho kết quả y như trước.

**Công nghệ:** Python 3 (.venv, unittest), PowerShell 5.1, Ollama, Google Colab Pro (GPU T4), Claude in Chrome.

**Thiết kế:** `md/THIET_KE_TEST_TOAN_BO_LOG_25112026.md` (đã duyệt 25/11/2026). Đọc cả hai file.

## Ràng buộc chung

- **Không `git commit` / `push` / `merge`.** Mỗi task kết thúc bằng `git diff --stat`; người dùng tự commit.
- `core/analyze.py` dùng chung với Lâm: chỉ cộng thêm. Prompt cho lô chỉ có ID cũ phải giữ đúng mã băm:
  - `{4104,4624,4625,4648,4688}` → `8fe535636b94ee6a958c074e99368748ef1bee638aec2e2280e6c3618f055ad8`
  - `{1102,4104,4624,4688,4698,7045}` → `5ffde5da487aa6b3fb56451ab3001f61fb5a2672a1153de795a96f526bf0fa60`
  (tính bằng `hashlib.sha256(A.build_system_prompt(A.BatchVerdict.model_json_schema(), "", ids).encode())`).
- Mốc chia: `window_start < 2026-11-22 00:00` (giờ máy) → `dev`, còn lại → `test`.
- Nhiễu bỏ ở mức ID (không đọc): Security 5379, 4907, 5058, 5059, 5061, 4634, 4608, 4826, 4902, 4904, 4905, 5024, 5033, 6417, 4696; PowerShell 40961, 40962, 53504, 600, 403, 300, 4100, 4102.
- ID mới được đọc: Security 4798, 4799, 4672, 5382, 4797, 4738, 4647, 4616, 1100, 4719; PowerShell/Operational 4103; Windows PowerShell 400, 800.
- Hướng dẫn trong prompt **không** chứa tên phần mềm thấy trong log của Lâm (Claude Code, wpsupdate, Zalo, bash, gamingservices…).
- `net.exe`, `net1.exe`, `whoami.exe`, `powershell.exe`, `pwsh.exe`, `cmd.exe`, `wmic.exe` không bao giờ là nhiễu.
- Model trên Colab phải trùng mã với máy: `qwen2.5:3b-instruct-q4_K_M` = `357c53fb659c`, `llama3.2:3b-instruct-q4_K_M` = `a80c4f17acd5`. Máy đang dùng Ollama 0.40.18.
- Không đưa gì lên Google trước khi người dùng xác nhận **Lâm đồng ý**. Chỉ đưa XML + manifest đã ẩn danh, không đưa evtx.
- Nếu chạy mô hình trên laptop: bộ canh nhiệt mặc định (58 / 68 / 75°C), GPU + CPU ≤ 90°C.
- Không quét thư mục người dùng / OneDrive. Không tắt hay thêm ngoại lệ Defender.

## Điểm dễ hỏng cần soi kỹ

1. Ca tấn công `_full` bị cắt `max_events = 300` làm rơi sự kiện tấn công cũ → bản `_full` phải chứa mọi `EventRecordID` của bản cũ (test ở Task 3).
2. Ẩn danh đổi nhầm tên nhóm / tài khoản dựng sẵn (Administrators, SYSTEM, `PC$`) làm luật đổi kết quả → test ở Task 5 + so kết quả luật trước/sau ẩn danh.
3. Sự kiện PowerShell cổ điển 400/800 không có `HostApplication=` hoặc có ký tự lạ → đọc không lỗi, trường rỗng thì bỏ (test ở Task 1).
4. Ca mà bộ lọc trong `analyze.py` bỏ hết sự kiện → phải ra `NOISE_ONLY`, không được gửi lại toàn bộ cho AI (test ở Task 4).
5. Colab ngắt giữa chừng để lại dòng CSV dở → chạy tiếp không lỗi, không tính dòng dở là đã xong (test ở Task 4).

---

### Task 1: `analyze.py` đọc ID mới + bộ lọc nhiễu mới

**Files:**
- Modify: `core/analyze.py` (`SUPPORTED_EVENT_IDS` ~dòng 41, `FIELDS` ~dòng 50, `read_events` ~dòng 242, `is_benign_noise` ~dòng 188)
- Create: `tests/test_full_log.py`

**Interfaces:**
- Produces: `NEW_EVENT_IDS: set[int]` (đúng danh sách "ID mới" ở Ràng buộc chung), `SUPPORTED_EVENT_IDS` = cũ ∪ `NEW_EVENT_IDS`; `read_events()` trả thêm trường `HostApplication`, `CommandLine` cho 400/800, `Payload`, `ContextInfo` cho 4103; `is_benign_noise()` nhận thêm quy tắc 4672 / 4798 / 4799.

- [ ] **Bước 1: Chụp kết quả luật hiện tại** (trước mọi sửa đổi):
  `.venv/Scripts/python.exe <scratchpad>/snap_rules.py <scratchpad>/before_full.json` (script đọc mọi thư mục có `*.xml` trong `data01, data100, data_normal_heavy, data_benchmark, eval_real/cases`, bỏ `_normal_evtx` / `_full_evtx`, ghi `strong`, `stages`, `kept` theo ca; nếu scratchpad mất thì viết lại đúng như vậy). Mong đợi: `1071 cases`.
- [ ] **Bước 2: Viết test fail** trong `tests/test_full_log.py` (dùng `ev()` như `tests/test_detection.py`; XML mẫu ghi vào `tempfile.TemporaryDirectory()`):
  - `test_classic_powershell_400_host_application`: `powershell.xml` có một Event `EventID 400`, `Channel "Windows PowerShell"`, `<EventData><Data>Available</Data><Data>None</Data><Data>\tNewEngineState=Available\r\n\tHostApplication=powershell.exe -enc SQBFAFgA\r\n\tEngineVersion=5.1</Data></EventData>` → `read_events(d)[0]["data"]["HostApplication"] == "powershell.exe -enc SQBFAFgA"`, và `is_benign_noise(...)` là `False`.
  - `test_classic_400_without_host_application_is_read`: như trên nhưng không có `HostApplication=` → đọc được 1 sự kiện, `"HostApplication" not in data`.
  - `test_noise_ids_are_not_read`: file chỉ có `EventID 5379` → `read_events` raise `ValueError("No supported events found")`.
  - `test_4672_service_accounts_are_noise`: `ev(4672, SubjectUserName="SYSTEM", SubjectUserSid="S-1-5-18")` → `True`; `ev(4672, SubjectUserName="nv01", SubjectUserSid="S-1-5-21-1-2-3-1001")` → `False`.
  - `test_group_enumeration_by_lolbin_is_not_noise`: với 4798 và 4799, `CallerProcessName` = `C:\Windows\System32\net1.exe`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `C:\Windows\System32\whoami.exe` → `False`; `C:\Windows\System32\svchost.exe`, `C:\Windows\System32\LogonUI.exe` → `True`; `C:\Users\Public\svchost.exe` → `False`.
- [ ] **Bước 3: Chạy test, phải fail:** `.venv/Scripts/python.exe -m unittest tests.test_full_log -v` → FAIL / ERROR ở cả 5 test.
- [ ] **Bước 4: Sửa `core/analyze.py`:**
  - `NEW_EVENT_IDS` + gộp vào `SUPPORTED_EVENT_IDS`.
  - `FIELDS` thêm: `CallerProcessName, PrivilegeList, SchemaFriendlyName, Resource, Identity, Workstation, HostApplication, Payload, ContextInfo, OldUacValue, NewUacValue, UserAccountControl, SidHistory, AllowedToDelegateTo, PasswordLastSet, PreviousTime, NewTime`.
  - `read_events`: với `event_id in (400, 800)` và `<Data>` không có `Name`, nối text các `<Data>`, lấy `HostApplication=` và `CommandLine=` bằng regex tới hết dòng (`[^\r\n]*`), bỏ giá trị rỗng. `Payload`, `ContextInfo`, `HostApplication` cắt theo `MAX_FIELD_CHARS` như `TaskContent`.
  - `is_benign_noise`: nhánh `4672` (SubjectUserSid `S-1-5-18/19/20` hoặc tên SYSTEM / LOCAL SERVICE / NETWORK SERVICE); nhánh `4798/4799`: noise khi `CallerProcessName.lower()` bắt đầu bằng `c:\windows\` **và** tên file thuộc `{"svchost.exe","vssvc.exe","taskhostw.exe","logonui.exe","dllhost.exe","explorer.exe","searchindexer.exe"}`.
- [ ] **Bước 5: Chạy lại:** `.venv/Scripts/python.exe -m unittest discover -s tests` → `OK` (35 cũ + 5 mới).
- [ ] **Bước 6: So kết quả luật:** chạy `snap_rules.py` ra `after_full.json`, so với `before_full.json` → không ca nào đổi `strong` / `stages`.
- [ ] **Bước 7:** `git diff --stat` (không commit).

### Task 2: Hướng dẫn trong prompt cho ID mới + công tắc đối chứng

**Files:**
- Modify: `core/analyze.py` (`EVENT_MEANING` ~dòng 854, `EXTENDED_SIGNS` ~dòng 876, `build_system_prompt` ~dòng 891)
- Test: `tests/test_full_log.py`

**Interfaces:**
- Consumes: `NEW_EVENT_IDS` (Task 1).
- Produces: `noise_guidance_enabled() -> bool` (đọc `os.getenv("NOISE_GUIDANCE", "1") != "0"` mỗi lần gọi); `EXTENDED_SIGNS` thêm các nhóm mới; `prompt_fingerprint() -> str` = SHA-256 của `build_system_prompt(schema, "", SUPPORTED_EVENT_IDS)` (dùng ở Task 6).

- [ ] **Bước 1: Viết test fail:**
  - `test_base_prompts_unchanged`: hai mã băm ở Ràng buộc chung khớp.
  - `test_new_group_guidance_in_prompt`: prompt cho `{4624, 4799}` chứa chuỗi tấn công của nhóm 4798/4799 (ví dụ có `T1087`) và chuỗi bình thường của nhóm đó.
  - `test_noise_guidance_switch`: đặt `NOISE_GUIDANCE=0` (`unittest.mock.patch.dict(os.environ, ...)`) → prompt cho `{4624, 4799}` vẫn có chuỗi tấn công, **không** có chuỗi bình thường của nhóm mới; prompt cho ID cũ vẫn đúng mã băm.
  - `test_guidance_has_no_app_names`: ghép mọi chuỗi trong `EXTENDED_SIGNS` của nhóm mới, viết thường, không chứa `claude`, `wpsupdate`, `zalo`, `bash`, `gamingservices`.
- [ ] **Bước 2: Chạy, phải fail** (trừ `test_base_prompts_unchanged` pass sẵn).
- [ ] **Bước 3: Sửa:** thêm `EVENT_MEANING` cho mọi ID mới; thêm các mục `EXTENDED_SIGNS` (mỗi mục `(ids, dấu hiệu tấn công, hoạt động bình thường)`), viết theo tài liệu Microsoft "Audit …" + ATT&CK:
  - `{4798, 4799}` — T1087 / T1069: dò tài khoản / nhóm (đặc biệt Administrators) bởi `net.exe`, `net1.exe`, `whoami`, PowerShell, cmd hoặc file lạ ngoài thư mục hệ thống, hàng loạt trong thời gian ngắn | bình thường: tiến trình dịch vụ Windows hoặc phần mềm cài trong Program Files kiểm tra nhóm khi đăng nhập / sao lưu / cập nhật.
  - `{4672}` — đặc quyền nhạy cảm (`SeDebugPrivilege`, `SeTcbPrivilege`, `SeImpersonatePrivilege`) gán cho tài khoản người dùng ngay sau đăng nhập mạng lạ | bình thường: tài khoản quản trị đăng nhập tại máy.
  - `{5382}` — T1555: đọc vault hàng loạt bởi tiến trình lạ | bình thường: trình duyệt / ứng dụng đọc mật khẩu đã lưu của chính người dùng.
  - `{4797}` — dò tài khoản mật khẩu trống từ máy khác | bình thường: kiểm tra cục bộ khi đăng nhập / chia sẻ.
  - `{4738}` — T1098: đổi UAC (bỏ yêu cầu mật khẩu, "password never expires"), thêm `SidHistory`, `AllowedToDelegateTo` | bình thường: hệ thống cập nhật thời gian đổi mật khẩu.
  - `{4616}` — T1070.006: đổi giờ hệ thống thủ công | bình thường: đồng bộ giờ tự động (`svchost.exe` / dịch vụ thời gian).
  - `{1100, 4719}` — T1562.002: dịch vụ log tắt / chính sách audit bị đổi ngoài lúc tắt máy | bình thường: 1100 ngay trước khi tắt / khởi động lại máy.
  - `{400, 800, 4103}` — T1059.001: `HostApplication` / lệnh có `-enc`, `-EncodedCommand`, `DownloadString`, `IEX` + URL ngoài, `-w hidden`, `FromBase64String` | bình thường: PowerShell mở từ công cụ lập trình / quản trị chạy lệnh thường. Không liệt kê tên sản phẩm.
  - Trong `build_system_prompt`: với mục thuộc nhóm mới, bỏ chuỗi "bình thường" khi `noise_guidance_enabled()` là `False`.
- [ ] **Bước 4:** `.venv/Scripts/python.exe -m unittest discover -s tests` → `OK`.
- [ ] **Bước 5:** `git diff --stat` (không commit).

### Task 3: Dựng ca bình thường `lam_full_*` và ca tấn công `_full`

**Files:**
- Modify: `eval_real/build_normal_cases.ps1`, `eval_real/build_cases.ps1`
- Create (dữ liệu, gitignored): `eval_real/cases/lam_full_*/`, `eval_real/cases/<case_id>_full/`, `eval_real/cases/_full_evtx/<case_id>/`, `eval_real/cases/_full_build_summary.json`

**Interfaces:**
- Produces: thư mục ca giống ca cũ (`security.xml`, `powershell.xml`, `system.xml`, `manifest.json`). Manifest `lam_full_*` có `category: "normal_full"`, `split: "dev"|"test"`. Manifest `_full` giữ `category` / `ground_truth` của ca gốc, thêm `base_case: "<case_id>"`. `_full_build_summary.json`: `{ "files": {tên: tổng}, "selected": {"dev": n, "test": n}, "windows": {"dev": n, "test": n} }`.

- [ ] **Bước 1: `build_normal_cases.ps1`:** thêm `-IdSet Agent|Full` (mặc định `Agent`, hành vi cũ giữ nguyên), `-SplitAt "2026-11-22"`, `-RawDirName "_normal_evtx"`. Khi `Full`: Security / PowerShell-Operational dùng ID cũ ∪ ID mới, thêm nguồn `Windows PowerShell.evtx` với ID 400, 800 (ghi chung `powershell.xml`, sắp theo thời gian), category `normal_full`, chỉ cắt evtx gốc cho cửa sổ `test`, ghi `_full_build_summary.json`.
- [ ] **Bước 2: Chạy:**
  `powershell -ExecutionPolicy Bypass -File eval_real\build_normal_cases.ps1 -EvtxDir "D:\tailieuDACN\WindowsLog_extract\Windows Log\NHAN-LAM-LAPTOP_20261124_193235" -Prefix lam_full -IdSet Full -RawDirName _full_evtx`
  Mong đợi: số cửa sổ dev ≈ 98, test ≈ 62 (sai lệch nhỏ chấp nhận được; ghi số thật). Ca `lam_normal_*` cũ không bị đụng.
- [ ] **Bước 3: `build_cases.ps1`:** thêm `-IdSet Full` → với mỗi ca trong `labels.json`: lấy đúng các sự kiện mà bản cũ đã chọn (12 ID, cắt `max_events`), **cộng** sự kiện ID mới có `TimeCreated` trong khoảng [đầu, cuối] của tập đó; ghi vào `<case_id>_full`. Bản cũ không bị ghi đè.
- [ ] **Bước 4: Chạy** `powershell -ExecutionPolicy Bypass -File eval_real\build_cases.ps1 -IdSet Full`.
- [ ] **Bước 5: Kiểm (Điểm dễ hỏng 1):** script Python ngắn ở scratchpad: với mọi ca có cả bản cũ và `_full`, tập `EventRecordID` (theo kênh) của bản cũ ⊆ bản `_full`; in số sự kiện ID mới được thêm mỗi ca. Mong đợi: không vi phạm. Ca thiếu XML do Defender chặn (4 ca đã biết) ghi lại, không sửa.
- [ ] **Bước 6:** `git diff --stat` (không commit).

### Task 4: `run_combined_eval.py`, `run_hayabusa.py`, `run_deepblue.ps1` cho bộ `full`

**Files:**
- Modify: `eval_real/run_combined_eval.py`, `eval_real/run_hayabusa.py`, `eval_real/run_deepblue.ps1`
- Test: `tests/test_full_log.py`

**Interfaces:**
- Consumes: ca + manifest của Task 3; `NOISE_GUIDANCE` (Task 2).
- Produces:
  - `load_cases(case_set: str = "legacy", split: str = "all", only: set[str] | None = None) -> list[dict]` — `legacy` = hành vi cũ; `full` = ca `normal_full` lọc theo `split`, cộng ca tấn công `<id>_full` (có đủ XML) **chỉ khi** `split` là `test` hoặc `all` (giai đoạn dev không chạy ca tấn công); `only` giữ lại các `case_id` trong tập.
  - `is_noise_only(case_dir: Path) -> bool` — `True` khi `read_events` có sự kiện nhưng `is_benign_noise` bỏ hết.
  - `load_done(path: Path) -> set[tuple[str, str]]` — bỏ qua dòng thiếu `pred`.
  - CLI mới: `--set legacy|full`, `--split dev|test|all`, `--only FILE` (mỗi dòng một `case_id`), `--no-gpu-guard`, `--cases-dir PATH` (Colab), `--baseline CSV` (chỉ cho `--report`).
  - Khi `is_noise_only`: mọi công cụ ghi `pred = "NOISE_ONLY"`, không gọi mô hình.
  - `--report`: coi `normal_session` và `normal_full` là ca bình thường; bỏ hậu tố `_full` khi ghép `case_id` với CSV DeepBlue / Hayabusa; loại `NOISE_ONLY` khỏi mọi chỉ số và ghi số lượng; dòng từ `--baseline` đổi tên công cụ thành `qwen_base` / `llama_base` ("… không có hướng dẫn nhiễu"); khi `--set full`, thêm mục "Phễu số liệu" đọc `_full_build_summary.json` và `prompt_freeze.json` (nếu có), tên file mặc định `SO_SANH_TOAN_BO_LOG_<tag>.md`.
  - `run_hayabusa.py --normal-dir eval_real/cases/_full_evtx --normal-category normal_full`; `run_deepblue.ps1 -NormalCategory normal_full`.

- [ ] **Bước 1: Viết test fail** (import `run_combined_eval` qua `sys.path` thêm `eval_real`):
  - `test_noise_only_case_detected`: thư mục tạm có `security.xml` chỉ gồm 4624 LogonType 5 SYSTEM → `is_noise_only` là `True`; thêm một 4688 `C:\Users\Public\x.exe` → `False`.
  - `test_dev_split_has_no_attack_cases`: với `CASES_DIR` trỏ tới `eval_real/cases` (skip nếu chưa có ca `lam_full_*`), `load_cases("full", "dev")` không có ca nào ngoài `normal_full`; `load_cases("full", "test")` có ca `_full`.
  - `test_resume_ignores_partial_row`: CSV có header + 1 dòng đủ + 1 dòng dở (`qwen,lam_full_x,normal_full,NORMAL` hết dòng) → `load_done` chỉ trả dòng đủ.
- [ ] **Bước 2: Chạy, phải fail.**
- [ ] **Bước 3: Sửa ba file** theo Interfaces. Hành vi khi không truyền tham số mới phải y như cũ.
- [ ] **Bước 4:** `.venv/Scripts/python.exe -m unittest discover -s tests` → `OK`.
- [ ] **Bước 5: Chạy thử không GPU:**
  `.venv/Scripts/python.exe eval_real/run_combined_eval.py --set full --split dev --tools rules,sigma --tag full_dev_smoke`
  Mong đợi: chạy hết ca dev, có dòng `NOISE_ONLY` nếu có, không `ERROR` ngoài 4 ca đã biết. Rồi `--report --set full --tag full_dev_smoke` tạo được file md. Xoá hai file `full_dev_smoke` sau khi xem.
- [ ] **Bước 6:** `git diff --stat` (không commit).

### Task 5: Ẩn danh + đóng gói cho Colab + notebook

**Files:**
- Create: `eval_real/colab_pack.py`, `eval_real/colab_run.ipynb`
- Test: `tests/test_full_log.py`
- Output (gitignored, không commit): `eval_real/colab_pack.zip`, `eval_real/cases/_anon_map.json` (bảng đổi tên, **không** đưa vào zip)

**Interfaces:**
- Produces:
  - `build_name_map(case_dirs: list[Path]) -> dict[str, str]` — gom giá trị `TargetUserName, SubjectUserName, MemberName, SamAccountName, Workstation, WorkstationName` từ ca `lam_full_*`, bỏ: rỗng, `-`, tên kết thúc `$`, `SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`, `ANONYMOUS LOGON`, `DWM-*`, `UMFD-*`, `Administrator`, `Guest`, `DefaultAccount`, `WDAGUtilityAccount`, tên nhóm dựng sẵn (`Administrators`, `Users`, `Remote Desktop Users`, …, mọi tên có SID dạng `S-1-5-32-*`) và `LAB-PC02` / `LABUSER`; gán `USER01`, `USER02`… theo thứ tự chữ cái.
  - `anonymize_xml(text: str, names: dict[str, str]) -> str` — thay tên (không phân biệt hoa thường, theo ranh giới từ) ở **mọi** chỗ trong văn bản, kể cả `ScriptBlockText` / `HostApplication`; SID `S-1-5-21-a-b-c-RID` → `S-1-5-21-0-0-0-RID` (giữ RID).
  - `main()`: chép ca `lam_full_*` (đã ẩn danh) + ca `_full` (dữ liệu công khai, chép nguyên) + `core/`, `eval_real/{run_combined_eval.py, run_eval.py, labels.json}`, `requirements.txt`, `colab_run.ipynb` vào zip; in danh sách file và dung lượng.

- [ ] **Bước 1: Viết test fail:**
  - `test_name_map_skips_builtins`: XML có `TargetUserName` = `nhanvien`, `SYSTEM`, `LAB-PC02$`, `Administrators`, `Administrator` → map chỉ có `{"nhanvien": "USER01"}`.
  - `test_anonymize_everywhere_and_keep_rid`: `anonymize_xml("<Data Name='TargetUserName'>NhanVien</Data><Data Name='ScriptBlockText'>cd C:\\x\\nhanvien\\y</Data><Data Name='TargetSid'>S-1-5-21-111-222-333-1001</Data>", {"nhanvien": "USER01"})` không còn `nhanvien` (mọi kiểu chữ), có `S-1-5-21-0-0-0-1001`; `S-1-5-32-544` giữ nguyên.
- [ ] **Bước 2: Chạy, phải fail.**
- [ ] **Bước 3: Viết `colab_pack.py`** theo Interfaces.
- [ ] **Bước 4: Kiểm (Điểm dễ hỏng 2):** chạy luật (`rule_labels`) trên mọi ca `lam_full_*` trước và sau ẩn danh (bản ẩn danh giải nén ra scratchpad) → kết quả giống hệt; `grep -i` mọi giá trị trong `_anon_map.json` trên thư mục giải nén → 0 kết quả.
- [ ] **Bước 5: Viết `colab_run.ipynb`** (ô theo thứ tự): (1) `nvidia-smi`; (2) `from google.colab import drive; drive.mount('/content/drive')`; (3) giải nén `/content/colab_pack.zip` vào `/content/winlog-agent`; (4) cài Ollama theo hướng dẫn chính thức ollama.com, chạy `ollama serve` nền bằng `subprocess.Popen`, chờ `http://127.0.0.1:11434` trả lời; (5) `ollama pull` hai model, in `ollama list` + `ollama --version`, **dừng** nếu mã model khác Ràng buộc chung; (6) `pip install -r requirements.txt`; (7) ô chạy có biến `SPLIT`, `TAG`, `NOISE_GUIDANCE`, `TOOLS` → `python eval_real/run_combined_eval.py --set full --split $SPLIT --tools $TOOLS --tag $TAG --no-gpu-guard --out /content/drive/MyDrive/DACN_colab/combined_results_$TAG.csv` (CSV nằm trên Drive để chạy tiếp được).
- [ ] **Bước 6:** `.venv/Scripts/python.exe eval_real/colab_pack.py` → in danh sách; xác nhận zip không có `.evtx`, `_anon_map.json`, `.env`, `*.pem`.
- [ ] **Bước 7:** `git diff --stat` (không commit).

### Task 6: Giai đoạn chỉnh (dev) trên Colab rồi khoá

**Files:** có thể sửa `core/analyze.py` (chỉ câu chữ `EXTENDED_SIGNS` nhóm mới); Create `eval_real/prompt_freeze.json`

- [ ] **Bước 1: Cổng:** người dùng xác nhận Lâm đồng ý đưa log ẩn danh lên Google. Chưa có → dừng.
- [ ] **Bước 2:** đọc skill `anthropic-skills:chrome-browser`; mở tab mới `https://colab.research.google.com`, tạo notebook từ `colab_run.ipynb` (tải lên), chọn runtime GPU T4. Người dùng bấm cho phép Drive.
- [ ] **Bước 3:** tải `colab_pack.zip` lên `/content`, chạy ô 1–6. Mã model phải khớp.
- [ ] **Bước 4: Vòng 1:** ô 7 với `SPLIT=dev, TOOLS=qwen,llama, TAG=full_dev1, NOISE_GUIDANCE=1`. Bị ngắt → chạy lại ô 3–7.
- [ ] **Bước 5:** tải CSV về (hỏi người dùng trước khi tải), đọc ca dev bị ALERT / UNKNOWN cùng sự kiện của nó. Sửa câu chữ hướng dẫn **tổng quát** (không tên phần mềm, không chuỗi riêng của ca). Chạy lại test Task 2.
- [ ] **Bước 6: Vòng 2 (nếu có sửa):** ghi các ca bị ALERT / UNKNOWN ở vòng 1 vào `eval_real/dev_round2.txt`, đóng gói lại (kèm file này), chạy ô 7 thêm `--only eval_real/dev_round2.txt` (`TAG=full_dev2`). Tối đa 2 vòng.
- [ ] **Bước 7: Khoá:** ghi `eval_real/prompt_freeze.json` = `{ "frozen_at": ISO, "analyze_sha256": sha256 của core/analyze.py, "prompt_fingerprint": prompt_fingerprint(), "ollama_colab": phiên bản, "gpu": tên GPU }`. Từ đây **không sửa `core/analyze.py`**. Đóng gói lại lần cuối.
- [ ] **Bước 8:** `git diff --stat`; báo người dùng số liệu dev (chỉ để tham khảo, không đưa vào kết quả chính).

### Task 7: Kiểm tra + đối chứng + ca tấn công trên Colab

- [ ] **Bước 1:** trên Colab, xác nhận `sha256(core/analyze.py)` trong gói = `prompt_freeze.json`.
- [ ] **Bước 2:** ô 7 lần lượt (mỗi lượt một CSV trên Drive):
  - `SPLIT=test, TOOLS=qwen,llama, TAG=full_test, NOISE_GUIDANCE=1` — gồm cả 19 ca `_full` (với `split=test`, `load_cases` kèm ca tấn công).
  - `SPLIT=test, TOOLS=qwen,llama, TAG=full_base, NOISE_GUIDANCE=0`.
- [ ] **Bước 3:** hỏi người dùng rồi tải hai CSV về `eval_real/`. Dừng runtime Colab (`Runtime → Disconnect and delete runtime`) để khỏi tốn đơn vị tính.
- [ ] **Bước 4:** trên laptop: `.venv/Scripts/python.exe eval_real/run_combined_eval.py --set full --split test --tools rules,sigma --tag full_test` (ghi thêm vào cùng CSV).

### Task 8: DeepBlueCLI, Hayabusa, báo cáo

**Files:** Output `eval_real/deepblue_results_full_test.csv`, `eval_real/hayabusa_results_full_test.csv`, `eval_real/SO_SANH_TOAN_BO_LOG_full_test.md`; Modify `md/DIEM_YEU_VA_HUONG_PHAT_TRIEN.md` (thêm một đoạn kết quả).

- [ ] **Bước 1:** `powershell -ExecutionPolicy Bypass -File eval_real\run_deepblue.ps1 -NormalDir eval_real\cases\_full_evtx -NormalCategory normal_full -OutCsv eval_real\deepblue_results_full_test.csv`
- [ ] **Bước 2:** `.venv/Scripts/python.exe eval_real/run_hayabusa.py --normal-dir eval_real/cases/_full_evtx --normal-category normal_full --out eval_real/hayabusa_results_full_test.csv`
- [ ] **Bước 3:** `.venv/Scripts/python.exe eval_real/run_combined_eval.py --report --set full --tag full_test --deepblue eval_real/deepblue_results_full_test.csv --hayabusa eval_real/hayabusa_results_full_test.csv --baseline eval_real/combined_results_full_base.csv`
- [ ] **Bước 4: Kiểm báo cáo:** có phễu số liệu, mã băm prompt, số `NOISE_ONLY`, danh sách ca bị loại, khoảng tin cậy, so sánh có / không hướng dẫn, so với lượt 24/11 (ghi "khác máy"), mục Hạn chế (mục 8 thiết kế).
- [ ] **Bước 5:** chạy toàn bộ test lần cuối → `OK`. `git status` + `git diff --stat`; đưa người dùng lệnh commit (không tự commit).
