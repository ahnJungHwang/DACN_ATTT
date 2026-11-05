# Tích hợp toàn luồng trên lần thu VM thật — task 11.1

**Đã nghiệm thu 11.1 ngày 2026-11-04** trên lần thu ngắn `87dba4a5`. Chrome chạy giao diện HTTPS thật, nhập hoặc dùng lại hai XML, tạo ca `0ecbb344-fd22-44f9-82c0-738907f35b2d`, hiển thị 9 tham chiếu, mở XML của whoami và gửi cả hai model. Kết quả giao diện lưu tại `data/acceptance-11.1.json` và `data/acceptance-11.1.png`. Sau khi đo lại 10/10 mẫu tokenizer trên Ollama 0.40.14, Qwen trả ALERT (4,72 giây), Llama trả UNKNOWN/INVALID_MODEL_OUTPUT (10,76 giây). Lượt đầu bị chặn đúng thiết kế vì bộ đếm cũ dùng phiên bản 0.40.13.

Đối chiếu RecordId 8372, 8374, 8376, 8378, 8380: năm lần sai mật khẩu nhắm tới lab_demo, phiên gọi thuộc Admin. RecordId 8383 mở phiên lab_demo 0x6dcd9c. cmd.exe (8384) dùng TargetLogonId của phiên mới, conhost.exe (8385) và whoami.exe (8386) dùng SubjectLogonId cùng phiên. Qwen nhận ra chuỗi hành vi, còn suy đoán nâng quyền chưa có bằng chứng. Llama không cung cấp kết luận hợp lệ. Phần n8n dùng biên bản Docker đã hoàn tất trên cùng lần thu, có đối chiếu tham chiếu và bản xuất cho cả hai model; lượt Chrome mới kiểm đường UI → API qua HTTPS. Các mục dưới ghi lịch sử trước khi chốt.

## Cập nhật đối chiếu ngày 2026-11-04

Biên bản ngày 2026-10-27 bên dưới là lịch sử, không còn mô tả đầy đủ tiến độ. Người dùng đã thu lại kịch bản ngắn và chép thư mục `Thang Code/log-test/20261028-123820-87dba4a5-f76b-4b9c-b107-9052b832fa83` ra máy thật. Không yêu cầu thu lại chỉ vì ca cũ vượt context.

Bằng chứng mới nằm tại `Thang Code/winlog-agent/data/verify-11.1/run-87dba4a5/`:

- `case.json`: ca `463b610f-af8e-447b-b7b5-a7a8251a0a21`, dữ liệu thật, 9 sự kiện, lọc tài khoản `lab_demo`.
- Có bản nhập, sự kiện, yêu cầu/kết quả hai model và bản xuất CSV/JSONL.
- `n8n/summary.json`: `complete=true`, hai model đều qua giới hạn context; Qwen 2650 token, Llama 2094 token, context 4096. Cả hai có `refs_and_export_match=true`.
- Qwen trả ALERT, không lỗi kỹ thuật. Llama trả UNKNOWN với `INVALID_MODEL_OUTPUT`; đây là lỗi đầu ra model được hệ thống xử lý và chuyển nhánh UNKNOWN, cần theo dõi riêng với chất lượng model.
- `ui-20261030.json` lưu hai yêu cầu trạng thái completed và kết quả hai model. File kết quả này không tự chứng minh mọi thao tác trực quan trên trình duyệt đã được nghiệm thu.

Đã có bằng chứng chạy luồng dữ liệu thật qua API và n8n, đối chiếu refs và xuất kết quả. Lý do cũ “chưa có kết quả ca chính do vượt context” đã được giải quyết bằng lần thu ngắn. Trước khi chốt toàn bộ 11.1, cần đối chiếu tiêu chí nghiệm thu gốc với phần kiểm tra giao diện và tài khoản/phiên đã ghi nhận; không đánh đồng việc model trả UNKNOWN với việc chưa chạy tích hợp. Số đếm task trước đây dựa trên tài liệu cũ cần được xác nhận lại theo tiêu chí này.

## Biên bản lịch sử ngày 2026-10-27

Ngày 2026-10-27. Dữ liệu: lần thu `a36f29e9` (xem vm-collection-verification.md). Bằng chứng chi tiết lưu local trong `data/verify-11.1/` (Git ignore). **Task 11.1 chưa đóng**: ca chính của kịch bản vượt context nên chưa có kết quả model để đối chiếu tài khoản/phiên.

## Môi trường

API `app.api --config config.example.toml` ở 127.0.0.1:8000, Ollama 0.40.11, Qwen digest `357c53fb…`, Llama digest `a80c4f17…`, `num_ctx=4096`, `num_predict=512`, dự trữ 256, temperature 0. n8n 2.44.6 (`n8nio/n8n@sha256:d02752c6…`); container n8n hằng ngày gọi được `host.docker.internal:8000` `/health` và `/cases` có token (200).

## Nhập và tạo ca

- Import `e1aacd21-0a65-42de-9b55-ae4742167242`: người dùng tải qua giao diện; hai nguồn `ready`, hash khớp manifest, 157 sự kiện. Gửi lại cùng file trả 409 SOURCE_EXISTS, không nhân đôi.
- POST /cases lọc `lab_demo`, 07:21–07:40 +07:00 tạo hai ca:
  - `d216366b-53af-4126-853a-591754e27f21` (failed_logins, threshold_reached): 19 sự kiện. 6 × 4625 (RecordId 7678–7690) → `login_after_failures` → 4624 RecordId 7696, phiên `0x762f8a` → 4688 powershell/conhost/whoami×2/notepad cùng phiên → 4104 ghép theo PID 6376. Mọi quan hệ `supported`. Khớp kịch bản.
  - `71586e3d-1d6f-41e0-a106-755e974034ee` (successful_login): 4 sự kiện của lần `runas` thứ hai, phiên `0x76bb32`; không có thao tác nào sau khi mở PowerShell.

## Phân tích

| Ca | Model | Đường | result_id | Nhãn | Ghi chú |
|---|---|---|---|---|---|
| d216366b | Qwen | API | 9ec55ccd-841e-4b93-aa22-675beed300dc | UNKNOWN | INPUT_TOO_LARGE, 4938 token > 3328 |
| d216366b | Llama | API | b9b2cdae-fcec-4d98-b985-8f6a76e961c1 | UNKNOWN | INPUT_TOO_LARGE, 3988 token > 3328 |
| 71586e3d | Qwen | API | 0bd2ed94-68c0-45dd-89d5-851bf34c8a03 | ALERT | |
| 71586e3d | Llama | API | d06d7b70-a84e-4611-a489-b4ecc12e8c36 | ALERT | |
| 71586e3d | Qwen | n8n | 11afb518-ae9d-4ab4-bf64-0fb56bce079d | ALERT | nhánh ALERT, lý do giống lượt API |
| 71586e3d | Llama | n8n | d3fdd7ec-da54-42f9-8fcf-fac3fb55c507 | ALERT | nhánh ALERT, lý do giống lượt API |
| d216366b | Qwen | n8n | 5cb3521a-f2f9-45e5-9d11-b9ae71b020e4 | UNKNOWN | nhánh UNKNOWN, technical_error INPUT_TOO_LARGE |

INPUT_TOO_LARGE là hành vi thiết kế (không cắt log, không gọi suy luận). Theo design, người dùng cần thu hẹp phạm vi có ghi nhận.

## Kiểm tra bằng chứng

- Mọi evidence_ref mở được qua GET /events, raw XML có EventRecordID nằm trong file thu gốc, sha256 trong ref khớp nguồn.
- Export JSONL bằng đúng document kết quả; CSV xuất được; GET /requests/{id} trả đúng result_id. Lookup `../secrets/...` trả 404.
- n8n: chạy workflow bàn giao trong container tạm cùng image/digest (không đụng volume n8n hằng ngày, credential tạm đã xóa). result_id, nhãn và evidence_refs của n8n khớp API.

## Đối chiếu sơ bộ (chờ người dùng xác nhận)

Ca 71586e3d theo nhật ký là phiên runas thứ hai của `lab_demo`, chỉ mở PowerShell rồi đóng: dự kiến không độc hại khi xét riêng.

- Qwen: gán đúng tài khoản `lab_demo` và cùng phiên (E001); kết luận ALERT dựa trên `prompt`/conhost là suy diễn, không có bằng chứng độc hại.
- Llama: khẳng định "elevated privileges", không được log hỗ trợ (`lab_demo` là user thường, LogonType 2, không có sự kiện nâng quyền); ALERT là suy diễn.

Cả hai có dấu hiệu cảnh báo nhầm. Đây là quan sát một ca, không phải số đo đánh giá.

## Hạn chế / còn thiếu

- Ca chính d216366b chưa có kết quả model; cần lần thu gọn hơn (ít sự kiện 4104) hoặc quyết định đổi num_ctx có ghi nhận.
- Bước tạo ca/phân tích gọi cùng endpoint giao diện dùng; giao diện trình duyệt chưa được kiểm trên các kết quả này (người dùng đăng nhập ở trình duyệt khác với khung trình duyệt của Claude).
- n8n chạy bằng CLI trong container tạm, chưa chạy từ editor n8n hằng ngày.
