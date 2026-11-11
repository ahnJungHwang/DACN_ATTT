# Báo cáo độ trễ cảnh báo & chống trùng — WinLog AI SOC

- **Phiên đo:** 11/11 23:27:33 → 12/11 00:08:29 (giờ máy server) · máy client: DESKTOP-D38O4BR
- **Số lô log:** 54 · trong đó 344 sự kiện Security / 471 sự kiện tổng
- **Mô hình:** qwen · luồng: n8n
- **Lệch đồng hồ client − server (đã bù):** 192.168.153.147: +0.377 s

## 1. Độ trễ đầu-cuối (giây) — trung vị / P95 / lớn nhất

| Nhóm | Số lô | Sự kiện đầu → cảnh báo | Sự kiện cuối → cảnh báo |
|---|---:|---:|---:|
| **Cảnh báo đã gửi Telegram** | 13 | 23.7 / 32.9 / 33.9 | 12.6 / 27.2 / 27.9 |
| ALERT bị chặn vì trùng | 23 | 18.3 / 27.6 / 28.6 | 11.6 / 21.3 / 22.5 |
| NORMAL (không cảnh báo) | 17 | 19.4 / 32.2 / 34.7 | 14.5 / 30.4 / 31.6 |
| Tất cả các lô (vận hành bình thường) | 53 | 20.3 / 31.9 / 34.7 | 12.5 / 28.5 / 31.6 |
| *Lô tồn đọng do server ngừng (không tính ở trên)* | 1 | 378.0 / 378.0 / 378.0 | 261.9 / 261.9 / 261.9 |

> 1 lô có sự kiện phải chờ ở client > 60 s vì server tạm ngừng (agent giữ lại rồi gửi bù khi server chạy lại — không mất log). Đây không phải độ trễ khi vận hành bình thường nên được tách riêng; chi tiết đánh dấu ⚠ ở mục 3.

## 2. Phân rã độ trễ theo từng chặng (giây) — trung vị / P95 / lớn nhất

| Nhóm | ① Client gom & gửi | ② Truyền tải | ③ n8n gọi lại | ④ AI phân tích | ⑤ n8n + Telegram |
|---|---:|---:|---:|---:|---:|
| **Cảnh báo đã gửi Telegram** | 3.6 / 13.5 / 15.9 | 0.0 / 4.9 / 12.1 | 0.1 / 0.1 / 0.1 | 8.3 / 14.1 / 14.4 | 0.8 / 1.1 / 1.3 |
| ALERT bị chặn vì trùng | 4.1 / 7.4 / 12.3 | 0.0 / 0.0 / 0.1 | 0.1 / 0.1 / 0.1 | 7.7 / 14.0 / 14.9 | 0.0 / 0.0 / 0.0 |
| NORMAL (không cảnh báo) | 6.5 / 20.9 / 24.2 | 0.0 / 12.1 / 12.1 | 0.1 / 0.1 / 0.1 | 5.8 / 8.5 / 10.7 | 0.0 / 0.0 / 0.0 |

Tỉ trọng trung bình của từng chặng trong một cảnh báo đã gửi: ① Client gom & gửi **31%** · ② Truyền tải **6%** · ③ n8n gọi lại **0%** · ④ AI phân tích **58%** · ⑤ n8n + Telegram **5%**

## 3. Chi tiết từng cảnh báo đã gửi Telegram

| # | Giờ nhận (server) | Kỹ thuật MITRE | Trạng thái | Sự kiện (Security) | ① Gom | ④ AI | ⑤ Telegram | **Sự kiện đầu → cảnh báo** | Sự kiện cuối → cảnh báo |
|---:|---|---|---|---:|---:|---:|---:|---:|---:|
| 1 | 11/11 23:28:57 | T1059.001 | NEW | 10 (7) | 6.679 | 14.398 | 0.953 | **25.347** | 22.126 |
| 2 | 11/11 23:29:19 | T1098/T1136 | NEW | 11 (10) | 5.3 | 8.498 | 0.911 | **29.942** | 14.845 |
| 3 | 11/11 23:30:23 | T1110 | NEW | 5 (4) | 1.049 | 7.285 | 0.876 | **10.166** | 9.268 |
| 4 | 11/11 23:32:06 | T1033 | NEW_TECHNIQUE | 7 (3) | 5.424 | 6.291 | 0.76 | **19.519** | 12.559 |
| 5 | 11/11 23:43:44 ⚠ tồn đọng | powershell execution | NEW | 38 (36) | 241.766 | 12.055 | 0.951 | **377.958** | 261.942 |
| 6 | 11/11 23:44:03 | tạo tiến trình mới | NEW | 10 (9) | 1.102 | 9.093 | 0.911 | **27.716** | 11.185 |
| 7 | 11/11 23:44:33 | T1059.001 | NEW | 16 (7) | 3.199 | 13.975 | 0.756 | **32.24** | 18.015 |
| 8 | 11/11 23:44:56 | T1110; T1033 | NEW | 10 (7) | 2.661 | 7.779 | 0.781 | **17.142** | 11.311 |
| 9 | 11/11 23:45:11 | T1098/T1136 | NEW_TECHNIQUE | 8 (6) | 4.029 | 7.14 | 0.752 | **22.057** | 12.009 |
| 10 | 12/11 00:00:14 | powershell scriptblock execution | NEW | 12 (11) | 11.952 | 13.39 | 1.281 | **31.097** | 26.837 |
| 11 | 12/11 00:00:35 | T1059.001 | NEW | 16 (7) | 15.91 | 11.066 | 0.779 | **33.909** | 27.853 |
| 12 | 12/11 00:01:05 | T1098/T1136 | NEW | 5 (4) | 2.32 | 8.263 | 0.802 | **23.725** | 23.562 |
| 13 | 12/11 00:01:36 | T1110 | NEW | 5 (4) | 1.799 | 8.094 | 0.737 | **11.568** | 10.683 |
| 14 | 12/11 00:01:51 | T1033 | NEW_TECHNIQUE | 11 (7) | 3.636 | 8.006 | 0.762 | **23.053** | 12.47 |

## 4. Chống trùng cảnh báo

| Chỉ số | Giá trị |
|---|---:|
| Số kết luận ALERT của AI | 37 |
| Gửi Telegram (sự cố mới / có kỹ thuật mới) | 14 |
| **Bị chặn vì trùng** (cùng máy + cùng kỹ thuật trong cửa sổ) | **23** |
| Tỉ lệ cảnh báo trùng được chặn | 62% |
| Số sự cố riêng biệt (máy + kỹ thuật MITRE) | 14 |
| Cửa sổ gom trùng | 10.0 phút (trượt) |

## 5. Cách đọc số liệu

- **Sự kiện đầu → cảnh báo**: từ lúc Windows ghi sự kiện SỚM nhất của lô (đồng hồ máy client, đã bù lệch) tới lúc node Telegram trong n8n gửi xong (n8n chỉ trả lời server sau node cuối cùng). Đây là con số chính.
- **Sự kiện cuối → cảnh báo**: tính từ sự kiện MUỘN nhất của lô (thường là bước tấn công cuối cùng).
- ① **Client gom & gửi**: agent quét log mỗi 5 s và gửi tuần tự; sự kiện sinh ra trong lúc agent đang chờ server trả lời lô trước sẽ phải đợi tới lô sau.
- ② **Truyền tải**: mạng + bắt tay HTTPS + hàng đợi, sau khi đã bù lệch đồng hồ.
- ③ **n8n gọi lại**: server -> webhook n8n -> n8n gọi lại /ingest.
- ④ **AI phân tích**: bộ luật tương quan + mô hình Ollama local.
- ⑤ **n8n + Telegram**: node IF + gọi Telegram Bot API. Cảnh báo trùng không gọi Telegram nên chặng này ≈ 0.
