@echo off
setlocal
chcp 65001 >nul

cd /d "%~dp0"
cls
echo ====================================================================
echo   CHƯƠNG TRÌNH ĐÁNH GIÁ & SO SÁNH HIỆU NĂNG SLM (QWEN vs LLAMA)
echo ====================================================================
echo   Tự động chạy qua các tập log kiểm thử, đối chiếu kết quả
echo   và xuất báo cáo so sánh chi tiết ra màn hình cùng file CSV.
echo ====================================================================
echo.

if not exist ".venv\Scripts\python.exe" (
    echo [!] Không tìm thấy môi trường Python ảo tại .venv\Scripts\python.exe
    echo     Vui lòng kiểm tra lại môi trường ảo.
    pause
    exit /b 1
)

.\.venv\Scripts\python.exe evaluate.py %*

echo.
echo ====================================================================
echo   ĐÃ HOÀN TẤT ĐÁNH GIÁ!
echo   Báo cáo chi tiết đã được lưu tại thư mục: results\
echo ====================================================================
pause

