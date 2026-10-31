@echo off
setlocal
chcp 65001 >nul

cd /d "%~dp0"
cls
echo ====================================================================
echo   KHOI DONG WINLOG AI SERVER (192.168.153.1:8000)
echo ====================================================================
echo   Server san sang nhan log tu Client 192.168.153.147
echo   va tu dong canh bao qua Telegram khi phat hien tan cong.
echo ====================================================================
echo.

.\.venv\Scripts\python.exe -m uvicorn app:app --host 0.0.0.0 --port 8000

echo.
pause
