@echo off
setlocal
chcp 65001 >nul

cd /d "%~dp0"
cls
echo ====================================================================
echo   KHOI DONG WINLOG AI SERVER (192.168.153.1:8000)
echo ====================================================================
echo   Server san sang nhan log tu Client 192.168.153.147
echo   va tu dong chuyen tiep toi n8n Workflow (Port 5679) de canh bao Telegram.
echo ====================================================================
echo.

.\.venv\Scripts\python.exe -m uvicorn app:app --host 0.0.0.0 --port 8000

echo.
pause
