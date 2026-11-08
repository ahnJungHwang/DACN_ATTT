@echo off
setlocal
chcp 65001 >nul

cd /d "%~dp0"
cls
echo ====================================================================
echo   KHOI DONG WINLOG AI SERVER QUA HTTPS (PORT 9443)
echo ====================================================================
echo   Server lang nghe an toan qua SSL/TLS:
echo   https://0.0.0.0:9443
echo   (Su dung cert.pem va key.pem)
echo ====================================================================
echo.

.\.venv\Scripts\python.exe -m uvicorn app:app --host 0.0.0.0 --port 9443 --ssl-keyfile key.pem --ssl-certfile cert.pem

echo.
pause
