@echo off
setlocal
chcp 65001 >nul

cd /d "%~dp0"
cls
echo ====================================================================
echo   KHOI DONG WINLOG AI SERVER QUA HTTPS (PORT 8443)
echo ====================================================================
echo   Server lang nghe an toan qua SSL/TLS:
echo   * Giao dien Web SOC Dashboard: https://localhost:8443/dashboard
echo   * Tai lieu Swagger API       : https://localhost:8443/docs
echo   (Su dung cert.pem va key.pem)
echo ====================================================================
echo.

.\.venv\Scripts\python.exe -m uvicorn app:app --host 0.0.0.0 --port 8443 --ssl-keyfile key.pem --ssl-certfile cert.pem

echo.
pause
