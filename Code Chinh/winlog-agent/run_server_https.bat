@echo off
setlocal
chcp 65001 >nul

cd /d "%~dp0"
:: Nap bien moi truong tu .env (OLLAMA_URL, N8N_WEBHOOK_URL, TELEGRAM_*, APP_MODULE)
if exist "%~dp0.env" for /f "usebackq eol=# tokens=1,* delims==" %%A in ("%~dp0.env") do set "%%A=%%B"
if not defined APP_MODULE set APP_MODULE=app

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

.\.venv\Scripts\python.exe -m uvicorn %APP_MODULE%:app --host 0.0.0.0 --port 8443 --ssl-keyfile key.pem --ssl-certfile cert.pem

echo.
pause
