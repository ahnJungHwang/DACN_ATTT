@echo off
setlocal
chcp 65001 >nul

cd /d "%~dp0"
:: Nap bien moi truong tu .env (OLLAMA_URL, N8N_WEBHOOK_URL, TELEGRAM_*, APP_MODULE)
if exist "%~dp0.env" for /f "usebackq eol=# tokens=1,* delims==" %%A in ("%~dp0.env") do set "%%A=%%B"
if not defined APP_MODULE set APP_MODULE=app

cls
echo ====================================================================
echo   KHOI DONG WINLOG AI SERVER (192.168.147.1:8000)
echo ====================================================================
echo   Server san sang nhan log tu Client 192.168.147.136
echo   va tu dong canh bao qua Telegram khi phat hien tan cong.
echo   * Giao dien Web SOC Dashboard: http://localhost:8000/dashboard
echo   * Tai lieu Swagger API       : http://localhost:8000/docs
echo ====================================================================
echo.

.\.venv\Scripts\python.exe -m uvicorn %APP_MODULE%:app --host 0.0.0.0 --port 8000

echo.
pause
