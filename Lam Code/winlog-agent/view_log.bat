@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"

cls
echo ====================================================================
echo   THEO DOI NHAT KY HOAT DONG (LOG) CUA CLIENT AGENT
echo   (Nhan Ctrl + C de thoat man hinh theo doi)
echo ====================================================================
echo.

if not exist "%~dp0client_agent.log" (
    echo [*] Chua co file log client_agent.log. Vui long click run_client.bat truoc.
    echo.
    pause
    exit /b
)

powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-Content -Path '%~dp0client_agent.log' -Tail 30 -Wait"