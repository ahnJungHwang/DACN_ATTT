@echo off
setlocal
chcp 65001 >nul

cd /d "%~dp0"
cls

echo ====================================================================
echo   KHOI DONG WINLOG CLIENT AGENT
echo ====================================================================
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0client_agent.ps1" -ServerUrl "http://192.168.153.1:8000/ingest"

echo.
echo ====================================================================
echo   AGENT DA DUNG. CUA SO SE DUOC GIU NGUYEN.
echo ====================================================================
pause
