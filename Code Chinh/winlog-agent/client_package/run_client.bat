@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
title WinLog Client Agent (AI SOC)

:: Security Log can quyen Administrator -> tu xin nang quyen neu dang chay quyen thuong
net session >nul 2>&1
if %errorlevel% equ 0 goto :RUN_ADMIN
echo [*] Dang yeu cau quyen Administrator de thu thap day du Security Log...
powershell.exe -NoProfile -Command "Start-Process cmd.exe -ArgumentList '/k \"\"%~f0\"\"' -Verb runas"
exit /b

:RUN_ADMIN
set SERVER_URL=https://192.168.153.1:8443/ingest
set INTERVAL=5
set MODEL=qwen

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0client_agent.ps1" -ServerUrl "%SERVER_URL%" -IntervalSeconds %INTERVAL% -Model "%MODEL%"

echo.
echo ====================================================================
echo   AGENT DA DUNG. CUA SO SE DUOC GIU NGUYEN DE XEM THONG BAO.
echo ====================================================================
pause
