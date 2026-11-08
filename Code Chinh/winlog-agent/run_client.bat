@echo off
chcp 65001 >nul
cd /d "%~dp0"
title WinLog Client Agent (AI SOC)

set SERVER_URL=https://192.168.153.1:9443/ingest
set INTERVAL=5
set MODEL=qwen

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0client_agent.ps1" -ServerUrl "%SERVER_URL%" -IntervalSeconds %INTERVAL% -Model "%MODEL%"

echo.
echo ====================================================================
echo   AGENT DA DUNG. CUA SO SE DUOC GIU NGUYEN DE XEM THONG BAO.
echo ====================================================================
pause
