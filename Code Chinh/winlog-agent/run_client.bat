@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
title WinLog Client Agent (AI SOC)

:: ====================================================================
:: CAU HINH URL AI SERVER VA THAM SO HOAT DONG
:: ====================================================================
set SERVER_URL=https://192.168.147.1:8443/ingest
set INTERVAL=5
set MODEL=qwen

:: Kiem tra quyen Administrator
"%SystemRoot%\System32\whoami.exe" /groups | find "S-1-16-12288" >nul 2>&1
if %errorlevel% neq 0 (
    echo ====================================================================
    echo   [!] LUU Y: DANG CHAY VOI QUYEN USER THUONG
    echo ====================================================================
    echo   - Agent van se hoat dong va bat cac lenh PowerShell tan cong - Event 4104.
    echo   - De doc duoc ca Security Log - Event 4688, 4624 - ban nen:
    echo     Click chuot phai vao file nay va chon "Run as administrator".
    echo ====================================================================
    echo.
    ping 127.0.0.1 -n 3 >nul
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0client_agent.ps1" -ServerUrl "%SERVER_URL%" -IntervalSeconds %INTERVAL% -Model "%MODEL%"

echo.
echo ====================================================================
echo   AGENT DA DUNG. CUA SO SE DUOC GIU NGUYEN DE XEM THONG BAO.
echo ====================================================================
pause