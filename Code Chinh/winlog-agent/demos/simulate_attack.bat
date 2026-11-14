@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
title WinLog AI SOC - Attack Simulator

if not exist "%~dp0simulate_attack.ps1" (
    echo ====================================================================
    echo   [!] LOI: THIEU FILE simulate_attack.ps1 TRONG THU MUC!
    echo ====================================================================
    echo   Thu muc hien tai: %~dp0
    echo   Khong tim thay file: simulate_attack.ps1
    echo.
    echo   HUONG DAN XU LY:
    echo   Vui long copy file 'simulate_attack.ps1' vao cung thu muc voi file .bat!
    echo ====================================================================
    pause
    exit /b
)

net session >nul 2>&1
if %errorlevel% equ 0 goto :RUN_ADMIN

echo [*] Dang yeu cau quyen Administrator de mo phong day du su kien...
powershell.exe -NoProfile -Command "Start-Process powershell.exe -ArgumentList '-NoProfile -ExecutionPolicy Bypass -NoExit -File \"\"%~dp0simulate_attack.ps1\"\" %*' -Verb runas"
exit /b

:RUN_ADMIN
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0simulate_attack.ps1" %*

echo.
echo ====================================================================
echo   KET THUC PHIEN MO PHONG TAN CONG.
echo ====================================================================
pause
