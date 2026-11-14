@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
title WinLog AI SOC - Demo 0: Benign Normal Traffic

if not exist "%~dp0simulate_attack.ps1" (
    echo [!] LOI: Thieu file simulate_attack.ps1 trong thu muc %~dp0!
    echo Vui long copy file simulate_attack.ps1 vao cung thu muc!
    pause
    exit /b
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0simulate_attack.ps1" -Demo 0

echo.
pause
