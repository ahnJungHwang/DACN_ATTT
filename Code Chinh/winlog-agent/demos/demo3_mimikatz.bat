@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
title WinLog AI SOC - Demo 3: Mimikatz Credential Dump

if not exist "%~dp0simulate_attack.ps1" (
    echo [!] LOI: Thieu file simulate_attack.ps1 trong thu muc %~dp0!
    echo Vui long copy file simulate_attack.ps1 vao cung thu muc!
    pause
    exit /b
)

net session >nul 2>&1
if %errorlevel% equ 0 goto :RUN_ADMIN

echo [*] Dang yeu cau quyen Administrator...
powershell.exe -NoProfile -Command "Start-Process powershell.exe -ArgumentList '-NoProfile -ExecutionPolicy Bypass -NoExit -File \"\"%~dp0simulate_attack.ps1\"\" -Demo 3' -Verb runas"
exit /b

:RUN_ADMIN
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0simulate_attack.ps1" -Demo 3

echo.
pause
