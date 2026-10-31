@echo off
setlocal
title WinLog Attack Simulation Runner

:: Kiem tra quyen Administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    cls
    echo ====================================================================
    echo   [!] CANH BAO: BAN CHUA MO BANG QUYEN ADMINISTRATOR!
    echo ====================================================================
    echo.
    echo   De trich xuat duoc day du Security Event Log (su kien 4624, 4625, 4688),
    echo   Windows bat buoc phai chay script voi quyen Administrator.
    echo.
    echo   HUONG DAN CHAY:
    echo   1. Dong cua so nay lai.
    echo   2. Click chuot phai vao file 'run_demo.bat' nay.
    echo   3. Chon 'Run as administrator' (Chay voi quyen quan tri vien).
    echo.
    echo ====================================================================
    pause
    exit /b
)

cd /d "%~dp0"
cls
echo ====================================================================
echo   DANG CHAY KICH BAN VOI QUYEN ADMINISTRATOR
echo ====================================================================
powershell.exe -NoProfile -ExecutionPolicy Bypass -NoExit -File "%~dp0run_demo.ps1"

echo.
echo ====================================================================
echo   CHUONG TRINH DA KET THUC. CUA SO NAY SE DUOC GIU NGUYEN.
echo ====================================================================
pause
