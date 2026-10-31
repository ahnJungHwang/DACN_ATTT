@echo off
setlocal
chcp 65001 >nul

:: Kiem tra quyen Administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ====================================================================
    echo   [!] CANH BAO: BAN CHUA MO BANG QUYEN ADMINISTRATOR!
    echo ====================================================================
    echo.
    echo   De giam sat duoc Security Event Log (su kien 4624, 4625, 4688),
    echo   Windows bat buoc phai chay script voi quyen Administrator.
    echo.
    echo   HUONG DAN:
    echo   1. Dong cua so nay lai.
    echo   2. Click chuot phai vao file 'run_monitor.bat' nay.
    echo   3. Chon 'Run as administrator' (Chay voi quyen quan tri vien).
    echo.
    echo ====================================================================
    pause
    exit /b
)

cd /d "%~dp0"
cls
echo ====================================================================
echo   KHOI DONG WINLOG AI AGENT - REAL-TIME MONITORING
echo ====================================================================
echo.

.\.venv\Scripts\python.exe realtime_monitor.py

echo.
echo ====================================================================
echo   CHUONG TRINH DA DUNG. CUA SO NAY SE DUOC GIU NGUYEN.
echo ====================================================================
pause
