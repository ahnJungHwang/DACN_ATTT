@echo off
chcp 65001 >nul
cd /d "%~dp0.."
cls

echo ====================================================================
echo   KHOI DONG WINLOG AI SERVER QUA HTTPS - PORT 9443
echo ====================================================================
echo   Server lang nghe tai: https://0.0.0.0:9443
echo ====================================================================
echo.

rem Kiem tra venv co dung duoc tren may nay khong
if not exist ".\.venv\Scripts\python.exe" goto :create_venv
.\.venv\Scripts\python.exe -c "exit()" >nul 2>&1
if errorlevel 1 goto :recreate_venv

goto :start_server

:recreate_venv
echo [*] Phat hien .venv duoc copy tu may khac khong tuong thich.
echo [*] Dang xoa .venv cu de tao lai...
rmdir /s /q ".\.venv"

:create_venv
echo [*] Dang kiem tra Python tren may nay...
where python >nul 2>&1
if errorlevel 1 goto :check_py
set "PY_CMD=python"
goto :do_create

:check_py
where py >nul 2>&1
if errorlevel 1 goto :no_python
set "PY_CMD=py"
goto :do_create

:do_create
echo [OK] Tim thay: %PY_CMD%
echo [*] Dang tao moi truong ao .venv...
%PY_CMD% -m venv .venv
if errorlevel 1 goto :create_failed

echo [*] Dang cai dat thu vien requirements.txt...
.\.venv\Scripts\pip install -r requirements.txt
if errorlevel 1 goto :install_failed
echo [OK] Cai dat hoan tat!
echo.
goto :start_server

:start_server
echo [*] Khoi dong Uvicorn Server tren port 9443...
echo.
.\.venv\Scripts\python.exe -m uvicorn --timeout-graceful-shutdown 3 --app-dir app app:app --host 0.0.0.0 --port 9443 --ssl-keyfile key.pem --ssl-certfile cert.pem
goto :finish

:no_python
echo ====================================================================
echo   [ERROR] MAY NAY CHUA CAI DAT PYTHON!
echo ====================================================================
echo   Vui long cai Python 3.10+ va tick vao "Add Python to PATH".
echo ====================================================================
goto :finish

:create_failed
echo [ERROR] Tao moi truong ao .venv that bai!
goto :finish

:install_failed
echo [ERROR] Cai dat thu vien requirements that bai!
goto :finish

:finish
echo.
pause
exit /b
