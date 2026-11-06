@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul
cd /d "%~dp0"

echo ====================================================================
echo   DANG DUNG TIEN TRINH WINLOG CLIENT AGENT CHAY NGAM...
echo ====================================================================
echo.

set KILLED=0
if exist "%~dp0client_agent.pid" (
    set /p AGENT_PID=<"%~dp0client_agent.pid"
    if defined AGENT_PID (
        taskkill /F /PID !AGENT_PID! >nul 2>&1
        if !errorlevel! equ 0 (
            echo   [OK] Da tat tien trinh Agent (PID: !AGENT_PID!) thanh cong.
            set KILLED=1
        )
    )
    del "%~dp0client_agent.pid" >nul 2>&1
)

if !KILLED! equ 0 (
    echo   [*] Khong tim thay tien trinh Agent nao dang chay.
)

echo.
echo ====================================================================
echo   HOAN TAT.
echo ====================================================================
ping 127.0.0.1 -n 3 >nul
exit