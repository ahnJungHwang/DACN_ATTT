@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul
cd /d "%~dp0.."

echo ====================================================================
echo   DANG DUNG TIEN TRINH WINLOG CLIENT AGENT CHAY NGAM...
echo ====================================================================
echo.

:: Doc PID tu client_agent.pid (client_agent.ps1 ghi luc khoi dong), kiem tra dung la Agent roi moi tat.
:: Neu khong co file .pid thi tim Agent theo dong lenh. Chi tiet: ps1\stop_client.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\ps1\stop_client.ps1"

echo.
echo ====================================================================
echo   HOAN TAT.
echo ====================================================================
ping 127.0.0.1 -n 3 >nul
exit