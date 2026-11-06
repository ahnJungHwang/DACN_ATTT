@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
title WinLog AI SOC - Import Docker n8n Image

echo ====================================================================
echo   KHOI PHUC CONTAINER DOCKER N8N TU FILE .TAR PORTABLE
echo ====================================================================
echo.

if not exist "%~dp0winlog-n8n-docker.tar" (
    echo [!] Khong tim thay file winlog-n8n-docker.tar trong thu muc nay!
    pause
    exit /b
)

echo [*] Buoc 1/2: Dang nap Image tu file .tar vao Docker...
echo (Qua trinh nay mat khoang 30-60 giay...)
docker load -i "%~dp0winlog-n8n-docker.tar"
if %errorlevel% neq 0 (
    echo [!] Khong the load image vao Docker! Hay dam bao Docker Desktop dang bat.
    pause
    exit /b
)

echo.
echo [*] Buoc 2/2: Dang khoi dong Container n8n (Port 5679)...
docker rm -f n8n >nul 2>&1
docker run -d --name n8n -p 5679:5678 --restart unless-stopped winlog-n8n:latest
if %errorlevel% neq 0 (
    echo [!] Khoi dong container that bai!
    pause
    exit /b
)

echo.
echo ====================================================================
echo   [OK] KHOI PHUC VA KHOI DONG N8N THANH CONG!
echo   Dia chi truy cap: http://localhost:5679
echo ====================================================================
echo.
pause
