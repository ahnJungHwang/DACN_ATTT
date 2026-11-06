@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
title WinLog AI SOC - Export Docker n8n Image

echo ====================================================================
echo   DONG GOI CONTAINER DOCKER N8N THANH FILE .TAR PORTABLE
echo ====================================================================
echo.

echo [*] Buoc 1/2: Chup lai trang thai hien tai cua container n8n...
docker commit n8n winlog-n8n:latest
if %errorlevel% neq 0 (
    echo [!] Khong the commit container 'n8n'. Hay kiem tra container co dang ton tai khong.
    pause
    exit /b
)

echo.
echo [*] Buoc 2/2: Xuat Image ra file winlog-n8n-docker.tar...
echo (Qua trinh nay co the mat 1-2 phut, vui long cho...)
docker save -o "%~dp0winlog-n8n-docker.tar" winlog-n8n:latest
if %errorlevel% neq 0 (
    echo [!] Xuat file .tar that bai!
    pause
    exit /b
)

echo.
echo ====================================================================
echo   [OK] DONG GOI N8N THANH CONG!
echo   File da duoc luu tai: %~dp0winlog-n8n-docker.tar
echo ====================================================================
echo.
pause
