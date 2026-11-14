@echo off
setlocal
chcp 65001 >nul 2>&1
cd /d "%~dp0.."
title WinLog AI SOC - Trinh Dien Demo Thuc Chien

:MENU
cls
echo ====================================================================================
echo   TRINH DIEU PHOI KICH BAN DEMO THUC CHIEN - HE THONG AI SOC WINDOWS
echo ====================================================================================
echo   Mo phong tan cong an toan, sinh log Windows Security ^& PowerShell thuc te
echo   He thong Agent tu dong bat log, gui Server phan tich (Qwen 2.5) va bao Telegram.
echo ====================================================================================
echo.
echo   [0] Demo 0: Tac vu Van phong Lanh tinh (Benign Normal - Thu nghiem chong bao gia)
echo   [1] Demo 1: Do quet Mat khau Brute-Force (MITRE T1110)
echo   [2] Demo 2: PowerShell C2 Download Cradle (MITRE T1059.001)
echo   [3] Demo 3: Trich xuat Mat khau Bo nho LSASS - Mimikatz (MITRE T1003)
echo   [4] Demo 4: Tao Backdoor User ^& Leo thang Quan tri vien (MITRE T1136 / T1098)
echo   [5] Demo 5: Duy tri Xam nhap Khoi dong Registry Run Key (MITRE T1547.001)
echo   [6] Demo 6: Chuoi Tan cong Toan dien APT (Full Cyber Kill Chain)
echo   [7] Khoi chay Attack Simulator nang cao (Tuy chinh tham so)
echo   [8] Mo thu muc chua cac file .bat doc lap (demos\)
echo   [Q] Thoat
echo.
echo ====================================================================================

set /p opt="Vui long chon kich ban [0-8, Q de thoat]: "

if /i "%opt%"=="q" exit /b
if "%opt%"=="0" (
    call "%CD%\demos\demo0_normal_benign.bat"
    goto :MENU
)
if "%opt%"=="1" (
    call "%CD%\demos\demo1_bruteforce.bat"
    goto :MENU
)
if "%opt%"=="2" (
    call "%CD%\demos\demo2_powershell_c2.bat"
    goto :MENU
)
if "%opt%"=="3" (
    call "%CD%\demos\demo3_mimikatz.bat"
    goto :MENU
)
if "%opt%"=="4" (
    call "%CD%\demos\demo4_backdoor_admin.bat"
    goto :MENU
)
if "%opt%"=="5" (
    call "%CD%\demos\demo5_registry_persistence.bat"
    goto :MENU
)
if "%opt%"=="6" (
    call "%CD%\demos\demo6_full_killchain.bat"
    goto :MENU
)
if "%opt%"=="7" (
    call "%CD%\demos\simulate_attack.bat"
    goto :MENU
)
if "%opt%"=="8" (
    explorer "demos"
    goto :MENU
)

echo [!] Lua chon khong hop le, vui long thu lai!
timeout /t 2 >nul
goto :MENU

