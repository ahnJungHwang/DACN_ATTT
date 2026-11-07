@echo off
setlocal
chcp 65001 >nul

"%SystemRoot%\System32\whoami.exe" /groups | find "S-1-16-12288" >nul 2>&1
if %errorlevel% neq 0 (
    echo ====================================================================
    echo   [!] CANH BAO: BAN CHUA MO BANG QUYEN ADMINISTRATOR!
    echo ====================================================================
    echo   Vui long click chuot phai vao file nay va chon "Run as administrator".
    pause
    exit /b
)

echo ====================================================================
echo   DANG BAT CHINH SACH GHI LOG AUDIT CUA WINDOWS CHO CLIENT
echo ====================================================================
echo.

echo [1/7] Bat ghi nhan Process Creation...
auditpol /set /subcategory:"Process Creation" /success:enable

echo [2/7] Bat ghi nhan Logon / Logoff...
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

echo [3/7] Bat ghi lai CommandLine trong Event 4688...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

echo [4/7] Bat ghi nhan ScriptBlock trong PowerShell Event 4104...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

echo [5/7] Bat ghi nhan tao / sua tai khoan (Event 4720)...
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable

echo [6/7] Bat ghi nhan thay doi nhom bao mat (Event 4728, 4732)...
auditpol /set /subcategory:"Security Group Management" /success:enable

echo [7/7] Bat ghi nhan tao Scheduled Task (Event 4698)...
auditpol /set /subcategory:"Other Object Access Events" /success:enable

echo     (Event 1102, 104, 7045 Windows luon tu ghi, khong can bat them)

echo.
gpupdate /force >nul 2>&1

echo ====================================================================
echo   [✓] CAU HINH HOAN TAT! MAY CLIENT DA SAN SANG THU THAP LOG.
echo ====================================================================
echo.
pause
