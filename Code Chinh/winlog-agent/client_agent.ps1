[CmdletBinding()]
param(
    [string]$ServerUrl = "https://192.168.147.1:8443/ingest",
    [int]$IntervalSeconds = 5,
    [string]$Model = "qwen",
    [string]$LogFile = "$PSScriptRoot\client_agent.log"
)

# 1. Dam bao tham so luon hop le, khong bao gio bi null
if (-not $IntervalSeconds -or $IntervalSeconds -le 0) {
    $IntervalSeconds = 5
}
if (-not $ServerUrl) {
    $ServerUrl = "https://192.168.147.1:8443/ingest"
}

# 2. Bo qua loi SSL khi dung HTTPS Self-Signed Certificate
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# 3. Lay thong tin Hostname va IP Client
$hostname = $env:COMPUTERNAME
$clientIp = "127.0.0.1"
try {
    $ips = [System.Net.Dns]::GetHostAddresses([System.Net.Dns]::GetHostName()) | 
           Where-Object { $_.AddressFamily -eq 'InterNetwork' -and $_.IPAddressToString -notlike "127.*" -and $_.IPAddressToString -notlike "169.254*" }
    if ($ips -and $ips.Count -gt 0) {
        $clientIp = $ips[0].IPAddressToString
    }
} catch {
    $clientIp = "127.0.0.1"
}

# 4. Kiem tra quyen Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# 5. Ham ghi log ra file
function Write-AgentLog {
    param([string]$Message)
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $logLine = "[$ts] $Message"
    if ($LogFile) {
        try {
            Add-Content -Path $LogFile -Value $logLine -Encoding UTF8 -ErrorAction SilentlyContinue
        } catch {}
    }
}

# Giao dien Banner ban dau
Clear-Host
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host "      WINLOG CLIENT AGENT - HE THONG THU THAP LOG VE AI SOC         " -ForegroundColor Cyan
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host "  * Target AI Server : $ServerUrl" -ForegroundColor White
Write-Host "  * May Client       : $hostname ($clientIp)" -ForegroundColor White
Write-Host "  * Chu ky kiem tra  : ${IntervalSeconds}s / lan" -ForegroundColor White
Write-Host "  * Quyen Admin      : $(if ($isAdmin) { 'CO (Doc day du Security + PowerShell Log)' } else { 'KHONG (Chi doc PowerShell Log)' })" -ForegroundColor $(if ($isAdmin) { 'Green' } else { 'Yellow' })
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host "[+] Agent dang giam sat em ru (KHONG sinh log lien tuc ra man hinh)." -ForegroundColor Green
Write-Host "[+] Chi khi co su kien moi phat sinh thi moi hien thi thong bao." -ForegroundColor Green
Write-Host "[*] Ban co the thu nho (minimize) cua so nay xuong Taskbar de lam viec." -ForegroundColor Gray
Write-Host "--------------------------------------------------------------------`n" -ForegroundColor DarkGray

Write-AgentLog "Client Agent khoi dong. Host: $hostname ($clientIp), Server: $ServerUrl, Admin: $isAdmin"

$lastSeenTime = (Get-Date).AddSeconds(-15)
$lastSecRecord = [long]0
$lastPsRecord = [long]0
$lastSysRecord = [long]0

# Ma su kien thu thap
#  Security: 4624/4625/4648 dang nhap, 4688 tao tien trinh, 1102 xoa nhat ky,
#            4720 tao tai khoan, 4728/4732 them vao nhom, 4698 tao scheduled task
#  System  : 7045 cai service moi, 104 xoa nhat ky System
$SecurityIds = 4624, 4625, 4648, 4688, 1102, 4720, 4728, 4732, 4698
$SystemIds = 7045, 104

# Vong lap giam sat
while ($true) {
    try {
        $secEvents = @()
        $psEvents = @()
        $sysEvents = @()

        # 1. Quet Security Log neu co quyen Admin
        if ($isAdmin) {
            try {
                $secFilter = @{
                    LogName   = 'Security'
                    Id        = $SecurityIds
                    StartTime = $lastSeenTime
                }
                # Loc theo RecordId de khong gui lai su kien da gui (StartTime khong du chinh xac)
                $secEvents = @(Get-WinEvent -FilterHashtable $secFilter -ErrorAction SilentlyContinue |
                               Where-Object { $_.RecordId -gt $lastSecRecord })
            } catch {}
        }

        # 2. Quet PowerShell Log (4104)
        try {
            $psFilter = @{
                LogName   = 'Microsoft-Windows-PowerShell/Operational'
                Id        = 4104
                StartTime = $lastSeenTime
            }
            $psEvents = @(Get-WinEvent -FilterHashtable $psFilter -ErrorAction SilentlyContinue |
                          Where-Object { $_.RecordId -gt $lastPsRecord })
        } catch {}

        # 3. Quet System Log (7045 cai service, 104 xoa nhat ky) - doc duoc ca khi khong co quyen Admin
        try {
            $sysFilter = @{
                LogName   = 'System'
                Id        = $SystemIds
                StartTime = $lastSeenTime
            }
            $sysEvents = @(Get-WinEvent -FilterHashtable $sysFilter -ErrorAction SilentlyContinue |
                           Where-Object { $_.RecordId -gt $lastSysRecord })
        } catch {}

        $totalNew = $secEvents.Count + $psEvents.Count + $sysEvents.Count

        # CHI IN VA GUI KHI CO SU KIEN MOI (KHONG SPAM KHI KHONG CO GI)
        if ($totalNew -gt 0) {
            $nowStr = (Get-Date).ToString("HH:mm:ss")
            Write-Host "[$nowStr] [PHAT HIEN] $totalNew su kien moi (Security: $($secEvents.Count), PowerShell: $($psEvents.Count), System: $($sysEvents.Count))" -ForegroundColor Yellow
            Write-Host "  -> Dang dong goi va gui ve AI Server ($ServerUrl)..." -ForegroundColor Cyan

            # Chuyen sang XML
            if ($secEvents.Count -gt 0) {
                $secXml = '<Events>' + (($secEvents | ForEach-Object { $_.ToXml() }) -join '') + '</Events>'
            } else {
                $secXml = '<Events></Events>'
            }

            if ($psEvents.Count -gt 0) {
                $psXml = '<Events>' + (($psEvents | ForEach-Object { $_.ToXml() }) -join '') + '</Events>'
            } else {
                $psXml = '<Events></Events>'
            }

            if ($sysEvents.Count -gt 0) {
                $sysXml = '<Events>' + (($sysEvents | ForEach-Object { $_.ToXml() }) -join '') + '</Events>'
            } else {
                $sysXml = '<Events></Events>'
            }

            # Cap nhat moc: RecordId lon nhat da gui cho tung log + moc thoi gian (lui 2s lam vung dem)
            $maxTime = $lastSeenTime
            foreach ($e in $secEvents) {
                if ($e.TimeCreated -gt $maxTime) { $maxTime = $e.TimeCreated }
                if ($e.RecordId -gt $lastSecRecord) { $lastSecRecord = $e.RecordId }
            }
            foreach ($e in $psEvents) {
                if ($e.TimeCreated -gt $maxTime) { $maxTime = $e.TimeCreated }
                if ($e.RecordId -gt $lastPsRecord) { $lastPsRecord = $e.RecordId }
            }
            foreach ($e in $sysEvents) {
                if ($e.TimeCreated -gt $maxTime) { $maxTime = $e.TimeCreated }
                if ($e.RecordId -gt $lastSysRecord) { $lastSysRecord = $e.RecordId }
            }
            $lastSeenTime = $maxTime.AddSeconds(-2)

            $payloadObj = @{
                client_id      = $clientIp
                hostname       = $hostname
                security_xml   = $secXml
                powershell_xml = $psXml
                system_xml     = $sysXml
                model          = $Model
            }
            $payloadJson = $payloadObj | ConvertTo-Json -Depth 5

            try {
                $resp = Invoke-RestMethod -Uri $ServerUrl -Method POST -ContentType "application/json; charset=utf-8" -Body ([System.Text.Encoding]::UTF8.GetBytes($payloadJson)) -TimeoutSec 300
                Write-Host "  [OK] Da day thanh cong len AI Server!`n" -ForegroundColor Green
                Write-AgentLog "[OK] Da day $totalNew su kien len AI Server thanh cong."
            } catch {
                Write-Host "  [LOI GUI] Khong the gui du lieu toi Server: $($_.Exception.Message)`n" -ForegroundColor Red
                Write-AgentLog "[ERROR] Khong the gui du lieu toi Server ($ServerUrl): $($_.Exception.Message)"
            }
        } else {
            # Khong co su kien moi: Tuyet doi KHONG in gi ra man hinh de man hinh dung yen sach se!
            if ((Get-Date).AddSeconds(-15) -gt $lastSeenTime) {
                $lastSeenTime = (Get-Date).AddSeconds(-15)
            }
        }
    } catch {
        # Bat loi de vong lap khong bao gio dung
    }

    Start-Sleep -Seconds $IntervalSeconds
}