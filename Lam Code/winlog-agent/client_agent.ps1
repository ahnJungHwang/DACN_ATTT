# ==============================================================================
# WINLOG CLIENT AGENT - GUI LOG REAL-TIME VE AI SERVER
# Chay truc tiep tren may Client (192.168.153.147) khong can cai Python!
# ==============================================================================
[CmdletBinding()]
param(
    [string]$ServerUrl = "http://192.168.153.1:8000/ingest",
    [int]$IntervalSeconds = 15
)

$ErrorActionPreference = 'SilentlyContinue'

$hostname = $env:COMPUTERNAME
$clientIp = "192.168.153.147"

# Tim IP noi bo thuc te neu co
try {
    $foundIp = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias "*Ethernet*", "*Wi-Fi*" | Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.*" } | Select-Object -First 1).IPAddress
    if ($foundIp) { $clientIp = $foundIp }
} catch {}

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "   WINLOG CLIENT AGENT - GIAM SAT VA DAY LOG VE SERVER" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " - Client Hostname    : $hostname" -ForegroundColor White
Write-Host " - Client IP          : $clientIp" -ForegroundColor White
Write-Host " - AI Server URL      : $ServerUrl" -ForegroundColor Yellow
Write-Host " - Chu ky quet        : $IntervalSeconds giay/lan" -ForegroundColor White
Write-Host "----------------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "[*] Dang ket noi thu toi AI Server..." -ForegroundColor Yellow

# Kiem tra ket noi toi Server
try {
    $healthUrl = $ServerUrl.Replace("/ingest", "/health")
    $healthCheck = Invoke-RestMethod -Uri $healthUrl -Method GET -TimeoutSec 5
    $modelsStr = $healthCheck.models -join ', '
    Write-Host "[OK] Ket noi toi AI Server thanh cong! Model: $modelsStr" -ForegroundColor Green
} catch {
    Write-Host "[!] CANH BAO: Chua ket noi duoc toi AI Server tai $ServerUrl" -ForegroundColor Red
    Write-Host "    Hay dam bao server app.py dang chay tren may 192.168.153.1 va Firewall mo port 8000." -ForegroundColor Yellow
}

Write-Host "`n[*] Bat dau thu thap va day log thoi gian thuc...`n" -ForegroundColor Green

$lastSeenTime = (Get-Date).AddSeconds(-30)
$round = 0

while ($true) {
    $round++
    $nowLocal = (Get-Date).ToString("HH:mm:ss")
    
    # 1. Quet Security Log (4624, 4625, 4648, 4688) theo gio Local
    $secFilter = @{
        LogName   = 'Security'
        Id        = 4624, 4625, 4648, 4688
        StartTime = $lastSeenTime
    }
    $secEvents = @(Get-WinEvent -FilterHashtable $secFilter -ErrorAction SilentlyContinue)

    # 2. Quet PowerShell Log (4104) theo gio Local
    $psFilter = @{
        LogName   = 'Microsoft-Windows-PowerShell/Operational'
        Id        = 4104
        StartTime = $lastSeenTime
    }
    $psEvents = @(Get-WinEvent -FilterHashtable $psFilter -ErrorAction SilentlyContinue)

    $totalNew = $secEvents.Count + $psEvents.Count

    if ($totalNew -eq 0) {
        Write-Host "[$nowLocal] (Lan $round) Dang theo doi... Khong co su kien moi." -ForegroundColor DarkGray
        $lastSeenTime = (Get-Date).AddSeconds(-5)
    } else {
        Write-Host "`n[$nowLocal] [PHAT HIEN SU KIEN] Security: $($secEvents.Count) | PowerShell: $($psEvents.Count)" -ForegroundColor Yellow
        Write-Host "  -> Dang dong goi va gui ve AI Server ($ServerUrl)..." -ForegroundColor Cyan

        # Chuyen doi sang XML
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

        # Cap nhat moc thoi gian quet theo gio Local
        $lastSeenTime = (Get-Date).AddSeconds(1)

        $payloadObj = @{
            client_id      = $clientIp
            hostname       = $hostname
            security_xml   = $secXml
            powershell_xml = $psXml
            model          = "qwen"
        }
        $payloadJson = $payloadObj | ConvertTo-Json -Depth 5

        try {
            $resp = Invoke-RestMethod -Uri $ServerUrl -Method POST -ContentType "application/json; charset=utf-8" -Body $payloadJson -TimeoutSec 60
            Write-Host "  [OK] Da day $totalNew su kien log len AI Server thanh cong!`n" -ForegroundColor Green
        } catch {
            Write-Host "  [ERROR] Khong the gui log ve Server: $_`n" -ForegroundColor Red
        }
    }

    Start-Sleep -Seconds $IntervalSeconds
}
