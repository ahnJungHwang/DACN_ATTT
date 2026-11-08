[CmdletBinding()]
param(
    [string]$ServerUrl = "https://192.168.147.1:8443/ingest",   # run_client.bat truyen vao; moi may lab co the khac
    [int]$IntervalSeconds = 5,
    [string]$Model = "qwen",
    [string]$LogFile = "$PSScriptRoot\client_agent.log"
)

# 1. Dam bao tham so luon hop le
if (-not $IntervalSeconds -or $IntervalSeconds -le 0) {
    $IntervalSeconds = 5
}
if (-not $ServerUrl) {
    $ServerUrl = "https://192.168.147.1:8443/ingest"
}

# 2. Bo qua loi SSL Self-Signed tren moi phien ban PowerShell/.NET bang CertificatePolicy thuan C#
# (Khong dung ScriptBlock {$true} vi se loi 'There is no Runspace available' tren thread worker)
if (-not ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type) {
    Add-Type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
            public bool CheckValidationResult(
                ServicePoint srvPoint, X509Certificate certificate,
                WebRequest request, int problem) {
                return true;
            }
        }
"@
}
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls

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

# 6. Tat QuickEdit Mode cua cua so console.
# Neu khong tat: chi can bam chuot vao cua so la tieu de doi thanh "Select ..." va
# TOAN BO script bi tam dung (khong quet log, khong gui len Server).
try {
    if (-not ([System.Management.Automation.PSTypeName]'WinLogConsoleMode').Type) {
        Add-Type @"
            using System;
            using System.Runtime.InteropServices;
            public static class WinLogConsoleMode {
                [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr GetStdHandle(int nStdHandle);
                [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetConsoleMode(IntPtr h, out uint mode);
                [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetConsoleMode(IntPtr h, uint mode);
                public static bool DisableQuickEdit() {
                    IntPtr h = GetStdHandle(-10);           // STD_INPUT_HANDLE
                    uint mode;
                    if (!GetConsoleMode(h, out mode)) return false;
                    mode &= ~0x0040u;                       // ENABLE_QUICK_EDIT_MODE
                    mode |= 0x0080u;                        // ENABLE_EXTENDED_FLAGS
                    return SetConsoleMode(h, mode);
                }
            }
"@
    }
    [void][WinLogConsoleMode]::DisableQuickEdit()
} catch {}

# 7. Ham gui heartbeat (payload rong) -> Server ghi nhan Agent "Active" tren Dashboard
function Send-Heartbeat {
    $hb = @{
        client_id      = $clientIp
        hostname       = $hostname
        security_xml   = '<Events></Events>'
        powershell_xml = '<Events></Events>'
        model          = $Model
    } | ConvertTo-Json
    try {
        $null = Invoke-RestMethod -Uri $ServerUrl -Method POST -ContentType "application/json; charset=utf-8" -Body $hb -TimeoutSec 10
        return $true
    } catch {
        $script:lastError = $_.Exception.Message
        return $false
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
Write-Host "  * Quyen Admin      : $(if ($isAdmin) { 'CO (Doc day du Security + PowerShell Log)' } else { 'KHONG (Chi doc PowerShell Log)' })" -ForegroundColor $(if ($isAdmin) { 'Green' } else { 'Red' })
Write-Host "====================================================================" -ForegroundColor Cyan

# Canh bao quyen Admin
if (-not $isAdmin) {
    Write-Host "[!] CANH BAO: Ban dang mo Agent bang user thuong (khong co quyen Admin)!" -ForegroundColor Yellow
    Write-Host "    -> KHONG DOC DUOC Security Log (Event 4624, 4625, 4688)." -ForegroundColor Yellow
    Write-Host "    -> De test Brute-force hoac Backdoor: Hay chuot phai run_client.bat -> 'Run as administrator'!" -ForegroundColor Yellow
    Write-Host ""
}

# Kiem tra ket noi Server qua /health
Write-Host "[*] Dang kiem tra ket noi toi AI Server..." -ForegroundColor Yellow
$healthUrl = $ServerUrl -replace '/ingest$', '/health'
$serverOnline = $false
try {
    $healthResp = Invoke-RestMethod -Uri $healthUrl -Method GET -TimeoutSec 6
    Write-Host "  [OK] Ket noi AI Server THANH CONG! Status: $($healthResp.status), Model: $($healthResp.models -join ', ')" -ForegroundColor Green
    $serverOnline = $true
} catch {
    Write-Host "  [ERROR] KHONG THE KET NOI TOI AI SERVER ($healthUrl)!" -ForegroundColor Red
    Write-Host "      Loi: $($_.Exception.Message)" -ForegroundColor Red
    # Chan doan: mang/firewall (TCP) hay loi HTTP/SSL
    try {
        $u = [Uri]$ServerUrl
        $tcp = New-Object System.Net.Sockets.TcpClient
        $ar = $tcp.BeginConnect($u.Host, $u.Port, $null, $null)
        $tcpOk = $ar.AsyncWaitHandle.WaitOne(3000) -and $tcp.Connected
        $tcp.Close()
        if ($tcpOk) {
            Write-Host "      -> TCP toi $($u.Host):$($u.Port) THONG. Loi nam o HTTP/HTTPS: kiem tra Server co dang chay bang run_server_https.bat (https, port $($u.Port)) khong." -ForegroundColor Yellow
        } else {
            Write-Host "      -> TCP toi $($u.Host):$($u.Port) KHONG THONG. Server chua chay, sai IP, hoac Firewall tren Server dang chan port $($u.Port)." -ForegroundColor Yellow
        }
    } catch {}
    Write-Host "      -> Agent van tiep tuc chay va tu dong ket noi lai khi Server san sang." -ForegroundColor Yellow
}
Write-Host "--------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "[+] Agent bat dau giam sat Event Log theo thoi gian thuc...`n" -ForegroundColor Cyan

Write-AgentLog "Client Agent khoi dong. Host: $hostname ($clientIp), Server: $ServerUrl, Admin: $isAdmin, ServerOnline: $serverOnline"

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

$cycleCount = 0
$lastHeartbeat = [DateTime]::MinValue
$HeartbeatSeconds = 30
$MaxBacklogMinutes = 10      # Server mat ket noi lau -> chi giu lai log 10 phut gan nhat

# Vong lap giam sat
while ($true) {
    $cycleCount++
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
        $nowStr = (Get-Date).ToString("HH:mm:ss")

        if ($totalNew -gt 0) {
            # CO SU KIEN MOI -> GUI SANG SERVER VA CHO SERVER XAC NHAN
            Write-Host "====================================================================" -ForegroundColor Yellow
            Write-Host "[$nowStr] [CLIENT -> SERVER] Phat hien $totalNew su kien moi!" -ForegroundColor Yellow
            
            if ($secEvents.Count -gt 0) {
                $secSummary = ($secEvents | Group-Object Id | ForEach-Object { "Event $($_.Name): $($_.Count) lan" }) -join ", "
                Write-Host "  * Security Log   : $($secEvents.Count) su kien ($secSummary)" -ForegroundColor White
            }
            if ($psEvents.Count -gt 0) {
                Write-Host "  * PowerShell Log : $($psEvents.Count) su kien (ScriptBlock 4104)" -ForegroundColor White
            }
            if ($sysEvents.Count -gt 0) {
                $sysSummary = ($sysEvents | Group-Object Id | ForEach-Object { "Event $($_.Name): $($_.Count) lan" }) -join ", "
                Write-Host "  * System Log     : $($sysEvents.Count) su kien ($sysSummary)" -ForegroundColor White
            }

            Write-Host "  -> Dang truyen $totalNew su kien sang AI Server ($ServerUrl)..." -ForegroundColor Cyan

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

            # Tinh moc moi (thoi gian + RecordId lon nhat tung log) - CHI ap dung sau khi Server xac nhan da nhan
            # (gui loi thi lan sau gui lai, khong bi mat log)
            $maxTime = $lastSeenTime
            $newSecRecord = $lastSecRecord; $newPsRecord = $lastPsRecord; $newSysRecord = $lastSysRecord
            foreach ($e in $secEvents) {
                if ($e.TimeCreated -gt $maxTime) { $maxTime = $e.TimeCreated }
                if ($e.RecordId -gt $newSecRecord) { $newSecRecord = $e.RecordId }
            }
            foreach ($e in $psEvents) {
                if ($e.TimeCreated -gt $maxTime) { $maxTime = $e.TimeCreated }
                if ($e.RecordId -gt $newPsRecord) { $newPsRecord = $e.RecordId }
            }
            foreach ($e in $sysEvents) {
                if ($e.TimeCreated -gt $maxTime) { $maxTime = $e.TimeCreated }
                if ($e.RecordId -gt $newSysRecord) { $newSysRecord = $e.RecordId }
            }

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
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                $resp = Invoke-RestMethod -Uri $ServerUrl -Method POST -ContentType "application/json; charset=utf-8" -Body ([System.Text.Encoding]::UTF8.GetBytes($payloadJson)) -TimeoutSec 300
                $sw.Stop()
                $elapsedSec = [Math]::Round($sw.Elapsed.TotalSeconds, 1)
                # Server da nhan -> moi chot moc. Thoi gian lui 2s lam vung dem; RecordId chong gui trung.
                $lastSeenTime = $maxTime.AddSeconds(-2)
                $lastSecRecord = $newSecRecord; $lastPsRecord = $newPsRecord; $lastSysRecord = $newSysRecord
                $lastHeartbeat = Get-Date
                $serverOnline = $true

                Write-Host "  [OK SERVER PHAN HOI] Server da nhan va dieu phoi thanh cong!" -ForegroundColor Green
                if ($resp.message) {
                    Write-Host "  * Thong diep Server : $($resp.message)" -ForegroundColor Green
                }
                Write-Host "  * Thoi gian phan hoi: ${elapsedSec}s" -ForegroundColor Gray
                Write-Host "====================================================================`n" -ForegroundColor Yellow
                Write-AgentLog -Message "[OK] Da day $totalNew su kien len Server ($elapsedSec s)."
            } catch {
                Write-Host "  [LOI GUI] Khong the gui du lieu toi Server ($ServerUrl)!" -ForegroundColor Red
                Write-Host "    Chi tiet: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "    -> Giu lai $totalNew su kien, se gui lai o chu ky sau." -ForegroundColor Yellow
                Write-Host "====================================================================`n" -ForegroundColor Yellow
                $serverOnline = $false
                # Khong de ton dong vo han khi Server tat lau
                $floor = (Get-Date).AddMinutes(-$MaxBacklogMinutes)
                if ($lastSeenTime -lt $floor) { $lastSeenTime = $floor }
                Write-AgentLog -Message "[ERROR] Khong the gui toi Server ($ServerUrl): $($_.Exception.Message)"
            }
        } else {
            # Heartbeat THAT toi Server moi 30s (Dashboard hien Agent "Active")
            if (((Get-Date) - $lastHeartbeat).TotalSeconds -ge $HeartbeatSeconds) {
                $wasOnline = $serverOnline
                $serverOnline = Send-Heartbeat
                $lastHeartbeat = Get-Date
                if ($serverOnline -and -not $wasOnline) {
                    Write-Host "[$nowStr] [OK] Da ket noi lai AI Server ($ServerUrl)." -ForegroundColor Green
                    Write-AgentLog -Message "[OK] Ket noi lai Server."
                } elseif (-not $serverOnline) {
                    Write-Host "[$nowStr] [x] MAT KET NOI Server: $script:lastError" -ForegroundColor Red
                    Write-AgentLog -Message "[ERROR] Heartbeat that bai: $script:lastError"
                }
            }
            if ($cycleCount % 2 -eq 1) {
                $st = if ($serverOnline) { "Da ket noi Server" } else { "CHUA ket noi Server (dang thu lai)" }
                Write-Host "[$nowStr] [*] Dang giam sat Event Log... (Security: 0 | PowerShell: 0) -> $st." -ForegroundColor $(if ($serverOnline) { 'DarkGray' } else { 'Red' })
            }
            if ((Get-Date).AddSeconds(-15) -gt $lastSeenTime) {
                $lastSeenTime = (Get-Date).AddSeconds(-15)
            }
        }
    } catch {
        Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] [EXCEPTION] $($_.Exception.Message)" -ForegroundColor Red
        Write-AgentLog -Message "[EXCEPTION] $($_.Exception.Message)"
    }

    Start-Sleep -Seconds $IntervalSeconds
}
