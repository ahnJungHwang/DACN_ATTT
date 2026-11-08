<#
.SYNOPSIS
    Chay tren MAY AO (client): gui tung ca trong bo mu ve AI Server qua POST /ingest,
    giong het cach client_agent.ps1 gui log that.

.DESCRIPTION
    - Moi ca duoc gui voi client_id = "<Prefix><ma ca>", vd: blind_B001.
      Server tu luu ket qua vao results\client_blind_B001_live\ tren may that.
    - May ao KHONG can (va KHONG duoc co) file answer_key.csv.
    - Ghi lai phan hoi cua server vao replay_log.csv (chi co ma ca, khong co nhan dung).

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\replay_blind.ps1
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\replay_blind.ps1 -ServerUrl https://192.168.153.1:9443/ingest -Model llama
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\replay_blind.ps1 -DryRun
#>
[CmdletBinding()]
param(
    [string]$BlindDir = "",
    [string]$ServerUrl = "https://192.168.153.1:9443/ingest",
    [ValidateSet("qwen", "llama")]
    [string]$Model = "qwen",
    [string]$Prefix = "blind_",
    [int]$DelaySeconds = 2,
    [int]$TimeoutSeconds = 600,
    [string]$OutCsv = "",
    [string[]]$Only = @(),
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

# PowerShell 5.1: $PSScriptRoot khong dung duoc trong gia tri mac dinh cua param
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $BlindDir) { $BlindDir = Join-Path $scriptDir "blind_set" }
if (-not $OutCsv)   { $OutCsv   = Join-Path $scriptDir "replay_log.csv" }

# Bo qua loi chung chi self-signed (giong client_agent.ps1)
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
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

if (-not (Test-Path -LiteralPath $BlindDir -PathType Container)) {
    Write-Host "[x] Khong tim thay thu muc bo mu: $BlindDir" -ForegroundColor Red
    exit 2
}
if (Get-ChildItem -LiteralPath $BlindDir -Recurse -Filter "answer_key*" -ErrorAction SilentlyContinue) {
    Write-Host "[x] Phat hien file answer_key trong bo mu! Xoa no khoi may ao truoc khi chay." -ForegroundColor Red
    exit 2
}

$cases = Get-ChildItem -LiteralPath $BlindDir -Directory | Sort-Object Name |
    Where-Object { (Test-Path (Join-Path $_.FullName "security.xml")) -and (Test-Path (Join-Path $_.FullName "powershell.xml")) }
# Khi goi bang -File, "-Only B001,B002" den day la 1 chuoi -> tach theo dau phay
$Only = @($Only | ForEach-Object { $_ -split "," } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
if ($Only.Count -gt 0) {
    $cases = $cases | Where-Object { $Only -contains $_.Name }
}
if (-not $cases) {
    Write-Host "[x] Khong co ca nao de gui." -ForegroundColor Red
    exit 2
}

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  BLIND REPLAY: $($cases.Count) ca  ->  $ServerUrl  (model: $Model)" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

$utf8 = New-Object System.Text.UTF8Encoding($false)
$log = New-Object System.Collections.Generic.List[object]
$i = 0

foreach ($c in $cases) {
    $i++
    $clientId = "$Prefix$($c.Name)"
    $secXml = [System.IO.File]::ReadAllText((Join-Path $c.FullName "security.xml"), $utf8)
    $psXml  = [System.IO.File]::ReadAllText((Join-Path $c.FullName "powershell.xml"), $utf8)

    $body = @{
        client_id      = $clientId
        hostname       = $env:COMPUTERNAME
        security_xml   = $secXml
        powershell_xml = $psXml
        model          = $Model
    } | ConvertTo-Json -Depth 5

    $row = [ordered]@{
        blind_id    = $c.Name
        client_id   = $clientId
        model       = $Model
        sent_at     = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")
        http_status = ""
        server_status = ""
        label       = ""
        elapsed_s   = ""
        stages      = ""
        error       = ""
    }

    Write-Host ("[{0,2}/{1}] {2} ... " -f $i, $cases.Count, $c.Name) -NoNewline

    if ($DryRun) {
        $row.server_status = "DRY_RUN"
        Write-Host ("dry-run ({0:N0} bytes)" -f $utf8.GetByteCount($body)) -ForegroundColor DarkGray
        $log.Add([pscustomobject]$row)
        continue
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $resp = Invoke-RestMethod -Uri $ServerUrl -Method POST `
            -ContentType "application/json; charset=utf-8" `
            -Body $utf8.GetBytes($body) -TimeoutSec $TimeoutSeconds
        $sw.Stop()
        $row.http_status = "200"
        if ($resp.analysis_status) { $row.server_status = $resp.analysis_status }
        elseif ($resp.status) { $row.server_status = $resp.status }
        if ($resp.verdict) {
            $row.label  = $resp.verdict.label
            $row.stages = ($resp.verdict.detected_stages -join "; ")
        }
        $row.elapsed_s = [Math]::Round($sw.Elapsed.TotalSeconds, 2)

        $shown = if ($row.label) { $row.label } else { "(ket qua luu tren server)" }
        $color = switch ($row.label) { "ALERT" { "Red" } "NORMAL" { "Green" } default { "Yellow" } }
        Write-Host ("{0}  ({1}s)" -f $shown, $row.elapsed_s) -ForegroundColor $color
    }
    catch {
        $sw.Stop()
        $row.error = $_.Exception.Message
        $row.elapsed_s = [Math]::Round($sw.Elapsed.TotalSeconds, 2)
        Write-Host "LOI: $($row.error)" -ForegroundColor Red
    }

    $log.Add([pscustomobject]$row)
    if ($DelaySeconds -gt 0 -and $i -lt $cases.Count) { Start-Sleep -Seconds $DelaySeconds }
}

$log | Export-Csv -LiteralPath $OutCsv -NoTypeInformation -Encoding UTF8
$errors = @($log | Where-Object { $_.error }).Count

Write-Host "----------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "[OK] Da gui $($log.Count) ca, loi: $errors. Nhat ky: $OutCsv" -ForegroundColor Green
Write-Host "     Chep replay_log.csv ve may that roi chay score_blind.py de cham diem." -ForegroundColor Green
