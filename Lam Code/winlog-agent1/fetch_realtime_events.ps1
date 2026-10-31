[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$StartTimeUtc,

    [Parameter(Mandatory = $true)]
    [string]$OutDir
)

$ErrorActionPreference = 'SilentlyContinue'

try {
    $start = [DateTime]::Parse($StartTimeUtc).ToUniversalTime()
} catch {
    $start = (Get-Date).AddMinutes(-2).ToUniversalTime()
}

if (-not (Test-Path $OutDir)) {
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
}

$secFilter = @{
    LogName   = 'Security'
    Id        = 4624, 4625, 4648, 4688
    StartTime = $start
}

$secEvents = @(Get-WinEvent -FilterHashtable $secFilter -ErrorAction SilentlyContinue)

$psFilter = @{
    LogName   = 'Microsoft-Windows-PowerShell/Operational'
    Id        = 4104
    StartTime = $start
}

$psEvents = @(Get-WinEvent -FilterHashtable $psFilter -ErrorAction SilentlyContinue)

$latestTime = $start

if ($secEvents.Count -gt 0) {
    $xmlContent = '<Events>' + (($secEvents | ForEach-Object { $_.ToXml() }) -join '') + '</Events>'
    [System.IO.File]::WriteAllText((Join-Path $OutDir "security.xml"), $xmlContent, [System.Text.Encoding]::UTF8)
    foreach ($e in $secEvents) {
        if ($e.TimeCreated.ToUniversalTime() -gt $latestTime) {
            $latestTime = $e.TimeCreated.ToUniversalTime()
        }
    }
} else {
    [System.IO.File]::WriteAllText((Join-Path $OutDir "security.xml"), '<Events></Events>', [System.Text.Encoding]::UTF8)
}

if ($psEvents.Count -gt 0) {
    $xmlContent = '<Events>' + (($psEvents | ForEach-Object { $_.ToXml() }) -join '') + '</Events>'
    [System.IO.File]::WriteAllText((Join-Path $OutDir "powershell.xml"), $xmlContent, [System.Text.Encoding]::UTF8)
    foreach ($e in $psEvents) {
        if ($e.TimeCreated.ToUniversalTime() -gt $latestTime) {
            $latestTime = $e.TimeCreated.ToUniversalTime()
        }
    }
} else {
    [System.IO.File]::WriteAllText((Join-Path $OutDir "powershell.xml"), '<Events></Events>', [System.Text.Encoding]::UTF8)
}

$result = @{
    security_count   = $secEvents.Count
    powershell_count = $psEvents.Count
    latest_utc       = $latestTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
}

$result | ConvertTo-Json -Compress
