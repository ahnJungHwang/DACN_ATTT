<#
    Xuat Security log va PowerShell log ra o I:\Windows Log
    - 1 file CSV gop tat ca su kien (de phan tich bang Excel / Timeline Explorer / pandas)
    - 1 file CSV chi chua cac Event ID quan trong
    - Ban sao .evtx goc cua tung log (de mo lai bang Event Viewer)

    Cach chay: mo PowerShell bang quyen Administrator, roi chay:
        powershell -ExecutionPolicy Bypass -File "duong_dan\Export-SecurityPowerShellLogs.ps1"
    Tuy chon so ngay (mac dinh 7, dat 0 de lay toan bo):
        powershell -ExecutionPolicy Bypass -File "...\Export-SecurityPowerShellLogs.ps1" -Days 30
#>

param(
    [int]$Days = 7
)

$ErrorActionPreference = 'Stop'

# --- 1. Kiem tra quyen Administrator ---
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Can chay PowerShell bang quyen Administrator (de doc duoc Security log)." -ForegroundColor Red
    exit 1
}

# --- 2. Kiem tra o I va tao thu muc ---
if (-not (Test-Path 'I:\')) {
    Write-Host "Khong tim thay o I:. Kiem tra lai o dia." -ForegroundColor Red
    exit 1
}

$stamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
$baseDir = 'I:\Windows Log'
$outDir  = Join-Path $baseDir "$env:COMPUTERNAME`_$stamp"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$logs = @(
    'Security',
    'Microsoft-Windows-PowerShell/Operational',
    'Windows PowerShell'
)

# Cac Event ID quan trong
$keyIds = @{
    'Security'                                 = 4624,4625,4634,4648,4672,4688,4697,4698,4719,4720,4722,4724,4728,4732,4738,4756,1102
    'Microsoft-Windows-PowerShell/Operational' = 4103,4104
    'Windows PowerShell'                       = 400,403,600,800
}

$startTime = if ($Days -gt 0) { (Get-Date).AddDays(-$Days) } else { $null }
Write-Host "Thu muc luu: $outDir"
Write-Host ("Pham vi: " + $(if ($startTime) { "$Days ngay gan nhat (tu $startTime)" } else { "toan bo log" }))

function Get-Events([string]$LogName, [int[]]$Ids) {
    $filter = @{ LogName = $LogName }
    if ($startTime) { $filter.StartTime = $startTime }
    if ($Ids)       { $filter.Id = $Ids }
    try {
        Get-WinEvent -FilterHashtable $filter -ErrorAction Stop
    } catch {
        if ($_.Exception.Message -notmatch 'No events were found') {
            Write-Host "  Loi khi doc ${LogName}: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

$select = @(
    'TimeCreated', 'LogName', 'Id', 'LevelDisplayName', 'ProviderName', 'MachineName',
    @{ n = 'UserSid'; e = { $_.UserId } },
    @{ n = 'Message'; e = { ($_.Message -replace "(`r`n|`n|`r)", ' | ') } }
)

# --- 3. Xuat file .evtx goc ---
Write-Host "`n[1/3] Xuat file .evtx goc..."
foreach ($log in $logs) {
    $file = Join-Path $outDir (($log -replace '[\\/]', '_') + '.evtx')
    wevtutil epl "$log" "$file" 2>$null
    if ($LASTEXITCODE -eq 0) { Write-Host "  OK  $file" }
    else { Write-Host "  Bo qua $log (khong ton tai hoac khong doc duoc)" -ForegroundColor Yellow }
}

# --- 4. CSV gop toan bo su kien ---
Write-Host "`n[2/3] Xuat CSV gop toan bo su kien (co the mat vai phut)..."
$allCsv = Join-Path $outDir 'All_Security_PowerShell.csv'
$all = foreach ($log in $logs) {
    $ev = @(Get-Events $log)
    Write-Host ("  {0,-45} {1,8} su kien" -f $log, $ev.Count)
    $ev
}
$all | Sort-Object TimeCreated | Select-Object $select |
    Export-Csv -Path $allCsv -NoTypeInformation -Encoding UTF8
Write-Host "  OK  $allCsv"

# --- 5. CSV chi Event ID quan trong ---
Write-Host "`n[3/3] Xuat CSV cac Event ID quan trong..."
$keyCsv = Join-Path $outDir 'Key_Events.csv'
$key = foreach ($log in $logs) { Get-Events $log $keyIds[$log] }
@($key) | Sort-Object TimeCreated | Select-Object $select |
    Export-Csv -Path $keyCsv -NoTypeInformation -Encoding UTF8
Write-Host "  OK  $keyCsv ($(@($key).Count) su kien)"

# --- 6. Tom tat ---
Write-Host "`nHoan tat. Cac file da luu:" -ForegroundColor Green
Get-ChildItem $outDir | Select-Object Name, @{ n = 'SizeMB'; e = { [math]::Round($_.Length / 1MB, 2) } } |
    Format-Table -AutoSize
Invoke-Item $outDir
