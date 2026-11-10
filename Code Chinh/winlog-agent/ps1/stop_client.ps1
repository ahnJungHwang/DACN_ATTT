<#
.SYNOPSIS
    Tat tien trinh client_agent.ps1 dang chay. Duoc goi boi bat\stop_client.bat.
.DESCRIPTION
    1. Doc PID tu client_agent.pid (thu muc goc winlog-agent) do client_agent.ps1 ghi luc khoi dong.
    2. Tim them cac tien trinh PowerShell co dong lenh chua client_agent.ps1
       (phong khi file .pid bi mat, hoac Agent duoc chay tu ban cu chua ghi .pid).
    3. Chi tat tien trinh khi xac nhan dung la client_agent.ps1 -> khong tat nham
       chuong trinh khac neu Windows da cap lai so PID cu.
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\ps1\stop_client.ps1
#>
$root = Split-Path -Parent $PSScriptRoot
$pidFile = Join-Path $root "client_agent.pid"

$ids = @()
if (Test-Path -LiteralPath $pidFile) {
    $raw = Get-Content -LiteralPath $pidFile -TotalCount 1 -ErrorAction SilentlyContinue
    if ($raw -match '^\s*(\d+)\s*$') { $ids += [int]$Matches[1] }
}
$ids += @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction SilentlyContinue |
          Where-Object { $_.ProcessId -ne $PID -and $_.CommandLine -like '*client_agent.ps1*' } |
          ForEach-Object { [int]$_.ProcessId })

$killed = 0
$failed = 0
foreach ($id in ($ids | Select-Object -Unique)) {
    if ($id -eq $PID) { continue }
    $p = Get-CimInstance Win32_Process -Filter "ProcessId=$id" -ErrorAction SilentlyContinue
    if (-not $p) { continue }                                              # PID cu, tien trinh da tat
    if ($p.Name -notin @('powershell.exe', 'pwsh.exe')) { continue }      # PID da bi chuong trinh khac dung lai
    # Agent chay bang quyen Admin thi user thuong khong doc duoc CommandLine (null) -> van tin PID trong file
    if ($p.CommandLine -and $p.CommandLine -notlike '*client_agent.ps1*') { continue }
    try {
        Stop-Process -Id $id -Force -ErrorAction Stop
        Wait-Process -Id $id -Timeout 5 -ErrorAction SilentlyContinue   # cho thoat han roi moi xoa file .pid
        Write-Host "  [OK] Da tat tien trinh Agent (PID: $id) thanh cong." -ForegroundColor Green
        $killed++
    } catch {
        $failed++
        Write-Host "  [!] Khong tat duoc Agent (PID: $id): $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "      -> Agent dang chay bang quyen Admin? Hay chuot phai stop_client.bat -> 'Run as administrator'." -ForegroundColor Yellow
    }
}

# Xoa client_agent.pid (giu lai chi khi co Agent tat khong duoc -> van dang chay)
if ($failed -eq 0) {
    Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
}
if ($killed -eq 0 -and $failed -eq 0) {
    Write-Host "  [*] Khong tim thay tien trinh Agent nao dang chay." -ForegroundColor Yellow
}
exit 0
