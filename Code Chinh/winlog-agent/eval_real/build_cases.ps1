#Requires -Version 5.1
<#
Chuyen cac file EVTX that (DeepBlueCLI, EVTX-to-MITRE) thanh ca kiem thu cho analyze.py.
- Doc nhan tu labels.json (da chot truoc khi chay model).
- Chi lay su kien agent thuc te thu: Security 4624/4625/4648/4688/1102/4720/4728/4732/4698,
  PowerShell/Operational 4104, System 7045/104.
- Loai su kien xoa nhat ky (1102/104) neu no la su kien DAU TIEN cua file: do nguoi tao mau xoa log
  truoc khi ghi lai tan cong (dau vet chuan bi du lieu, khong phai tan cong). Ghi so luong vao manifest.
- Gioi han max_events su kien dau tien theo thoi gian; ghi lai trong manifest.
- Khong thuc thi bat ky noi dung nao trong log.
Cach chay:  powershell -ExecutionPolicy Bypass -File eval_real\build_cases.ps1
#>
param(
    [string]$LabelsPath = "$PSScriptRoot\labels.json",
    [string]$OutDir = "$PSScriptRoot\cases",
    # Full: ghi them ban <case_id>_full = dung cac su kien ban cu da chon + su kien ID moi
    # (md/THIET_KE_TEST_TOAN_BO_LOG_25112026.md) nam trong cung khoang thoi gian. Ban cu giu nguyen.
    [ValidateSet('Agent', 'Full')][string]$IdSet = 'Agent'
)
$ErrorActionPreference = 'Stop'
$labels = Get-Content -LiteralPath $LabelsPath -Raw -Encoding UTF8 | ConvertFrom-Json
$maxEvents = [int]$labels.max_events
$secIds = @(4624, 4625, 4648, 4688, 1102, 4720, 4728, 4732, 4698)
$psIds = @(4104)
$sysIds = @(7045, 104)
$full = $IdSet -eq 'Full'
$newSecIds = @(4798, 4799, 4672, 5382, 4797, 4738, 4647, 4616, 1100, 4719)
$newPsIds = @(4103)
$classicPsIds = @(400, 800)
$utf8 = New-Object System.Text.UTF8Encoding($false)

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$summary = @()

foreach ($c in $labels.cases) {
    $src = $labels.sources.($c.source)
    $evtx = Join-Path (Join-Path $PSScriptRoot $src.evtx_dir) $c.file
    $row = [ordered]@{ case_id = $c.case_id; category = $c.category; status = ''; security = 0; powershell = 0; system = 0; total_supported = 0; truncated = $false }
    if (-not (Test-Path -LiteralPath $evtx)) { $row.status = 'MISSING_EVTX'; $summary += [pscustomobject]$row; continue }

    $sha = (Get-FileHash -LiteralPath $evtx -Algorithm SHA256).Hash
    try {
        $all = @(Get-WinEvent -Path $evtx -Oldest -ErrorAction Stop)
    } catch {
        $row.status = "READ_ERROR: $($_.Exception.Message)"; $summary += [pscustomobject]$row; continue
    }
    # Su kien xoa log o vi tri dau file = dau vet chuan bi mau -> loai
    $prepClear = @()
    if ($all.Count -gt 0 -and (($all[0].LogName -eq 'Security' -and $all[0].Id -eq 1102) -or ($all[0].LogName -eq 'System' -and $all[0].Id -eq 104))) {
        $prepClear = @($all[0])
    }
    $supported = @($all | Where-Object {
        ($prepClear -notcontains $_) -and (
        ($_.LogName -eq 'Security' -and $secIds -contains $_.Id) -or
        ($_.LogName -eq 'Microsoft-Windows-PowerShell/Operational' -and $psIds -contains $_.Id) -or
        ($_.LogName -eq 'System' -and $sysIds -contains $_.Id))
    })
    $row.total_supported = $supported.Count
    $picked = @($supported | Select-Object -First $maxEvents)
    $row.truncated = ($supported.Count -gt $maxEvents)
    $caseId = $c.case_id
    $extra = @()
    if ($full) {
        # Giu nguyen moi su kien ban cu da chon; them su kien ID moi trong [dau, cuoi] cua tap do (khong cat max_events)
        $times = @($picked | ForEach-Object { $_.TimeCreated } | Sort-Object)
        if ($times.Count) {
            $t0 = $times[0]; $t1 = $times[-1]
            $extra = @($all | Where-Object {
                ($prepClear -notcontains $_) -and $_.TimeCreated -ge $t0 -and $_.TimeCreated -le $t1 -and (
                ($_.LogName -eq 'Security' -and $newSecIds -contains $_.Id) -or
                ($_.LogName -eq 'Microsoft-Windows-PowerShell/Operational' -and $newPsIds -contains $_.Id) -or
                ($_.LogName -eq 'Windows PowerShell' -and $classicPsIds -contains $_.Id))
            })
        }
        $picked = @(@($picked) + $extra | Sort-Object TimeCreated)
        $caseId = "$($c.case_id)_full"
        $row.case_id = $caseId
    }
    $sec = @($picked | Where-Object { $_.LogName -eq 'Security' })
    $ps = @($picked | Where-Object { $_.LogName -in 'Microsoft-Windows-PowerShell/Operational', 'Windows PowerShell' })
    $sys = @($picked | Where-Object { $_.LogName -eq 'System' })
    $row.security = $sec.Count; $row.powershell = $ps.Count; $row.system = $sys.Count

    $dir = Join-Path $OutDir $caseId
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    try {
        [IO.File]::WriteAllText((Join-Path $dir 'security.xml'), '<Events>' + (($sec | ForEach-Object { $_.ToXml() }) -join '') + '</Events>', $utf8)
        [IO.File]::WriteAllText((Join-Path $dir 'powershell.xml'), '<Events>' + (($ps | ForEach-Object { $_.ToXml() }) -join '') + '</Events>', $utf8)
        [IO.File]::WriteAllText((Join-Path $dir 'system.xml'), '<Events>' + (($sys | ForEach-Object { $_.ToXml() }) -join '') + '</Events>', $utf8)
    } catch {
        $row.status = "WRITE_ERROR (co the bi antivirus chan): $($_.Exception.Message)"; $summary += [pscustomobject]$row; continue
    }
    $manifest = [ordered]@{
        case_id = $caseId; ground_truth = $c.ground_truth; category = $c.category
        technique = $c.technique; dual_use = [bool]$c.dual_use
        actions = "Log that tu $($src.repository) - $($c.file)"
        label_basis = $c.label_basis
        source = [ordered]@{ repository = $src.repository; commit = $src.commit; file = $c.file; sha256 = $sha }
        events_in_file = $all.Count; supported_in_file = $supported.Count
        security_count = $sec.Count; powershell_count = $ps.Count; system_count = $sys.Count
        dropped_prep_log_clear = $prepClear.Count
        truncated_to_first = $(if ($row.truncated) { $maxEvents } else { $null })
        built_at = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    if ($full) { $manifest.base_case = $c.case_id; $manifest.id_set = 'Full'; $manifest.new_id_events = $extra.Count }
    [IO.File]::WriteAllText((Join-Path $dir 'manifest.json'), ($manifest | ConvertTo-Json -Depth 5), $utf8)
    $row.status = 'OK'
    $summary += [pscustomobject]$row
}

$summary | Format-Table -AutoSize | Out-String -Width 220
