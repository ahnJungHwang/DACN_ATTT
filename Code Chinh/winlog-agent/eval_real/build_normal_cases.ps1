#Requires -Version 5.1
<#
Cat log HOAT DONG BINH THUONG (file .evtx xuat tu may that) thanh cac ca NORMAL de do bao dong gia.
- Vao: thu muc chua Security.evtx va/hoac Microsoft-Windows-PowerShell_Operational.evtx (System.evtx neu co).
- Chia thoi gian thanh cua so -WindowMinutes (mac dinh 10 phut); cua so co >= 1 su kien agent thu = 1 ca.
  Su kien agent thu: Security 4624/4625/4648/4688/1102/4720/4728/4732/4698, PowerShell 4104, System 7045/104.
- Moi ca ghi vao eval_real\cases\<Prefix>_<yyyyMMdd_HHmm>\ (security.xml, powershell.xml, system.xml, manifest.json)
  -> an danh: ten may, email, thu muc ho so C:\Users\<ten>.
- Ban sao .evtx GOC cua tung cua so (moi su kien, khong loc) o eval_real\cases\_normal_evtx\<case_id>\ de chay DeepBlueCLI.
  File .evtx khong an danh duoc -> nam trong cases\ (da .gitignore), KHONG dua len GitHub.
- Chi doc log, khong thuc thi noi dung trong log.

Cach chay:
  powershell -ExecutionPolicy Bypass -File eval_real\build_normal_cases.ps1 -EvtxDir "D:\...\NHAN-LAM-LAPTOP_..." -Prefix lam_normal
#>
param(
    [Parameter(Mandatory)][string]$EvtxDir,
    [string]$Prefix = "normal_real",
    [int]$WindowMinutes = 10,
    [string]$Description = "Hoat dong binh thuong tren laptop thanh vien nhom (log xuat tu may that)",
    [string]$OutDir = "",
    # Agent = 12 ID agent thu (nhu cu). Full = them nhom ID moi (md/THIET_KE_TEST_TOAN_BO_LOG_25112026.md),
    # doc them "Windows PowerShell.evtx", ghi split dev/test, category normal_full.
    [ValidateSet('Agent', 'Full')][string]$IdSet = 'Agent',
    [datetime]$SplitAt = '2026-11-22',
    [string]$RawDirName = '_normal_evtx'
)
$ErrorActionPreference = 'Stop'
if (-not $OutDir) { $OutDir = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'cases' }  # $PSScriptRoot rong trong param o PS 5.1
$utf8 = New-Object System.Text.UTF8Encoding($false)
$full = $IdSet -eq 'Full'
$secIds = @(4624, 4625, 4648, 4688, 1102, 4720, 4728, 4732, 4698)
$psIds = @(4104)
if ($full) {
    $secIds += 4798, 4799, 4672, 5382, 4797, 4738, 4647, 4616, 1100, 4719
    $psIds += 4103
}
$sources = @(
    @{ File = 'Security.evtx'; Key = 'security'; Ids = $secIds },
    @{ File = 'Microsoft-Windows-PowerShell_Operational.evtx'; Key = 'powershell'; Ids = $psIds },
    @{ File = 'System.evtx'; Key = 'system'; Ids = 7045, 104 }
)
if ($full) { $sources += @{ File = 'Windows PowerShell.evtx'; Key = 'powershell'; Ids = 400, 800 } }
function Get-Split([datetime]$t) { if ($t -lt $SplitAt) { 'dev' } else { 'test' } }

# 1. Doc su kien agent thu tu tung file
$events = @()
foreach ($s in $sources) {
    $path = Join-Path $EvtxDir $s.File
    if (-not (Test-Path -LiteralPath $path)) { continue }
    $xp = '*[System[(' + (($s.Ids | ForEach-Object { "EventID=$_" }) -join ' or ') + ')]]'
    $ev = @(Get-WinEvent -Path $path -FilterXPath $xp -Oldest -ErrorAction SilentlyContinue)
    Write-Host ("{0,-48} {1,6} su kien agent thu" -f $s.File, $ev.Count)
    $events += $ev | ForEach-Object { [pscustomobject]@{ Key = $s.Key; Time = $_.TimeCreated; Xml = $_.ToXml(); Machine = $_.MachineName } }
}
if (-not $events) { throw "Khong co su kien nao trong $EvtxDir" }

# 2. Gia tri can an danh: ten may, email, ten thu muc ho so
$rules = [ordered]@{}
foreach ($m in ($events.Machine | Where-Object { $_ } | Select-Object -Unique)) { $rules[[regex]::Escape($m)] = 'LAB-PC02' }
$rules['[\w.+-]+@[\w-]+(\.[\w-]+)+'] = 'labuser@example.com'
$rules['(?<=C:\\Users\\)(?!Public\b|Default\b|All Users\b)[^\\<"'' ]+'] = 'LABUSER'
function Protect([string]$text) { foreach ($k in $rules.Keys) { $text = [regex]::Replace($text, "(?i)$k", $rules[$k]) }; $text }

# 3. Chia cua so, ghi ca
$day0 = ($events | Sort-Object Time | Select-Object -First 1).Time.Date
$windows = @{ dev = 0; test = 0 }
$groups = $events | Group-Object { [math]::Floor(($_.Time - $day0).TotalMinutes / $WindowMinutes) } | Sort-Object { [int]$_.Name }
$made = 0
foreach ($g in $groups) {
    $wStart = $day0.AddMinutes([int]$g.Name * $WindowMinutes); $wEnd = $wStart.AddMinutes($WindowMinutes)
    $id = "{0}_{1:yyyyMMdd_HHmm}" -f $Prefix, $wStart
    $dir = Join-Path $OutDir $id
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $count = @{}
    foreach ($k in 'security', 'powershell', 'system') {
        $sel = @($g.Group | Where-Object Key -eq $k | Sort-Object Time)
        $count[$k] = $sel.Count
        [IO.File]::WriteAllText((Join-Path $dir "$k.xml"), (Protect ('<Events>' + (($sel | ForEach-Object Xml) -join '') + '</Events>')), $utf8)
    }
    $split = Get-Split $wStart
    $windows[$split]++
    $manifest = [ordered]@{
        case_id = $id; ground_truth = 'NORMAL'; category = $(if ($full) { 'normal_full' } else { 'normal_session' }); technique = ''; dual_use = $false
        actions = $Description
        label_basis = 'Phien su dung binh thuong; da quet tu khoa tan cong (mimikatz, -enc, DownloadString...) va xem tay cac ca bi bao dong'
        window_start = $wStart.ToString('yyyy-MM-dd HH:mm'); window_end = $wEnd.ToString('yyyy-MM-dd HH:mm'); window_minutes = $WindowMinutes
        security_count = $count.security; powershell_count = $count.powershell; system_count = $count.system
        built_at = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    if ($full) { $manifest.split = $split; $manifest.id_set = 'Full' }
    [IO.File]::WriteAllText((Join-Path $dir 'manifest.json'), ($manifest | ConvertTo-Json -Depth 4), $utf8)
    $made++
    if ($full -and $split -ne 'test') { continue }  # DeepBlueCLI / Hayabusa chi cham tren phan kiem tra

    # Ban sao evtx goc cua cua so cho DeepBlueCLI (moi su kien trong cua so, giong DeepBlueCLI doc ca file)
    $rawDir = Join-Path (Join-Path $OutDir $RawDirName) $id
    New-Item -ItemType Directory -Force -Path $rawDir | Out-Null
    $q = "*[System[TimeCreated[@SystemTime>='{0:yyyy-MM-ddTHH:mm:ss.000Z}' and @SystemTime<'{1:yyyy-MM-ddTHH:mm:ss.000Z}']]]" -f $wStart.ToUniversalTime(), $wEnd.ToUniversalTime()
    foreach ($s in $sources) {
        $src = Join-Path $EvtxDir $s.File
        if (-not (Test-Path -LiteralPath $src)) { continue }
        $dst = Join-Path $rawDir $s.File
        if (Test-Path -LiteralPath $dst) { Remove-Item -LiteralPath $dst }
        wevtutil epl "$src" "$dst" /lf:true "/q:$q"
        if ($LASTEXITCODE -ne 0) { throw "wevtutil loi khi cat $($s.File) cho $id" }
    }
}
Write-Host "[OK] Tao $made ca NORMAL ($WindowMinutes phut/ca) trong $OutDir; evtx goc cho DeepBlueCLI o $OutDir\$RawDirName"

# 4. Pheu so lieu cho bao cao (chi che do Full): tong su kien moi file, so su kien duoc doc va so cua so theo dev/test
if ($full) {
    $files = [ordered]@{}; $total = @{ dev = 0; test = 0 }
    foreach ($s in $sources) {
        $path = Join-Path $EvtxDir $s.File
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $times = @(Get-WinEvent -Path $path -Oldest -ErrorAction SilentlyContinue | ForEach-Object { $_.TimeCreated })
        $files[$s.File] = $times.Count
        foreach ($t in $times) { $total[(Get-Split $t)]++ }
    }
    $selected = @{ dev = 0; test = 0 }
    foreach ($e in $events) { $selected[(Get-Split $e.Time)]++ }
    $summary = [ordered]@{
        split_at = $SplitAt.ToString('yyyy-MM-dd HH:mm'); files = $files
        total = [ordered]@{ dev = $total.dev; test = $total.test }
        selected = [ordered]@{ dev = $selected.dev; test = $selected.test }
        windows = [ordered]@{ dev = $windows.dev; test = $windows.test }
        built_at = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    [IO.File]::WriteAllText((Join-Path $OutDir '_full_build_summary.json'), ($summary | ConvertTo-Json -Depth 4), $utf8)
    Write-Host ("[OK] Pheu: tong dev {0} / test {1}; doc dev {2} / test {3}; cua so dev {4} / test {5}" -f $total.dev, $total.test, $selected.dev, $selected.test, $windows.dev, $windows.test)
}
