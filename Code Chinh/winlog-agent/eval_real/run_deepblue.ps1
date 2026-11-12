#Requires -Version 5.1
<#
Chay DeepBlueCLI (cong cu KHONG dung AI) tren cac file EVTX goc de so sanh voi Qwen / Llama.
- Ca + nhan lay tu labels.json (nhan da chot truoc): 'cases', them 'out_of_scope' (tan cong nam o log agent
  KHONG thu - DeepBlueCLI doc ca file nen van co the thay).
- Moi file .evtx trong -NormalDir duoc coi la mot phien hoat dong BINH THUONG (nhan NORMAL) -> do bao dong gia.
- Moi file: goi DeepBlue.ps1, dem so phat hien. Co >= 1 phat hien -> ALERT, khong co -> NORMAL.
- Cot log_clear_only = True khi MOI phat hien chi la "... Log Clear". Trong cac bo mau, xoa log la dau vet
  nguoi tao mau don log truoc khi ghi (he thong cua nhom da loai su kien nay), nen khi so sanh cong bang
  cac ca do khong duoc tinh la bat dung. Viec cham diem do compare_tools.py lam.
- Ghi eval_real\deepblue_results.csv (moi ca mot dong, kem thoi gian chay).
- DeepBlue.ps1 chi DOC file evtx, khong thuc thi noi dung trong log.

DeepBlue.ps1 + regexes.txt + safelist.txt tai tu https://github.com/sans-blue-team/DeepBlueCLI
(dung commit ghi trong labels.json), dat o thu muc -ToolDir. Khong dua vao repo (GPL-3.0, ben thu ba).

Cach chay:  powershell -ExecutionPolicy Bypass -File eval_real\run_deepblue.ps1
#>
param(
    [string]$LabelsPath = "$PSScriptRoot\labels.json",
    [string]$ToolDir = "",
    [string]$NormalDir = "$PSScriptRoot\normal_evtx",
    [string]$OutCsv = "$PSScriptRoot\deepblue_results.csv"
)
$ErrorActionPreference = 'Stop'
$labels = Get-Content -LiteralPath $LabelsPath -Raw -Encoding UTF8 | ConvertFrom-Json
$dbcDir = Join-Path $PSScriptRoot $labels.sources.deepbluecli.evtx_dir
if (-not $ToolDir) { $ToolDir = Join-Path (Split-Path $dbcDir) 'tool' }
$deepblue = Join-Path $ToolDir 'DeepBlue.ps1'
if (-not (Test-Path -LiteralPath $deepblue)) { throw "Khong thay $deepblue" }

function New-Case($id, $source, $category, $truth, $evtx) {
    [pscustomobject]@{ case_id = $id; source = $source; category = $category; ground_truth = $truth; evtx = $evtx }
}
$cases = @(
    foreach ($c in $labels.cases) {
        New-Case $c.case_id $c.source $c.category $c.ground_truth (Join-Path (Join-Path $PSScriptRoot $labels.sources.($c.source).evtx_dir) $c.file)
    }
    foreach ($o in $labels.out_of_scope) {
        $truth = if ($o.technique -like '(khong mo ta)*') { 'UNKNOWN' } else { 'ALERT' }
        New-Case ('oos_' + [IO.Path]::GetFileNameWithoutExtension($o.file)) 'deepbluecli' 'out_of_scope' $truth (Join-Path $dbcDir $o.file)
    }
    if (Test-Path -LiteralPath $NormalDir) {
        foreach ($f in Get-ChildItem -LiteralPath $NormalDir -Filter *.evtx) {
            New-Case ('normal_' + $f.BaseName) 'lab_vm' 'normal_session' 'NORMAL' $f.FullName
        }
    }
)

$rows = foreach ($c in $cases) {
    $found = @(); $err = ''
    $sw = [Diagnostics.Stopwatch]::StartNew()
    Push-Location $ToolDir   # DeepBlue.ps1 doc regexes.txt / safelist.txt o thu muc hien tai
    try {
        if (-not (Test-Path -LiteralPath $c.evtx)) { throw "Khong thay file evtx" }
        $found = @(& $deepblue -file $c.evtx 6>$null | Where-Object { $_.Message })
    } catch { $err = $_.Exception.Message } finally { Pop-Location }
    $sw.Stop()
    $pred = if ($err) { 'ERROR' } elseif ($found.Count -gt 0) { 'ALERT' } else { 'NORMAL' }
    $msgs = @($found | ForEach-Object { $_.Message } | Select-Object -Unique)
    Write-Host ("{0,-42} {1,-7} -> {2,-6} ({3} phat hien, {4:n1}s) {5}" -f $c.case_id, $c.ground_truth, $pred, $found.Count, $sw.Elapsed.TotalSeconds, $err)
    [pscustomobject]@{
        case_id = $c.case_id; source = $c.source; file = (Split-Path $c.evtx -Leaf); category = $c.category
        ground_truth = $c.ground_truth; pred_label = $pred
        is_correct = ($pred -eq $c.ground_truth)
        detections = $found.Count
        log_clear_only = ($msgs.Count -gt 0 -and @($msgs | Where-Object { $_ -notmatch 'Log Clear' }).Count -eq 0)
        messages = ($msgs -join '; ')
        elapsed_seconds = [math]::Round($sw.Elapsed.TotalSeconds, 2); error = $err
    }
}
$rows | Export-Csv -LiteralPath $OutCsv -NoTypeInformation -Encoding UTF8
Write-Host "`nDa ghi $OutCsv"
