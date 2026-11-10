<#
.SYNOPSIS
    Trich xuat cac file .evtx (tan cong that) thanh fragment XML ma he thong doc duoc.

.DESCRIPTION
    Chay tren MAY THAT. Duyet dataset\EVTX-ATTACK-SAMPLES, voi moi file .evtx co chua
    event ID duoc ho tro (4624/4625/4648/4688/4104), xuat ra:
        data100_fragments\evtx\<ten>\security.xml
        data100_fragments\evtx\<ten>\powershell.xml
    generate_data100.py se boc ngau nhien tu kho fragment nay.
    KHONG tao noi dung tan cong moi — chi doc lai log co san trong dataset.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\ps1\extract_evtx_fragments.ps1
#>
[CmdletBinding()]
param(
    [string]$Dataset = "",
    [string]$OutDir  = "",
    [int]$MinEvents = 2
)

$ErrorActionPreference = "Stop"
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$scriptDir = Split-Path -Parent $scriptDir  # file nay nam trong ps1\ -> dung thu muc goc winlog-agent
if (-not $Dataset) { $Dataset = Join-Path $scriptDir "dataset\EVTX-ATTACK-SAMPLES" }
if (-not $OutDir)  { $OutDir  = Join-Path $scriptDir "data100_fragments\evtx" }

$SUPPORTED = 4624, 4625, 4648, 4688, 4104
$HEADER = "<Events>"
$FOOTER = "</Events>"

if (Test-Path $OutDir) { Remove-Item $OutDir -Recurse -Force }
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$made = 0
foreach ($f in Get-ChildItem -LiteralPath $Dataset -Recurse -Filter *.evtx) {
    try { $ev = @(Get-WinEvent -Path $f.FullName -ErrorAction Stop) } catch { continue }

    $sec = @($ev | Where-Object { $_.LogName -eq 'Security' -and $SUPPORTED -contains $_.Id })
    $ps  = @($ev | Where-Object { $_.Id -eq 4104 -and $_.ProviderName -eq 'Microsoft-Windows-PowerShell' })
    if (($sec.Count + $ps.Count) -lt $MinEvents) { continue }

    # Ten fragment: tactic + ten file, bo ky tu la
    $tactic = $f.Directory.Name -replace '[^A-Za-z0-9]', '_'
    $base   = [System.IO.Path]::GetFileNameWithoutExtension($f.Name) -replace '[^A-Za-z0-9]', '_'
    $name   = ("{0}__{1}" -f $tactic, $base)
    if ($name.Length -gt 80) { $name = $name.Substring(0, 80) }

    $dst = Join-Path $OutDir $name
    New-Item -ItemType Directory -Path $dst -Force | Out-Null

    $secXml = $HEADER + (($sec | ForEach-Object { $_.ToXml() }) -join '') + $FOOTER
    $psXml  = $HEADER + (($ps  | ForEach-Object { $_.ToXml() }) -join '') + $FOOTER
    [System.IO.File]::WriteAllText((Join-Path $dst "security.xml"),   $secXml, (New-Object System.Text.UTF8Encoding($false)))
    [System.IO.File]::WriteAllText((Join-Path $dst "powershell.xml"), $psXml,  (New-Object System.Text.UTF8Encoding($false)))

    "{0,-40} sec={1,-3} ps={2}" -f $name, $sec.Count, $ps.Count | Write-Host
    $made++
}

Write-Host "----------------------------------------------------------------------"
Write-Host "[OK] Da trich xuat $made fragment tan cong that vao: $OutDir"
