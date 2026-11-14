<#
.SYNOPSIS
    Xuat log HOAT DONG BINH THUONG tren may that thanh cac ca kiem thu co nhan NORMAL
    (dung dinh dang data01/: security.xml, powershell.xml, system.xml, manifest.json).

.DESCRIPTION
    - Chi lay dung cac Event ID ma client_agent.ps1 thu thap:
        Security  : 4624, 4625, 4648, 4688, 1102, 4720, 4728, 4732, 4698
        PowerShell: 4104
        System    : 7045, 104
    - Chia khoang thoi gian thanh nhieu cua so (mac dinh 10 phut) -> moi cua so co su kien = 1 ca NORMAL.
    - Mac dinh AN DANH: thay ten user, ten may, thu muc ho so nguoi dung bang gia tri gia
      (van nen tu doc lai truoc khi dua len GitHub, vi dong lenh 4688/4104 co the chua thong tin rieng tu).
    - CHI xuat khoang thoi gian ban CHAC CHAN khong chay kich ban tan cong / mo phong nao.

.EXAMPLE
    # 30 phut vua qua, chia 10 phut/ca
    powershell -NoProfile -ExecutionPolicy Bypass -File .\ps1\export_normal_logs.ps1 -Description "Lam bai, luot web, VS Code"

.EXAMPLE
    # Mot buoi lam viec cu the, chia 15 phut/ca
    powershell -NoProfile -ExecutionPolicy Bypass -File .\ps1\export_normal_logs.ps1 -Start "2026-11-12 08:00" -End "2026-11-12 11:00" -WindowMinutes 15 -Description "Buoi sang: hoc online, Word, Chrome"
#>
[CmdletBinding()]
param(
    [datetime]$Start = (Get-Date).AddMinutes(-30),
    [datetime]$End = (Get-Date),
    [int]$WindowMinutes = 10,
    [string]$Description = "Hoat dong binh thuong tren may ca nhan",
    [string]$OutDir = "",
    [string]$Prefix = "case_normal_real",
    [switch]$NoAnonymize
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot                     # thu muc goc winlog-agent
if (-not $OutDir) { $OutDir = Join-Path $root "data_normal" }
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] Khong co quyen Administrator -> KHONG doc duoc Security log (nguon chinh)." -ForegroundColor Red
    Write-Host "    Chuot phai PowerShell -> 'Run as administrator' roi chay lai." -ForegroundColor Yellow
    exit 1
}
if ($End -le $Start) { throw "End phai sau Start." }

$sources = @(
    @{ File = "security.xml";   Log = "Security";                                  Ids = 4624, 4625, 4648, 4688, 1102, 4720, 4728, 4732, 4698 },
    @{ File = "powershell.xml"; Log = "Microsoft-Windows-PowerShell/Operational"; Ids = @(4104) },
    @{ File = "system.xml";     Log = "System";                                    Ids = 7045, 104 }
)

# Gia tri can an danh (sap xep dai truoc de khong thay mot phan chuoi)
$secrets = [ordered]@{}
if (-not $NoAnonymize) {
    $secrets[$env:USERPROFILE] = "C:\Users\LABUSER"
    $secrets[$env:COMPUTERNAME] = "LAB-PC01"
    $secrets[$env:USERNAME] = "LABUSER"
    if ($env:USERDOMAIN -and $env:USERDOMAIN -ne $env:COMPUTERNAME) { $secrets[$env:USERDOMAIN] = "LABDOMAIN" }
}
function Protect-Xml([string]$xml) {
    foreach ($k in ($secrets.Keys | Sort-Object Length -Descending)) {
        if ($k) { $xml = [regex]::Replace($xml, [regex]::Escape($k), $secrets[$k], 'IgnoreCase') }
    }
    return $xml
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd_HHmm"
$made = 0; $skipped = 0; $t = $Start; $n = 0
Write-Host "[*] Xuat log tu $($Start.ToString('dd/MM HH:mm')) den $($End.ToString('dd/MM HH:mm')), $WindowMinutes phut/ca -> $OutDir" -ForegroundColor Cyan

while ($t -lt $End) {
    $n++
    $wEnd = $t.AddMinutes($WindowMinutes); if ($wEnd -gt $End) { $wEnd = $End }
    $counts = @{}; $xmls = @{}; $total = 0
    foreach ($s in $sources) {
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = $s.Log; Id = $s.Ids; StartTime = $t; EndTime = $wEnd } -ErrorAction SilentlyContinue |
                Sort-Object RecordId)
        $counts[$s.File] = $ev.Count; $total += $ev.Count
        $body = ($ev | ForEach-Object { $_.ToXml() }) -join ''
        $xmls[$s.File] = Protect-Xml ('<Events>' + $body + '</Events>')
    }
    if ($total -eq 0) { $skipped++; $t = $wEnd; continue }

    $caseId = "{0}_{1}_{2:D2}" -f $Prefix, $stamp, $n
    $dir = Join-Path $OutDir $caseId
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    foreach ($f in $xmls.Keys) { [IO.File]::WriteAllText((Join-Path $dir $f), $xmls[$f], $utf8) }
    $manifest = [ordered]@{
        case_id          = $caseId
        category         = "Benign"
        ground_truth     = "NORMAL"
        actions          = $Description
        expected_stages  = @()
        source           = "real_pc"
        anonymized       = (-not $NoAnonymize.IsPresent)
        window_start     = $t.ToUniversalTime().ToString("o")
        window_end       = $wEnd.ToUniversalTime().ToString("o")
        security_count   = $counts["security.xml"]
        powershell_count = $counts["powershell.xml"]
        system_count     = $counts["system.xml"]
        created_at       = (Get-Date).ToUniversalTime().ToString("o")
    }
    [IO.File]::WriteAllText((Join-Path $dir "manifest.json"), ($manifest | ConvertTo-Json -Depth 4), $utf8)
    Write-Host ("  [+] {0}: Security {1} | PowerShell {2} | System {3}" -f $caseId, $counts["security.xml"], $counts["powershell.xml"], $counts["system.xml"]) -ForegroundColor Green
    $made++
    $t = $wEnd
}

Write-Host "[OK] Tao $made ca NORMAL ($skipped cua so khong co su kien) trong $OutDir" -ForegroundColor Cyan
if (-not $NoAnonymize) {
    Write-Host "     Da an danh: ten user / ten may / thu muc ho so. Van nen DOC LAI dong lenh (4688, 4104) truoc khi commit." -ForegroundColor Yellow
}
