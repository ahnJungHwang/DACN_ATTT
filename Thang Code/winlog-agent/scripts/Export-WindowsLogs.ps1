#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$StartTime,
    [Parameter(Mandatory=$true)][string]$EndTime,
    [string]$OutputRoot = 'C:\Lab'
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Collection.psm1') -Force
$result = Export-LabLogs -StartTime $StartTime -EndTime $EndTime -OutputRoot $OutputRoot
$result | ConvertTo-Json -Depth 10
if ($result.Manifest.status -eq 'partial') { exit 2 }
