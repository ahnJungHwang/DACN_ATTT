# No audit changes, accounts or logins: only test the extracted native-command helper.
$ErrorActionPreference='Stop'
$path=Join-Path $PSScriptRoot '../scripts/lab/run_demo.ps1'
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $path),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
$function=$ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-CheckedNative'},$true)
Invoke-Expression $function.Extent.Text
Invoke-CheckedNative $env:ComSpec @('/d','/c','exit 0')
$failed=$false
try { Invoke-CheckedNative $env:ComSpec @('/d','/c','exit 7') } catch { $failed=$_.Exception.Message -match '7' }
if (-not $failed) { throw 'Nonzero native exit was not rejected' }
Write-Output 'PASS: syntax, native exit 0 accepted, exit 7 rejected; no lab actions executed.'
# Extract helpers only; mock account cmdlets, never mutate accounts.
foreach ($name in @('Remove-DemoOwnedAccount','Export-DemoEvidence')) {
 $definition=$ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true)
 Invoke-Expression $definition.Extent.Text
}
$script:deleted=@()
function Get-LocalUser { param($Name) [pscustomobject]@{SID=[pscustomobject]@{Value='S-1-5-21-1000'}} }
function Remove-LocalUser { param($SID) $script:deleted+= $SID }
Remove-DemoOwnedAccount -Created $false -Sid 'S-1-5-21-1000' | Out-Null
if ($script:deleted.Count) { throw 'Deleted unowned account' }
$rejected=$false
try { Remove-DemoOwnedAccount -Created $true -Sid 'S-1-5-21-2000' } catch { $rejected=$true }
if (-not $rejected -or $script:deleted.Count) { throw 'SID mismatch not protected' }
Remove-DemoOwnedAccount -Created $true -Sid 'S-1-5-21-1000' | Out-Null
if ($script:deleted.Count -ne 1 -or $script:deleted[0] -ne 'S-1-5-21-1000') { throw 'Owned account cleanup incorrect' }
function Export-LabLogs { param($StartTime,$EndTime,$OutputRoot) @{Start=$StartTime;End=$EndTime;Root=$OutputRoot} }
$result=Export-DemoEvidence -Start '2026-11-03T09:00:00+07:00' -End '2026-11-03T09:02:00+07:00' -Root 'unused-test'
if ($result.Start -ne '2026-11-03T09:00:00+07:00' -or $result.End -ne '2026-11-03T09:02:00+07:00') { throw 'Demo interval changed' }
Write-Output 'PASS: unowned account preserved; changed SID refused; owned SID removed; exact export boundaries forwarded (mocked).'
