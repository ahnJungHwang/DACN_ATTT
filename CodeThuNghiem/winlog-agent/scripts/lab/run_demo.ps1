#requires -Version 5.1
[CmdletBinding()]
param([string]$OutputRoot='C:\demo')
function Remove-DemoOwnedAccount {
 param([bool]$Created,[string]$Sid)
 if (-not $Created) { return 'not_owned_no_changes' }
 if ([string]::IsNullOrWhiteSpace($Sid)) { throw 'Missing owned SID; refusing cleanup' }
 $account=Get-LocalUser lab_demo -ErrorAction Stop
 if ($account.SID.Value -ne $Sid) { throw 'Account SID changed; refusing cleanup' }
 Remove-LocalUser -SID $Sid -ErrorAction Stop
 return 'created_account_removed'
}
function Export-DemoEvidence {
 param([string]$Start,[string]$End,[string]$Root)
 Export-LabLogs -StartTime $Start -EndTime $End -OutputRoot $Root
}
$ErrorActionPreference='Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators')) { throw 'Run as Administrator in lab VM' }
Import-Module (Join-Path $PSScriptRoot '..\Collection.psm1') -Force
if (Get-LocalUser lab_demo -ErrorAction SilentlyContinue) { throw 'lab_demo already exists; use a clean VM. Nothing changed.' }
$folder=Join-Path $OutputRoot ('scenario-'+[guid]::NewGuid())
New-Item -ItemType Directory -Path $folder -Force | Out-Null
$journal=@{status='running';steps=@();log_correlation_verified=$false}
$created=$false; $code=1; $start=[DateTimeOffset]::Now.ToString('o')
function Invoke-CheckedNative {
 param([string]$File,[string[]]$Arguments)
 $output=& $File @Arguments 2>&1
 if ($LASTEXITCODE -ne 0) { throw "$File failed ($LASTEXITCODE): $output" }
}
try {
 Invoke-CheckedNative auditpol.exe @('/set','/subcategory:{0CCE9215-69AE-11D9-BED3-505054503030}','/success:enable','/failure:enable')
 Invoke-CheckedNative auditpol.exe @('/set','/subcategory:{0CCE922B-69AE-11D9-BED3-505054503030}','/success:enable')
 Invoke-CheckedNative reg.exe @('add','HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit','/v','ProcessCreationIncludeCmdLine_Enabled','/t','REG_DWORD','/d','1','/f')
 Invoke-CheckedNative reg.exe @('add','HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging','/v','EnableScriptBlockLogging','/t','REG_DWORD','/d','1','/f')
 $password=ConvertTo-SecureString ('Lab!aA9-'+[guid]::NewGuid()) -AsPlainText -Force
 $user=New-LocalUser lab_demo -Password $password
 $created=$true
 Add-LocalGroupMember -Group (Get-LocalGroup -SID 'S-1-5-32-545') -Member $user
 $journal.sid=$user.SID.Value
 $credential=[pscredential]::new("$env:COMPUTERNAME\lab_demo",$password)
 $exe=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
 for ($i=1;$i -le 5;$i++) {
  $bad=[pscredential]::new($credential.UserName,(ConvertTo-SecureString ('Wrong!'+[guid]::NewGuid()) -AsPlainText -Force))
  try {
   Start-Process $exe -Credential $bad -ArgumentList '-NoProfile -NonInteractive -Command exit' -WorkingDirectory $env:SystemRoot -WindowStyle Hidden -Wait
   throw 'Unexpected successful bad-password login'
  } catch {
   $exception=$_.Exception
   while ($exception.InnerException) { $exception=$exception.InnerException }
   if ($exception -isnot [ComponentModel.Win32Exception] -or $exception.NativeErrorCode -ne 1326) { throw "Attempt $i failed for a reason other than bad password; inspect lockout/logon policy." }
   $journal.steps+=@{step='bad_password';attempt=$i;win32_code=1326;time=[DateTimeOffset]::Now.ToString('o')}
  }
 }
 # Literal child commands: one credentialed parent, all children inherit its token.
 $child='$ErrorActionPreference="Stop"; try { $id=[Security.Principal.WindowsIdentity]::GetCurrent(); if ($id.User.Value -ne "__SID__") { throw "Wrong identity" }; Write-Output ("VERIFIED_SID="+$id.User.Value); whoami.exe /all; if ($LASTEXITCODE -ne 0) { throw "whoami failed" }; whoami.exe /logonid; if ($LASTEXITCODE -ne 0) { throw "logonid failed" }; Write-Output "LAB_ACTIVITY_COMPLETED"; exit 0 } catch { Write-Error $_ -ErrorAction Continue; exit 1 }'
 $child=$child.Replace('__SID__',$user.SID.Value)
 $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($child))
 $stdout=Join-Path $folder 'activity.stdout.txt'
 $process=Start-Process $exe -Credential $credential -ArgumentList "-NoProfile -NonInteractive -EncodedCommand $encoded" -WorkingDirectory $env:SystemRoot -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError (Join-Path $folder 'activity.stderr.txt') -PassThru -Wait
 $process.Refresh()
 if ($process.ExitCode -ne 0) { throw "Activity exit code: $($process.ExitCode)" }
 $output=Get-Content $stdout -Raw
 if (-not $output.Contains('VERIFIED_SID='+$user.SID.Value) -or -not $output.Contains('LAB_ACTIVITY_COMPLETED')) { throw 'Identity/completion marker missing' }
 $journal.steps+=@{step='activity_completed';account=$credential.UserName;sid=$user.SID.Value;pid=$process.Id;exit_code=$process.ExitCode}
 $journal.status='execution_completed_pending_log_review'; $code=0
} catch {
 $journal.status='failed';$journal.error=$_.Exception.Message;Write-Warning $journal.error
} finally {
 $end=[DateTimeOffset]::Now.ToString('o');$journal.start=$start;$journal.end=$end
 Start-Sleep -Seconds 3
 try {
  $result=Export-DemoEvidence -Start $start -End $end -Root $folder
  $journal.collection=@{folder=$result.Folder;status=$result.Manifest.status}
  if ($result.Manifest.status -eq 'partial' -and $code -eq 0) { $code=2 }
 } catch { $journal.collection=@{error=$_.Exception.Message};$journal.status='failed';$code=1 }
 if ($created) {
  try {
   $journal.cleanup=Remove-DemoOwnedAccount -Created $created -Sid $user.SID.Value
  } catch { $journal.cleanup=$_.Exception.Message;$journal.status='failed';$code=1 }
 }
 $journal | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $folder 'scenario-journal.json') -Encoding UTF8
 Write-Host "Status: $($journal.status). Evidence: $folder"
 Write-Host 'Verify 4625/4624/4688 SID and logon ID plus 4104 before approving the scenario.'
}
exit $code
