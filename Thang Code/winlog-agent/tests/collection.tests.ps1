# Synthetic events only. Runs under Windows PowerShell 5.1 without Pester.
$ErrorActionPreference = 'Stop'
$modulePath = Join-Path $PSScriptRoot '../scripts/Collection.psm1'
foreach ($file in @($modulePath, (Join-Path $PSScriptRoot '../scripts/Export-WindowsLogs.ps1'))) {
    $tokens = $null; $parseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $file), [ref]$tokens, [ref]$parseErrors) | Out-Null
    if ($parseErrors.Count -ne 0) { throw ($parseErrors | Out-String) }
}
Import-Module $modulePath -Force
$module = Get-Module Collection
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('winlog-collection-test-' + [Guid]::NewGuid())
& $module {
    param($root)
    function Assert($condition, $message) { if (-not $condition) { throw $message } }
    $script:mode = 'normal'
    function Read-LabEvents {
        param($Filter)
        Assert (-not $Filter.ContainsKey('MaxEvents')) 'No implicit limit allowed'
        if ($script:mode -eq 'empty') { return }
        if ($script:mode -eq 'noMatching') {
            $record = New-Object Management.Automation.ErrorRecord ([Exception]::new('no match')), 'NoMatchingEventsFound', 'ObjectNotFound', $null
            throw $record
        }
        if ($Filter.LogName -ne 'Security' -and $script:mode -eq 'denied') { throw [UnauthorizedAccessException]::new('denied') }
        if ($Filter.LogName -ne 'Security' -and $script:mode -eq 'readError') { throw 'channel failed' }
        foreach ($seconds in @(-1,0,30,60,61)) {
            $event = [pscustomobject]@{ TimeCreated=$Filter.StartTime.AddSeconds($seconds); RecordId=$seconds+2; Id=$Filter.Id[0] }
            $event | Add-Member ScriptMethod ToXml { '<Event><System><EventID>' + $this.Id + '</EventID></System></Event>' }
            $event
        }
    }
    $params = @{StartTime='2026-10-24T10:00:00+07:00'; EndTime='2026-10-24T10:01:00+07:00'; OutputRoot=$root}
    $result = Export-LabLogs @params
    Assert ($result.Manifest.status -eq 'complete') 'normal status'
    Assert ($result.Manifest.sources[0].count -eq 3) 'inclusive boundaries'
    Assert ($result.Manifest.start_utc -like '2026-10-24T03:00:00*') 'UTC conversion'
    $xml = [xml](Get-Content -LiteralPath (Join-Path $result.Folder 'security.xml') -Raw)
    Assert ($xml.Events.Event.Count -eq 3) 'XML count'
    $again = Export-LabLogs @params
    Assert ($again.Folder -ne $result.Folder) 'must not overwrite'
    foreach ($mode in @('empty','noMatching','denied','readError')) {
        $script:mode = $mode
        $result = Export-LabLogs @params
        if ($mode -in @('empty','noMatching')) {
            Assert ($result.Manifest.sources[0].status -eq 'no_events') 'empty source'
            Assert ($result.Manifest.sources[0].count -eq 0) 'empty count'
        } else {
            Assert ($result.Manifest.status -eq 'partial') 'partial status'
            Assert ($result.Manifest.sources[0].status -eq 'success') 'retain successful source'
            $expected = if ($mode -eq 'denied') {'permission_denied'} else {'read_error'}
            Assert ($result.Manifest.sources[1].status -eq $expected) 'correct error'
        }
    }
    foreach ($bad in @('2026-10-24T10:00:00', 'invalid', '2026-10-24T11:00:00+07:00')) {
        $rejected = $false
        try { Export-LabLogs -StartTime $bad -EndTime $params.EndTime -OutputRoot $root | Out-Null }
        catch { $rejected = $true }
        Assert $rejected 'invalid time accepted'
    }
    $script:mode = 'normal'
    $originalWriter = ${function:Write-LabFile}
    function Write-LabFile {
        param($Path,$Text)
        if ($Path -like '*powershell.xml') { throw [IO.IOException]::new('disk failure') }
        & $originalWriter $Path $Text
    }
    $result = Export-LabLogs @params
    Assert ($result.Manifest.status -eq 'partial') 'write failure status'
    Assert ($result.Manifest.sources[1].status -eq 'write_error') 'write failure kind'
    function Write-LabFile { param($Path,$Text); throw [IO.IOException]::new('disk full') }
    $rejected = $false
    try { Export-LabLogs @params | Out-Null } catch { $rejected = $_.Exception.Message -like '*NOT complete*' }
    Assert $rejected 'manifest failure cannot report success'
    Write-Output "Collection tests passed; synthetic outputs retained: $root"
} $testRoot
