# Windows PowerShell 5.1. Importing this module does not read or change logs.
Set-StrictMode -Version 2.0

function ConvertTo-LabTime {
    param([string]$Value)
    if ($Value -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,7})?(Z|[+-]\d{2}:\d{2})$') {
        throw 'Time must be ISO 8601 with explicit offset, e.g. 2026-10-24T10:00:00+07:00'
    }
    return [DateTimeOffset]::Parse($Value, [Globalization.CultureInfo]::InvariantCulture)
}

function Read-LabEvents {
    param([hashtable]$Filter)
    Get-WinEvent -FilterHashtable $Filter -ErrorAction Stop
}

function Write-LabFile {
    param([string]$Path, [string]$Text)
    $temporary = $Path + '.part'
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($temporary, $Text, $encoding)
    [IO.File]::Move($temporary, $Path)
}

function Export-LabLogs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$StartTime,
        [Parameter(Mandatory=$true)][string]$EndTime,
        [string]$OutputRoot = 'C:\Lab'
    )
    $start = ConvertTo-LabTime $StartTime
    $end = ConvertTo-LabTime $EndTime
    if ($start -gt $end) { throw 'StartTime must not be after EndTime' }
    $runId = [Guid]::NewGuid().ToString()
    $folder = Join-Path $OutputRoot ((Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + $runId)
    New-Item -ItemType Directory -Path $folder -ErrorAction Stop | Out-Null
    $manifest = [ordered]@{
        schema_version = 1; run_id = $runId; computer = $env:COMPUTERNAME
        created_utc = [DateTimeOffset]::UtcNow.ToString('o')
        start_input = $StartTime; end_input = $EndTime
        start_utc = $start.ToUniversalTime().ToString('o'); end_utc = $end.ToUniversalTime().ToString('o')
        start_machine_local = $start.ToLocalTime().ToString('o'); end_machine_local = $end.ToLocalTime().ToString('o')
        machine_timezone = [TimeZoneInfo]::Local.Id
        interval = 'inclusive'; status = 'complete'; sources = @()
    }
    $definitions = @(
        @{ name='Security'; log='Security'; ids=@(4624,4625,4688); file='security.xml' },
        @{ name='PowerShell'; log='Microsoft-Windows-PowerShell/Operational'; ids=@(4104); file='powershell.xml' }
    )
    foreach ($definition in $definitions) {
        $source = [ordered]@{
            source=$definition.name; channel=$definition.log; event_ids=$definition.ids
            status='success'; count=0; counts_by_id=@{}; file=$null; sha256=$null
            first_event_utc=$null; last_event_utc=$null; error=$null
        }
        $phase = 'read'
        try {
            $filter = @{LogName=$definition.log; Id=$definition.ids; StartTime=$start.UtcDateTime; EndTime=$end.UtcDateTime}
            $events = @()
            try {
                $events = @(Read-LabEvents $filter)
            } catch {
                if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
            }
            # Explicitly enforce the closed interval, including boundary timestamps.
            $events = @($events | Where-Object {
                $_.TimeCreated.ToUniversalTime() -ge $start.UtcDateTime -and
                $_.TimeCreated.ToUniversalTime() -le $end.UtcDateTime
            } | Sort-Object TimeCreated, RecordId)
            $source.count = $events.Count
            foreach ($id in $definition.ids) {
                $source.counts_by_id[[string]$id] = @($events | Where-Object { $_.Id -eq $id }).Count
            }
            if ($events.Count -eq 0) { $source.status = 'no_events' }
            else {
                $source.first_event_utc = $events[0].TimeCreated.ToUniversalTime().ToString('o')
                $source.last_event_utc = $events[-1].TimeCreated.ToUniversalTime().ToString('o')
            }
            $xml = '<Events>' + (($events | ForEach-Object { $_.ToXml() }) -join "`r`n") + '</Events>'
            $phase = 'write'
            $path = Join-Path $folder $definition.file
            Write-LabFile $path $xml
            $source.file = $definition.file
            $source.sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
        } catch {
            $source.status = if ($phase -eq 'write') { 'write_error' }
                             elseif ($_.Exception -is [UnauthorizedAccessException] -or $_.CategoryInfo.Category -eq 'PermissionDenied') { 'permission_denied' }
                             else { 'read_error' }
            $source.error = @{message=$_.Exception.Message; id=$_.FullyQualifiedErrorId; phase=$phase}
            $manifest.status = 'partial'
        }
        $manifest.sources += $source
    }
    try {
        Write-LabFile (Join-Path $folder 'manifest.json') ($manifest | ConvertTo-Json -Depth 8)
    } catch {
        throw "Manifest write failed. Collection is NOT complete. Preserve folder: $folder. $($_.Exception.Message)"
    }
    [pscustomobject]@{Folder=$folder; Manifest=$manifest}
}

Export-ModuleMember -Function Export-LabLogs
