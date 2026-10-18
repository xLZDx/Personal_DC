$script:PersonalDCLogRetentionDays = 7
$script:PersonalDCLogStreams = @("autostart", "backend.stdout", "backend.stderr", "tunnel.stdout", "tunnel.stderr")

function Get-PersonalDCLogPath([string]$Directory, [string]$Stream, [datetime]$TimestampUtc = [DateTime]::UtcNow) {
    if ($Stream -notin $script:PersonalDCLogStreams) {
        throw "Unsupported Personal DC log stream '$Stream'."
    }
    $day = $TimestampUtc.ToUniversalTime().ToString("yyyyMMdd", [Globalization.CultureInfo]::InvariantCulture)
    return Join-Path $Directory ("{0}-{1}.log" -f $Stream, $day)
}

function Remove-ExpiredPersonalDCLogs(
    [string]$Directory,
    [datetime]$NowUtc = [DateTime]::UtcNow,
    [switch]$IncludeChildStreams,
    [string[]]$ExcludeFileNames = @()
) {
    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) { return }
    $cutoff = $NowUtc.ToUniversalTime().AddDays(-$script:PersonalDCLogRetentionDays)
    try {
        $files = @(Get-ChildItem -LiteralPath $Directory -File -ErrorAction Stop)
    }
    catch {
        return [pscustomobject]@{
            file = $Directory
            operation = "enumerate"
            error_type = $_.Exception.GetType().FullName
        }
    }

    $failures = @()
    foreach ($file in $files) {
        if ($ExcludeFileNames -contains $file.Name) { continue }
        $matchesEventLog = $file.Name -match '^autostart(-\d{8})?\.log$'
        $matchesChildLog = $IncludeChildStreams -and $file.Name -match '^(backend\.stdout|backend\.stderr|tunnel\.stdout|tunnel\.stderr)(-\d{8})?\.log$'
        if (-not ($matchesEventLog -or $matchesChildLog)) { continue }
        if ($file.LastWriteTimeUtc -lt $cutoff) {
            try {
                Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
            }
            catch {
                $failures += [pscustomobject]@{
                    file = $file.Name
                    operation = "delete"
                    error_type = $_.Exception.GetType().FullName
                }
            }
        }
    }
    return $failures
}

function Invoke-PersonalDCLogCriticalSection([scriptblock]$Action) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $identity.User) { throw "Could not resolve the Personal DC log writer SID." }

    $mutexName = "Global\Personal_DC_V2_Tunnel_Log_$($identity.User.Value)"
    $mutexSecurity = [System.Security.AccessControl.MutexSecurity]::new()
    $fullControl = [System.Security.AccessControl.MutexRights]::FullControl
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $mutexSecurity.AddAccessRule([System.Security.AccessControl.MutexAccessRule]::new($identity.User, $fullControl, $allow))
    $systemSid = [Security.Principal.SecurityIdentifier]::new("S-1-5-18")
    $mutexSecurity.AddAccessRule([System.Security.AccessControl.MutexAccessRule]::new($systemSid, $fullControl, $allow))

    $createdNew = $false
    $mutex = [Threading.Mutex]::new($false, $mutexName, [ref]$createdNew, $mutexSecurity)
    $held = $false
    try {
        try { $held = $mutex.WaitOne([TimeSpan]::FromSeconds(10)) }
        catch [Threading.AbandonedMutexException] { $held = $true }
        if (-not $held) { throw "Timed out waiting for the Personal DC log mutex." }
        & $Action
    }
    finally {
        if ($held) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
}

function Write-PersonalDCEvent(
    [string]$Directory,
    [string]$Level,
    [string]$Event,
    [hashtable]$Data = @{},
    [datetime]$Timestamp = [DateTime]::Now
) {
    New-Item -ItemType Directory -Force -Path $Directory | Out-Null
    Invoke-PersonalDCLogCriticalSection {
        $eventCleanupFailures = @(Remove-ExpiredPersonalDCLogs -Directory $Directory -NowUtc $Timestamp.ToUniversalTime())
        $entry = [ordered]@{
            timestamp = $Timestamp.ToString("o")
            level = $Level
            event = $Event
            data = $Data
        }
        if ($eventCleanupFailures.Count -gt 0) { $entry["cleanup_warnings"] = $eventCleanupFailures }
        $path = Get-PersonalDCLogPath -Directory $Directory -Stream "autostart" -TimestampUtc $Timestamp.ToUniversalTime()
        $line = ($entry | ConvertTo-Json -Compress -Depth 5) + [Environment]::NewLine
        [IO.File]::AppendAllText($path, $line, [Text.UTF8Encoding]::new($false))
    }
}
