param()

$ErrorActionPreference = "Stop"
$TaskName = "Personal_DC_V2_Tunnel"
$LogPath = Join-Path (Split-Path -Parent $PSScriptRoot) "logs\autostart.log"
$Mutex = $null
$MutexHeld = $false
$ExitCode = 0

function Write-RecoveryEvent([string]$Level, [string]$Event, [hashtable]$Data = @{}) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $LogPath) | Out-Null
    $entry = [ordered]@{
        timestamp = (Get-Date).ToString("o")
        level = $Level
        event = $Event
        data = $Data
    }
    Add-Content -LiteralPath $LogPath -Value ($entry | ConvertTo-Json -Compress -Depth 5) -Encoding UTF8
}

try {
    $userSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    if (-not $userSid) { throw "Could not resolve the recovery task user SID." }

    $mutexName = "Global\Personal_DC_V2_Tunnel_Recovery_$($userSid.Value)"
    $mutexSecurity = [System.Security.AccessControl.MutexSecurity]::new()
    $fullControl = [System.Security.AccessControl.MutexRights]::FullControl
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $mutexSecurity.AddAccessRule([System.Security.AccessControl.MutexAccessRule]::new($userSid, $fullControl, $allow))
    $systemSid = [Security.Principal.SecurityIdentifier]::new("S-1-5-18")
    $mutexSecurity.AddAccessRule([System.Security.AccessControl.MutexAccessRule]::new($systemSid, $fullControl, $allow))

    $createdNew = $false
    $Mutex = [Threading.Mutex]::new($false, $mutexName, [ref]$createdNew, $mutexSecurity)
    try { $MutexHeld = $Mutex.WaitOne(0) }
    catch [Threading.AbandonedMutexException] { $MutexHeld = $true }

    if (-not $MutexHeld) {
        # The recovery task is Parallel so the scheduler accepts concurrent
        # triggers; this machine-wide mutex lets only one action request starts.
        $ExitCode = 0
    }
    else {
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if (-not $task) { throw "Recovery target task '$TaskName' is not registered." }

        switch ([string]$task.State) {
            { $_ -in @("Running", "Queued") } {
                Write-RecoveryEvent "INFO" "recovery_noop_supervisor_active" @{ state = [string]$task.State }
            }
            "Ready" {
                try {
                    Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop

                    $startDeadline = [DateTime]::UtcNow.AddSeconds(10)
                    $current = $null
                    do {
                        Start-Sleep -Milliseconds 200
                        $current = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
                    } until (($current -and [string]$current.State -in @("Running", "Queued")) -or [DateTime]::UtcNow -ge $startDeadline)

                    if (-not $current -or [string]$current.State -notin @("Running", "Queued")) {
                        throw "Task Scheduler did not activate '$TaskName' after the start request."
                    }
                    Write-RecoveryEvent "INFO" "recovery_start_confirmed" @{ state = [string]$current.State }
                }
                catch {
                    # A manual start can race this request. Treat that as
                    # recovered only after Scheduler confirms it is active.
                    $current = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
                    if ($current -and [string]$current.State -in @("Running", "Queued")) {
                        Write-RecoveryEvent "INFO" "recovery_start_race_already_active" @{ state = [string]$current.State }
                    }
                    else {
                        throw
                    }
                }
            }
            default { throw "Recovery target task '$TaskName' is not startable (state=$([string]$task.State))." }
        }
    }
}
catch {
    $message = $_.Exception.Message -replace '(?i)(authorization|api[_-]?key|token)(\s*[:=]\s*)[^\s,;]+', '$1$2[REDACTED]'
    try { Write-RecoveryEvent "ERROR" "recovery_failed" @{ error = $message } } catch { }
    $ExitCode = 1
}
finally {
    if ($MutexHeld -and $Mutex) { $Mutex.ReleaseMutex() }
    if ($Mutex) { $Mutex.Dispose() }
}

exit $ExitCode
