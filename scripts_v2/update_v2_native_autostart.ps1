# Upgrade the EXISTING scheduled task Personal_DC_V2_Tunnel to the native supervisor.
# - Does not create another task, tunnel or key. Non-elevated (RunLevel Limited), current user, at logon.
# - Exports the current task XML first so the change is reversible. -Rollback restores the immutable ORIGINAL
#   (pre-cutover) task deterministically; -Rollback -Previous restores the newest snapshot that is NOT the native task.
#   Re-running the updater never snapshots an already-native task, so rollback can never "restore" the new task.
# - v1 (Personal_DC) is never touched.
[CmdletBinding()]
param([switch]$DryRun, [switch]$Rollback, [switch]$Previous)
$ErrorActionPreference = "Stop"
$Task   = "Personal_DC_V2_Tunnel"
$Root   = Split-Path -Parent $PSScriptRoot
$State  = Join-Path $env:LOCALAPPDATA "Personal_DC_V2"
$Backup = Join-Path $State "backups"
New-Item -ItemType Directory -Force -Path $Backup | Out-Null
$current = Get-ScheduledTask -TaskName $Task -ErrorAction SilentlyContinue
if (-not $current) { throw "V2_TASK_NOT_FOUND: $Task (create it first with install_v2_windows_autostart_20261009.ps1)" }

if ($Rollback) {
    $orig = Join-Path $Backup "task-$Task-ORIGINAL.xml"
    if ($Previous) {
        $pick = Get-ChildItem -LiteralPath $Backup -Filter "task-$Task-*.xml" | Where-Object { $_.Name -notlike "*-ORIGINAL.xml" } |
            Sort-Object LastWriteTime -Descending |
            Where-Object { [IO.File]::ReadAllText($_.FullName) -notlike "*start_v2_native_supervisor.ps1*" } | Select-Object -First 1
    } else { $pick = Get-Item -LiteralPath $orig -ErrorAction SilentlyContinue }
    if (-not $pick) { throw "NO_TASK_BACKUP_FOUND" }
    if ($DryRun) { Write-Output ("WOULD_RESTORE " + $pick.FullName); exit 0 }
    Register-ScheduledTask -TaskName $Task -Xml ([IO.File]::ReadAllText($pick.FullName)) -Force | Out-Null
    Write-Output ("V2_TASK_RESTORED_FROM=" + $pick.FullName); exit 0
}

$user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$script = Join-Path $PSScriptRoot "start_v2_native_supervisor.ps1"
if (-not (Test-Path -LiteralPath $script)) { throw "SUPERVISOR_SCRIPT_MISSING" }
$arg = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $script + '"'
$action    = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $arg -WorkingDirectory $Root
$trigger   = New-ScheduledTaskTrigger -AtLogOn -User $user
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
# The supervisor handles its own restarts; the scheduler restart is a second safety net.
$settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
if ($DryRun) { Write-Output ("WOULD_UPDATE_TASK=" + $Task + " ACTION=powershell.exe " + $arg); exit 0 }
$stamp = (Get-Date).ToString("yyyyMMddTHHmmss")
$xml = Export-ScheduledTask -TaskName $Task
# The very first export (the pre-v2.2 task) is kept immutably; later exports never replace it.
$orig = Join-Path $Backup "task-$Task-ORIGINAL.xml"
if (-not (Test-Path -LiteralPath $orig)) { Set-Content -LiteralPath $orig -Value $xml -Encoding Unicode }
if ($current.Actions.Arguments -like "*start_v2_native_supervisor.ps1*") { Write-Output "ALREADY_NATIVE_SUPERVISOR (settings refreshed, no new snapshot)" }
else { Set-Content -LiteralPath (Join-Path $Backup "task-$Task-$stamp.xml") -Value $xml -Encoding Unicode }
Set-ScheduledTask -TaskName $Task -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
$after = Get-ScheduledTask -TaskName $Task
if ($after.State -eq "Disabled") { throw "V2_TASK_DISABLED_AFTER_UPDATE" }
if ($after.Actions.Arguments -notlike "*start_v2_native_supervisor.ps1*") { throw "V2_TASK_ACTION_NOT_APPLIED" }
Write-Output "CUTOVER_NOTE: the running tunnel/backend keep running; the supervisor adopts a verified backend and refuses a busy 18081. Stop the old tunnel before the next logon or the supervisor will wait."
Write-Output "V2_AUTOSTART_UPDATED_TO_NATIVE_SUPERVISOR"
Write-Output ("TASK=" + $Task + " USER=" + $user + " BACKUP=task-$Task-$stamp.xml")
Write-Output "V1_NOT_MODIFIED"
