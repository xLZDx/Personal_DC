# Personal DC v2 Windows logon autostart. Non-elevated, non-destructive.
# Run with the Windows user owning the v2 DPAPI keys.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Task = 'Personal_DC_V2_Tunnel'
$LogonUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$start = Join-Path $PSScriptRoot 'start_v2_showcase.ps1'
$private = Join-Path $env:LOCALAPPDATA 'Personal_DC_V2'
$runtime = Join-Path $private 'secrets\runtime-key.dpapi'
$backend = Join-Path $private 'secrets\backend-key.dpapi'
$profile = Join-Path $private 'profiles\personal-dc-v2.yaml'
if (-not ((Test-Path $start) -and (Test-Path $runtime) -and (Test-Path $backend) -and (Test-Path $profile))) {
    throw 'V2_INSTALL_PRECHECK_FAILED'
}
if (Get-ScheduledTask -TaskName $Task -ErrorAction SilentlyContinue) {
    throw 'V2_TASK_ALREADY_EXISTS_REFUSE_OVERWRITE'
}
$cmd = '-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $start + '"'
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $cmd
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $LogonUser
$principal = New-ScheduledTaskPrincipal -UserId $LogonUser -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName $Task -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Personal DC v2 synthetic showcase. Separate from v1.' | Out-Null
$created = Get-ScheduledTask -TaskName $Task -ErrorAction Stop
if ($created.State -eq 'Disabled') { throw 'V2_TASK_DISABLED_AFTER_CREATION' }
Write-Output 'V2_AUTOSTART_REGISTERED'
Write-Output ('TASK=' + $Task)
Write-Output ('LOGON_USER=' + $LogonUser)
Write-Output 'V1_NOT_MODIFIED'
