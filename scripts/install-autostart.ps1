param()
$ErrorActionPreference = "Stop"
$Repo = Split-Path -Parent $PSScriptRoot
$StartScript = Join-Path $PSScriptRoot "start-autostart.ps1"
$RecoveryScript = Join-Path $PSScriptRoot "recover-autostart.ps1"
$TaskName = "Personal_DC_V2_Tunnel"
$RecoveryTaskName = "Personal_DC_V2_Tunnel_Recovery"
$UserId = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$ConsoleHost = Join-Path $env:SystemRoot "System32\conhost.exe"
$WindowsPowerShell = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"

function New-HiddenPowerShellTaskAction([string]$ScriptPath) {
    $arguments = '--headless "' + $WindowsPowerShell + '" -NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $ScriptPath + '"'
    New-ScheduledTaskAction -Execute $ConsoleHost -Argument $arguments -WorkingDirectory $Repo
}

$Action = New-HiddenPowerShellTaskAction $StartScript
$SupervisorPrincipal = New-ScheduledTaskPrincipal -UserId $UserId -LogonType Interactive -RunLevel Limited
$SupervisorSettings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero)

$RecoveryAction = New-HiddenPowerShellTaskAction $RecoveryScript
$RecoveryLogonTrigger = New-ScheduledTaskTrigger -AtLogOn -User $UserId
$RecoveryStart = (Get-Date).AddMinutes(1)
$RecoveryDailyTrigger = New-ScheduledTaskTrigger -Daily -At $RecoveryStart -DaysInterval 1
$RecoveryRepetition = New-CimInstance `
    -Namespace "Root/Microsoft/Windows/TaskScheduler" `
    -ClassName MSFT_TaskRepetitionPattern `
    -ClientOnly `
    -Property @{
        Interval = "PT1M"
        Duration = "P1D"
        StopAtDurationEnd = $false
    }
$RecoveryDailyTrigger.Repetition = $RecoveryRepetition
$RecoveryTriggers = @($RecoveryLogonTrigger, $RecoveryDailyTrigger)
$RecoveryPrincipal = New-ScheduledTaskPrincipal -UserId $UserId -LogonType Interactive -RunLevel Limited
$RecoverySettings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -MultipleInstances Parallel `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Seconds 30)

# Register the recovery task first. Its global mutex and state check make its
# logon and minute triggers safe while the existing supervisor remains running.
Register-ScheduledTask `
    -TaskName $RecoveryTaskName `
    -Action $RecoveryAction `
    -Trigger $RecoveryTriggers `
    -Principal $RecoveryPrincipal `
    -Settings $RecoverySettings `
    -Description "Recover Personal DC v2.2 when its long-running supervisor is not active." `
    -Force | Out-Null

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $Action `
    -Principal $SupervisorPrincipal `
    -Settings $SupervisorSettings `
    -Description "Supervise Personal DC v2.2 and its existing OpenAI Secure MCP Tunnel profile when started by its recovery task." `
    -Force | Out-Null

Write-Host "Scheduled tasks installed: $TaskName, $RecoveryTaskName" -ForegroundColor Green
Get-ScheduledTask -TaskName @($TaskName, $RecoveryTaskName) | Select-Object TaskName,State
