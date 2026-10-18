param()
$ErrorActionPreference = "Stop"
$Repo = Split-Path -Parent $PSScriptRoot
$StartScript = Join-Path $PSScriptRoot "start-autostart.ps1"
$TaskName = "Personal_DC_V2_Tunnel"
$UserId = [Security.Principal.WindowsIdentity]::GetCurrent().Name

$ActionArgs = '-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $StartScript + '"'
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $ActionArgs -WorkingDirectory $Repo
$LogonTrigger = New-ScheduledTaskTrigger -AtLogOn -User $UserId
$DailyStart = (Get-Date).AddMinutes(1)
$DailyTrigger = New-ScheduledTaskTrigger -Daily -At $DailyStart -DaysInterval 1
$DailyRepetition = New-CimInstance `
    -Namespace "Root/Microsoft/Windows/TaskScheduler" `
    -ClassName MSFT_TaskRepetitionPattern `
    -ClientOnly `
    -Property @{
        Interval = "PT1M"
        Duration = "P1D"
        StopAtDurationEnd = $false
    }
$DailyTrigger.Repetition = $DailyRepetition
$Triggers = @($LogonTrigger, $DailyTrigger)
$Principal = New-ScheduledTaskPrincipal -UserId $UserId -LogonType Interactive -RunLevel Limited
$Settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -RestartCount 5 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -MultipleInstances IgnoreNew `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero)

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $Action `
    -Trigger $Triggers `
    -Principal $Principal `
    -Settings $Settings `
    -Description "Supervise Personal DC v2.2 and its existing OpenAI Secure MCP Tunnel profile at Windows logon." `
    -Force | Out-Null

Write-Host "Scheduled task installed: $TaskName" -ForegroundColor Green
Get-ScheduledTask -TaskName $TaskName | Select-Object TaskName,State
