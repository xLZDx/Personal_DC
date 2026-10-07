param()
$ErrorActionPreference = "Stop"
$Repo = Split-Path -Parent $PSScriptRoot
$StartScript = Join-Path $PSScriptRoot "start-autostart.ps1"
$TaskName = "Personal_DC_Tunnel"
$UserId = [Security.Principal.WindowsIdentity]::GetCurrent().Name

$ActionArgs = '-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $StartScript + '"'
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $ActionArgs
$Trigger = New-ScheduledTaskTrigger -AtLogOn -User $UserId
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
    -Trigger $Trigger `
    -Principal $Principal `
    -Settings $Settings `
    -Description "Start Personal DC OpenAI Secure MCP Tunnel at Windows logon." `
    -Force | Out-Null

Write-Host "Scheduled task installed: $TaskName" -ForegroundColor Green
Get-ScheduledTask -TaskName $TaskName | Select-Object TaskName,State
