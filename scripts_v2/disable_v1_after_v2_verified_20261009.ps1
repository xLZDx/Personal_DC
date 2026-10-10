# Carefully retire v1 logon task ONLY AFTER v2 has demonstrated readiness.
# No deletion, no blanket Python/tunnel process termination.
[CmdletBinding()]
param([switch]$StopV1TaskAfterDisable)
$ErrorActionPreference='Stop'
$v2task = Get-ScheduledTask -TaskName 'Personal_DC_V2_Tunnel' -ErrorAction SilentlyContinue
$v1task = Get-ScheduledTask -TaskName 'Personal_DC_Tunnel' -ErrorAction SilentlyContinue
if (-not $v2task -or $v2task.State -eq 'Disabled') {
    throw 'V2_LOGON_TASK_NOT_REGISTERED_AND_ENABLED'
}
function Endpoint([string]$url) {
    try {
        $r=Invoke-WebRequest -UseBasicParsing -Uri $url -TimeoutSec 4
        return [string]$r.Content.Trim()
    } catch {
        throw 'V2_TUNNEL_NOT_READY_ABORT_RETIREMENT'
    }
}
for($i=0;$i -lt 3;$i++) {
    if ((Endpoint 'http://127.0.0.1:18081/healthz') -cne 'live' -or
        (Endpoint 'http://127.0.0.1:18081/readyz') -cne 'ready') {
        throw 'V2_NOT_HEALTHY_ABORT_RETIREMENT'
    }
    if ($i -lt 2) { Start-Sleep -Seconds 2 }
}
if (-not $v1task) { Write-Output 'V1_TASK_ALREADY_MISSING';exit 0 }
if ($v1task.State -eq 'Disabled') { Write-Output 'V1_TASK_ALREADY_DISABLED';exit 0 }
Disable-ScheduledTask -TaskName 'Personal_DC_Tunnel' -ErrorAction Stop | Out-Null
if ((Get-ScheduledTask -TaskName 'Personal_DC_Tunnel').State -ne 'Disabled') {
    throw 'V1_TASK_DISABLE_NOT_CONFIRMED'
}
Write-Output 'V1_AUTOSTART_DISABLED'
if($StopV1TaskAfterDisable) {
    # Explicit opt-in, this may disconnect the old ChatGPT v1 app.
    Stop-ScheduledTask -TaskName 'Personal_DC_Tunnel' -ErrorAction Stop
    Write-Output 'V1_SCHEDULED_TASK_STOP_REQUESTED'
}
Write-Output 'V1_FILES_AND_DPAPI_KEY_PRESERVED_FOR_ROLLBACK'
