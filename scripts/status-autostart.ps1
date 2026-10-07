param()
$ErrorActionPreference = "Stop"
$SecretPath = Join-Path $env:LOCALAPPDATA "Personal_DC\secrets\runtime-key.dpapi"
$TaskName = "Personal_DC_Tunnel"
$HealthBase = "http://127.0.0.1:18080"

$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
$result = [ordered]@{
    SecretExists = Test-Path $SecretPath
    TaskExists = [bool]$task
    TaskState = if ($task) { [string]$task.State } else { "Missing" }
    Health = $false
    Ready = $false
    HealthBase = $HealthBase
}

try {
    $result.Health = ((Invoke-WebRequest -UseBasicParsing ($HealthBase + "/healthz") -TimeoutSec 3).Content.Trim() -eq "live")
    $result.Ready = ((Invoke-WebRequest -UseBasicParsing ($HealthBase + "/readyz") -TimeoutSec 3).Content.Trim() -eq "ready")
} catch {}

[pscustomobject]$result | Format-List
