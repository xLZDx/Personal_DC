param()
$ErrorActionPreference = "Stop"
$SecretPath = Join-Path $env:LOCALAPPDATA "Personal_DC\secrets\runtime-key.dpapi"
$TaskName = "Personal_DC_Tunnel"
$UrlFile = Join-Path $env:USERPROFILE ".local\state\tunnel-client\health\personal-dc.url"

$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
$result = [ordered]@{
    SecretExists = Test-Path $SecretPath
    TaskExists = [bool]$task
    TaskState = if ($task) { [string]$task.State } else { "Missing" }
    Health = $false
    Ready = $false
    HealthBase = ""
}

if (Test-Path $UrlFile) {
    $base = (Get-Content $UrlFile -Raw).Trim()
    $result.HealthBase = $base
    if ($base) {
        try {
            $result.Health = ((Invoke-WebRequest -UseBasicParsing ($base + "/healthz") -TimeoutSec 3).Content.Trim() -eq "live")
            $result.Ready = ((Invoke-WebRequest -UseBasicParsing ($base + "/readyz") -TimeoutSec 3).Content.Trim() -eq "ready")
        } catch {}
    }
}

[pscustomobject]$result | Format-List
