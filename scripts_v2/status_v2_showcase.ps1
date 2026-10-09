# Read-only health/status for the independent v2 customer showcase.
[CmdletBinding()]
param()
$ErrorActionPreference = "Stop"
$root = Join-Path $env:LOCALAPPDATA "Personal_DC_V2"
$profiles = Join-Path $root "profiles"
function Listening([int]$port) {
    return [bool](Get-NetTCPConnection -LocalAddress "127.0.0.1" -LocalPort $port -State Listen -ErrorAction SilentlyContinue)
}
$v1 = Get-ScheduledTask -TaskName "Personal_DC_Tunnel" -ErrorAction SilentlyContinue
$v2 = Get-ScheduledTask -TaskName "Personal_DC_V2_Tunnel" -ErrorAction SilentlyContinue
$profile = @(Get-ChildItem -LiteralPath $profiles -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -in @("personal-dc-v2.yaml","personal-dc-v2.yml") })
$health = "not_started"
$ready = "not_started"
if (Listening 18081) {
    try {
        $health = (Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:18081/healthz" -TimeoutSec 3).Content.Trim()
        $ready = (Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:18081/readyz" -TimeoutSec 3).Content.Trim()
    } catch { $health = "unavailable"; $ready = "unavailable" }
}
[pscustomobject]@{
    V1BackendPort = 18765
    V1BackendListening = (Listening 18765)
    V1TunnelHealthPort = 18080
    V1ScheduledTask = if($v1){[string]$v1.State}else{"Missing"}
    V2BackendPort = 18766
    V2BackendListening = (Listening 18766)
    V2TunnelHealthPort = 18081
    V2TunnelHealth = $health
    V2TunnelReady = $ready
    V2ProfileExists = ($profile.Count -eq 1)
    V2RuntimeKeyDPAPI = Test-Path (Join-Path $root "secrets\runtime-key.dpapi")
    V2BackendKeyDPAPI = Test-Path (Join-Path $root "secrets\backend-key.dpapi")
    V2ScheduledTask = if($v2){[string]$v2.State}else{"Missing"}
    V2Identity = "Synthetic-only separate showcase"
    V2ProductionReady = $false
} | Format-List
