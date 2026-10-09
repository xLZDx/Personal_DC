# Read-only status of the Personal DC v2 native stack (task, supervisor, ports, identity).
[CmdletBinding()]
param()
$ErrorActionPreference = "Continue"
$State = Join-Path $env:LOCALAPPDATA "Personal_DC_V2"
$t = Get-ScheduledTask -TaskName "Personal_DC_V2_Tunnel" -ErrorAction SilentlyContinue
Write-Output ("TASK_STATE=" + $(if ($t) { $t.State } else { "MISSING" }))
if ($t) { Write-Output ("TASK_ACTION=" + ($t.Actions | ForEach-Object { $_.Execute + " " + $_.Arguments })) }
$sf = Join-Path $State "run\supervisor.json"
if (Test-Path -LiteralPath $sf) { Write-Output ("SUPERVISOR=" + (Get-Content -LiteralPath $sf -Raw)) } else { Write-Output "SUPERVISOR=NO_STATUS_FILE" }
foreach ($port in 18766, 18081) {
    $c = Get-NetTCPConnection -LocalAddress "127.0.0.1" -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    Write-Output ("PORT_" + $port + "=" + $(if ($c) { "LISTEN pid=" + $c[0].OwningProcess } else { "CLOSED" }))
}
$log = Get-ChildItem -LiteralPath (Join-Path $State "logs") -Filter "supervisor-*.log" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($log) { Write-Output "--- last supervisor log lines ---"; Get-Content -LiteralPath $log.FullName -Tail 8 }
