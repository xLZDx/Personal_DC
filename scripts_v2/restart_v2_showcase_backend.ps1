# Restart *only* the verified native v2 Windows backend, never v1 or the tunnel.
# A short discovery interruption is expected while the local process restarts.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Join-Path $env:LOCALAPPDATA 'Personal_DC_V2'
$pidFile = Join-Path $root 'run\backend.pid'
$expected = 'dc_v2.native_personal_mcp'
if (-not (Test-Path -LiteralPath $pidFile -PathType Leaf)) {
    throw 'V2_BACKEND_PID_FILE_NOT_FOUND'
}
$raw = [IO.File]::ReadAllText($pidFile).Trim()
$pidNumber = 0
if (-not [int]::TryParse($raw, [ref]$pidNumber) -or $pidNumber -le 0) {
    throw 'V2_BACKEND_PID_INVALID'
}
$listener = @(Get-NetTCPConnection -LocalAddress '127.0.0.1' -LocalPort 18766 -State Listen -ErrorAction SilentlyContinue)
if ($listener.Count -ne 1 -or $listener[0].OwningProcess -ne $pidNumber) {
    throw 'V2_BACKEND_PORT_OWNER_MISMATCH'
}
$process = Get-CimInstance Win32_Process -Filter "ProcessId = $pidNumber" -ErrorAction Stop
if (-not $process -or $process.Name -ine 'python.exe' -or
    $process.CommandLine -notmatch [regex]::Escape($expected) -or
    $process.ExecutablePath -ne 'C:\Python314\python.exe') {
    throw 'V2_BACKEND_PROCESS_IDENTITY_UNVERIFIED'
}
Write-Output 'VERIFIED_ONLY_V2_BACKEND'
Stop-Process -Id $pidNumber -ErrorAction Stop
$limit = (Get-Date).AddSeconds(12)
while ((Get-Date) -lt $limit) {
    $busy = Get-NetTCPConnection -LocalAddress '127.0.0.1' -LocalPort 18766 -State Listen -ErrorAction SilentlyContinue
    if (-not $busy) { break }
    Start-Sleep -Milliseconds 200
}
if ($busy) { throw 'V2_BACKEND_PORT_NOT_RELEASED' }
& (Join-Path $PSScriptRoot 'start_v2_showcase.ps1') -BackendOnly
if ($LASTEXITCODE -ne 0) { throw 'V2_BACKEND_RESTART_FAILED' }
Write-Output 'V2_BACKEND_RESTARTED_AND_PROBED'
