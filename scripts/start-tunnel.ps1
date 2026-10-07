param([string]$Profile = "personal-dc")

$ErrorActionPreference = "Stop"
$Repo = Split-Path -Parent $PSScriptRoot
$Client = Join-Path $Repo "vendor\tunnel-client\tunnel-client.exe"

if (-not $env:CONTROL_PLANE_API_KEY) {
    throw "CONTROL_PLANE_API_KEY is not set in this PowerShell session."
}
if (-not (Test-Path $Client)) {
    throw "tunnel-client is not installed. Run .\scripts\install-tunnel-client.ps1 first."
}

Push-Location $Repo
try {
    & $Client doctor --profile $Profile --explain
    if ($LASTEXITCODE -ne 0) { throw "Tunnel doctor failed." }
    & $Client run --profile $Profile
}
finally {
    Pop-Location
}
