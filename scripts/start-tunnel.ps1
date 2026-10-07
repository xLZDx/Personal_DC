param()

$ErrorActionPreference = "Stop"
$SecretPath = Join-Path $env:LOCALAPPDATA "Personal_DC\secrets\runtime-key.dpapi"

if (-not (Test-Path $SecretPath)) {
    throw "Secure runtime key is not stored yet. Run .\scripts\save-runtime-key.ps1 first."
}

& (Join-Path $PSScriptRoot "start-autostart.ps1")
