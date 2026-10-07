param(
    [Parameter(Mandatory = $true)]
    [string]$TunnelId,
    [string]$Profile = "personal-dc"
)

$ErrorActionPreference = "Stop"
$Repo = Split-Path -Parent $PSScriptRoot
$Client = Join-Path $Repo "vendor\tunnel-client\tunnel-client.exe"

if (-not $env:CONTROL_PLANE_API_KEY) {
    throw "CONTROL_PLANE_API_KEY is not set in this PowerShell session."
}
if (-not (Test-Path $Client)) {
    & (Join-Path $PSScriptRoot "install-tunnel-client.ps1")
}

$McpCommand = 'python "' + (Join-Path $Repo "run_server.py") + '"'
Push-Location $Repo
try {
    & $Client init --sample sample_mcp_stdio_local --profile $Profile --tunnel-id $TunnelId --mcp-command $McpCommand
    & $Client doctor --profile $Profile --explain
}
finally {
    Pop-Location
}
