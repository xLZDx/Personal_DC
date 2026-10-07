param(
    [Parameter(Mandatory = $true)]
    [string]$TunnelId,
    [string]$Profile = "personal-dc"
)
$ErrorActionPreference = "Stop"
$Repo = Split-Path -Parent $PSScriptRoot
$Client = Join-Path $Repo "vendor\tunnel-client\tunnel-client.exe"
& $Client init --force --sample sample_mcp_remote_no_auth --profile $Profile --tunnel-id $TunnelId --mcp-server-url "http://127.0.0.1:18765/mcp" --health-listen-addr "127.0.0.1:18080"
if ($LASTEXITCODE -ne 0) { throw "Failed to configure HTTP tunnel profile." }
Write-Host "Configured stateless local HTTP MCP target." -ForegroundColor Green
