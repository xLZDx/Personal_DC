param(
    [Parameter(Mandatory = $true)]
    [string]$TunnelId,
    [string]$Profile = "personal-dc"
)

$ErrorActionPreference = "Stop"
& (Join-Path $PSScriptRoot "configure-http-tunnel.ps1") -TunnelId $TunnelId -Profile $Profile
