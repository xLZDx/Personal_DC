# Independently configure v2 profile, never touching the v1 personal-dc profile.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$TunnelId)
$ErrorActionPreference = "Stop"
if ($TunnelId -cnotmatch '^tunnel_[0-9a-f]{32}$') {
    throw "Use a fresh v2 tunnel_id from OpenAI Platform."
}
$root = Join-Path $env:LOCALAPPDATA "Personal_DC_V2"
$exe = Join-Path $root "bin\tunnel-client.exe"
$profiles = Join-Path $root "profiles"
if (-not (Test-Path -LiteralPath $exe)) { throw "Run bootstrap_v2_showcase.ps1 first." }
$existing = @(Get-ChildItem -LiteralPath $profiles -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -in @("personal-dc-v2.yaml","personal-dc-v2.yml") })
if ($existing.Count -gt 0) {
    $text = [IO.File]::ReadAllText($existing[0].FullName)
    if ($text.Contains($TunnelId)) {
        Write-Output "V2_TUNNEL_PROFILE_ALREADY_CONFIGURED"
        exit 0
    }
    throw "V2 profile already exists for a different tunnel. No overwrite."
}
& $exe init --sample sample_mcp_remote_no_auth --profile personal-dc-v2 --profile-dir $profiles --tunnel-id $TunnelId --mcp-server-url "http://127.0.0.1:18766/mcp" --health-listen-addr "127.0.0.1:18081"
if ($LASTEXITCODE -ne 0) { throw "Could not initialize v2 profile." }
Write-Output "V2_TUNNEL_PROFILE_READY"
Write-Output "V2_TUNNEL_ID=$TunnelId"
Write-Output "BACKEND=http://127.0.0.1:18766/mcp"
Write-Output "HEALTH=http://127.0.0.1:18081"
Write-Output "V1_UNCHANGED=True"
