param([int]$Port = 8765)

$ErrorActionPreference = "Stop"
$Repo = Split-Path -Parent $PSScriptRoot
Set-Location $Repo

$env:PERSONAL_DC_HOME = $Repo
$env:PERSONAL_DC_TRANSPORT = "streamable-http"
$env:PERSONAL_DC_PORT = "$Port"

Write-Host "Starting local MCP endpoint at http://127.0.0.1:$Port/mcp"
python -m personal_dc.server
