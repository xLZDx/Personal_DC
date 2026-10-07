$ErrorActionPreference = "Stop"
$Repo = Split-Path -Parent $PSScriptRoot
Set-Location $Repo
$env:PERSONAL_DC_HOME = $Repo
$env:PERSONAL_DC_TRANSPORT = "stdio"
python -m personal_dc.server
