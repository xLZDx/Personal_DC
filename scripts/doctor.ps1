$ErrorActionPreference = "Stop"
$Repo = Split-Path -Parent $PSScriptRoot
Set-Location $Repo
$env:PERSONAL_DC_HOME = $Repo
python -m personal_dc.doctor
