$ErrorActionPreference = "Stop"

$Repo = Split-Path -Parent $PSScriptRoot
$Dest = Join-Path $Repo "vendor\tunnel-client"
New-Item -ItemType Directory -Force -Path $Dest | Out-Null

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw "GitHub CLI (gh) is required to download the official OpenAI tunnel-client release."
}

$Tag = gh release view --repo openai/tunnel-client --json tagName --jq ".tagName"
if (-not $Tag) { throw "Could not resolve latest openai/tunnel-client release." }

$Asset = "tunnel-client-$Tag-windows-amd64.zip"
Write-Host "Installing OpenAI tunnel-client $Tag"
Push-Location $Dest
try {
    gh release download $Tag --repo openai/tunnel-client --pattern $Asset --clobber
    Expand-Archive -Path $Asset -DestinationPath . -Force
    & (Join-Path $Dest "tunnel-client.exe") --version
}
finally {
    Pop-Location
}
