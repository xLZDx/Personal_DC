param()
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Security

$Repo = Split-Path -Parent $PSScriptRoot
$Client = Join-Path $Repo "vendor\tunnel-client\tunnel-client.exe"
$SecretPath = Join-Path $env:LOCALAPPDATA "Personal_DC\secrets\runtime-key.dpapi"
$LogPath = Join-Path $Repo "logs\autostart.log"

function Log([string]$Message) {
    $line = "{0} {1}" -f (Get-Date).ToString("o"), $Message
    Add-Content -Path $LogPath -Value $line -Encoding UTF8
}

try {
    if (-not (Test-Path $Client)) { throw "tunnel-client not found: $Client" }
    if (-not (Test-Path $SecretPath)) { throw "DPAPI runtime key not found: $SecretPath" }

    $protected = [IO.File]::ReadAllBytes($SecretPath)
    $bytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $protected,
        $null,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    try {
        $env:CONTROL_PLANE_API_KEY = [Text.Encoding]::UTF8.GetString($bytes)
        if ([string]::IsNullOrWhiteSpace($env:CONTROL_PLANE_API_KEY)) { throw "Decrypted runtime key is empty." }
    }
    finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
        [Array]::Clear($protected, 0, $protected.Length)
    }

    Log "Starting Personal DC tunnel runtime."
    Push-Location $Repo
    try {
        & $Client run --profile personal-dc
        $exitCode = $LASTEXITCODE
        Log "tunnel-client exited with code $exitCode."
        exit $exitCode
    }
    finally { Pop-Location }
}
catch {
    Log ("ERROR: " + $_.Exception.Message)
    exit 1
}
