param()
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Security

$Repo = Split-Path -Parent $PSScriptRoot
$Client = Join-Path $Repo "vendor\tunnel-client\tunnel-client.exe"
$SecretPath = Join-Path $env:LOCALAPPDATA "Personal_DC\secrets\runtime-key.dpapi"
$LogPath = Join-Path $Repo "logs\autostart.log"
$BackendOut = Join-Path $Repo "logs\backend.stdout.log"
$BackendErr = Join-Path $Repo "logs\backend.stderr.log"
$TunnelOut = Join-Path $Repo "logs\tunnel.stdout.log"
$TunnelErr = Join-Path $Repo "logs\tunnel.stderr.log"

function Log([string]$Message) {
    Add-Content -Path $LogPath -Value ("{0} {1}" -f (Get-Date).ToString("o"), $Message) -Encoding UTF8
}

$backend = $null
$tunnel = $null
try {
    if (-not (Test-Path $Client)) { throw "tunnel-client not found: $Client" }
    if (-not (Test-Path $SecretPath)) { throw "DPAPI runtime key not found: $SecretPath" }

    $env:PERSONAL_DC_HOME = $Repo
    $env:PERSONAL_DC_TRANSPORT = "streamable-http"
    $env:PERSONAL_DC_PORT = "18765"

    Log "Starting local stateless MCP backend on 127.0.0.1:18765."
    $backend = Start-Process -FilePath "python.exe" -ArgumentList "-m","personal_dc.server" -WorkingDirectory $Repo -WindowStyle Hidden -PassThru -RedirectStandardOutput $BackendOut -RedirectStandardError $BackendErr

    $deadline = (Get-Date).AddSeconds(20)
    $ok = $false
    do {
        Start-Sleep -Milliseconds 250
        try { $ok = Test-NetConnection -ComputerName 127.0.0.1 -Port 18765 -InformationLevel Quiet -WarningAction SilentlyContinue } catch { $ok = $false }
    } until ($ok -or (Get-Date) -gt $deadline -or $backend.HasExited)
    if (-not $ok) { throw "Local MCP backend did not open 127.0.0.1:18765." }

    $protected = [IO.File]::ReadAllBytes($SecretPath)
    $bytes = [System.Security.Cryptography.ProtectedData]::Unprotect($protected,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    try {
        $env:CONTROL_PLANE_API_KEY = [Text.Encoding]::UTF8.GetString($bytes)
        if ([string]::IsNullOrWhiteSpace($env:CONTROL_PLANE_API_KEY)) { throw "Decrypted runtime key is empty." }
    }
    finally {
        [Array]::Clear($bytes,0,$bytes.Length)
        [Array]::Clear($protected,0,$protected.Length)
    }

    Log "Starting OpenAI Secure MCP Tunnel on health port 18080."
    $tunnel = Start-Process -FilePath $Client -ArgumentList "run","--profile","personal-dc" -WorkingDirectory $Repo -WindowStyle Hidden -PassThru -RedirectStandardOutput $TunnelOut -RedirectStandardError $TunnelErr
    $env:CONTROL_PLANE_API_KEY = $null
    $tunnel.WaitForExit()
    $exitCode = $tunnel.ExitCode
    Log "tunnel-client exited with code $exitCode."
    exit $exitCode
}
catch {
    $env:CONTROL_PLANE_API_KEY = $null
    Log ("ERROR: " + $_.Exception.Message)
    exit 1
}
finally {
    $env:CONTROL_PLANE_API_KEY = $null
    if ($tunnel -and -not $tunnel.HasExited) { Stop-Process -Id $tunnel.Id -Force -ErrorAction SilentlyContinue }
    if ($backend -and -not $backend.HasExited) { Stop-Process -Id $backend.Id -Force -ErrorAction SilentlyContinue }
}
