# Run the separate v2 synthetic customer showcase; v1 is not modified.
# -BackendOnly starts local 18766 without opening a tunnel.
# Without -BackendOnly, uses the independent OpenAI tunnel profile/key.
[CmdletBinding()]
param([switch]$BackendOnly, [switch]$DoctorOnly)
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Security
$Repo = Split-Path -Parent $PSScriptRoot
$Root = Join-Path $env:LOCALAPPDATA "Personal_DC_V2"
$Run = Join-Path $Root "run"
$Logs = Join-Path $Root "logs"
$BackendBlob = Join-Path $Root "secrets\backend-key.dpapi"
$RuntimeBlob = Join-Path $Root "secrets\runtime-key.dpapi"
$Python = "C:\Python314\python.exe"
$Client = Join-Path $Root "bin\tunnel-client.exe"
$ProfileDir = Join-Path $Root "profiles"
$ProfileFiles = @(Get-ChildItem -LiteralPath $ProfileDir -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -in @("personal-dc-v2.yaml", "personal-dc-v2.yml") })
if (-not (Test-Path -LiteralPath $Python) -or -not (Test-Path -LiteralPath $BackendBlob)) {
    throw "Bootstrap and Python 3.14 are required."
}
if (-not $BackendOnly) {
    if ($ProfileFiles.Count -ne 1 -or -not (Test-Path -LiteralPath $RuntimeBlob)) {
        throw "Configure a distinct tunnel and save v2 runtime key before starting tunnel."
    }
}
function Load-Dpapi([string]$Path) {
    $encrypted = [IO.File]::ReadAllBytes($Path)
    $clear = $null
    try {
        $clear = [Security.Cryptography.ProtectedData]::Unprotect(
            $encrypted, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
        return [Text.Encoding]::UTF8.GetString($clear)
    } finally {
        [Array]::Clear($encrypted, 0, $encrypted.Length)
        if ($clear) { [Array]::Clear($clear, 0, $clear.Length) }
    }
}
function Check-Port([int]$Port) {
    return [bool](Get-NetTCPConnection -LocalAddress "127.0.0.1" -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
}
function Trusted-Backend([int]$ProcessId) {
    $proc = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction SilentlyContinue
    return [bool]($proc -and $proc.Name -ieq "python.exe" -and
        $proc.CommandLine -match "dc_v2.showcase_mcp")
}
$StartedBackend = $null
$BackendPidPath = Join-Path $Run "backend.pid"
$backendSecret = Load-Dpapi $BackendBlob
if ($backendSecret -cnotmatch '^[0-9a-f]{64}$') { throw "Invalid v2 backend key." }
if (Check-Port 18766) {
    if (-not (Test-Path -LiteralPath $BackendPidPath)) { throw "V2 port is in use by unknown process." }
    $pidValue = [int]([IO.File]::ReadAllText($BackendPidPath).Trim())
    if (-not (Trusted-Backend $pidValue)) { throw "V2 port process identity is not verified." }
    Write-Output "V2_BACKEND_ALREADY_RUNNING"
} else {
    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssfff")
    $stdOut = Join-Path $Logs ("backend-" + $timestamp + ".out.log")
    $stdErr = Join-Path $Logs ("backend-" + $timestamp + ".err.log")
    # The backend receives only the demo-local secret, NOT the OpenAI runtime key.
    $env:CONTROL_PLANE_API_KEY = $null
    $env:PDC_V2_BACKEND_KEY = $backendSecret
    try {
        $StartedBackend = Start-Process -FilePath $Python -ArgumentList "-m", "dc_v2.showcase_mcp" -WorkingDirectory $Repo -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdOut -RedirectStandardError $stdErr
    } finally {
        $env:PDC_V2_BACKEND_KEY = $null
    }
    [IO.File]::WriteAllText($BackendPidPath, [string]$StartedBackend.Id)
    $deadline = (Get-Date).AddSeconds(20)
    while ((Get-Date) -lt $deadline -and -not (Check-Port 18766) -and -not $StartedBackend.HasExited) {
        Start-Sleep -Milliseconds 250
    }
    if (-not (Check-Port 18766)) {
        throw "V2 backend did not bind 127.0.0.1:18766. Inspect separate V2 logs."
    }
    Write-Output ("V2_BACKEND_READY_PID=" + $StartedBackend.Id)
}
$env:PDC_V2_BACKEND_KEY = $backendSecret
try {
    & $Python (Join-Path $PSScriptRoot "probe_v2_showcase.py")
    if ($LASTEXITCODE -ne 0) { throw "V2 backend positive/negative local MCP probe failed." }
} finally {
    $env:PDC_V2_BACKEND_KEY = $null
}
if ($BackendOnly) {
    Write-Output "V2_BACKEND_ONLY_READY"
    exit 0
}
if (Check-Port 18081) { throw "V2 tunnel health port 18081 is already in use. No duplicate started." }
$runtimeKey = Load-Dpapi $RuntimeBlob
if ([string]::IsNullOrWhiteSpace($runtimeKey) -or $runtimeKey.Length -lt 20) {
    throw "Missing v2 tunnel runtime key."
}
try {
    $env:CONTROL_PLANE_API_KEY = $runtimeKey
    $env:PDC_V2_BACKEND_KEY = $backendSecret
    $env:TUNNEL_CLIENT_PROFILE = $null
    $env:TUNNEL_CLIENT_PROFILE_DIR = $null
    $env:OPENAI_ADMIN_KEY = $null
    if ($DoctorOnly) {
        & $Client doctor --profile personal-dc-v2 --profile-dir $ProfileDir --mcp.extra-headers "X-PDC-V2-Demo-Auth: env:PDC_V2_BACKEND_KEY" --mcp.discovery-extra-headers "X-PDC-V2-Demo-Auth: env:PDC_V2_BACKEND_KEY" --explain
        if ($LASTEXITCODE -ne 0) { throw "V2 tunnel doctor did not pass." }
        Write-Output "V2_TUNNEL_DOCTOR_PASS"
        exit 0
    }
    Write-Output "V2_TUNNEL_STARTING_PROFILE=personal-dc-v2"
    # OpenAI credential is only supplied in the child environment, never argv/logs.
    & $Client run --profile personal-dc-v2 --profile-dir $ProfileDir --mcp.extra-headers "X-PDC-V2-Demo-Auth: env:PDC_V2_BACKEND_KEY" --mcp.discovery-extra-headers "X-PDC-V2-Demo-Auth: env:PDC_V2_BACKEND_KEY" --log.level info
    exit $LASTEXITCODE
} finally {
    $env:CONTROL_PLANE_API_KEY = $null
    $env:PDC_V2_BACKEND_KEY = $null
    $runtimeKey = $null
    $backendSecret = $null
    # Deliberately leave a previously running independent backend alone.
    # If this invocation started the backend and the tunnel exited, stop only ours.
    if ($StartedBackend -and (Trusted-Backend $StartedBackend.Id)) {
        Stop-Process -Id $StartedBackend.Id -ErrorAction SilentlyContinue
    }
}
