# Store a DISTINCT v2 OpenAI Secure MCP Tunnel runtime key using current-user DPAPI.
# Run interactively on Razer; never paste the key into ChatGPT.
[CmdletBinding()]
param()
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Security
$root = Join-Path $env:LOCALAPPDATA "Personal_DC_V2"
$secretRoot = Join-Path $root "secrets"
if (-not (Test-Path -LiteralPath $secretRoot)) { throw "Run bootstrap_v2_showcase.ps1 first." }
$path = Join-Path $secretRoot "runtime-key.dpapi"
if (Test-Path -LiteralPath $path) { throw "V2 key already saved; refusing overwrite. Use an explicit rotation procedure." }
Write-Host "Enter the dedicated v2 runtime API key (Tunnels Read + Use)." -ForegroundColor Cyan
Write-Host "Input is hidden; nothing is sent to ChatGPT or a repository."
$key = Read-Host "V2 CONTROL_PLANE_API_KEY" -AsSecureString
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($key)
$raw = $null
$protected = $null
try {
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    if ([string]::IsNullOrWhiteSpace($plain) -or $plain.Length -lt 20) { throw "Invalid v2 runtime key." }
    $raw = [Text.Encoding]::UTF8.GetBytes($plain)
    $protected = [Security.Cryptography.ProtectedData]::Protect(
        $raw, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
    [IO.File]::WriteAllBytes($path, $protected)
    Write-Output "V2_RUNTIME_KEY_SAVED_DPAPI"
} finally {
    if ($ptr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
    if ($raw) { [Array]::Clear($raw, 0, $raw.Length) }
    if ($protected) { [Array]::Clear($protected, 0, $protected.Length) }
    $plain = $null
    $key = $null
}
