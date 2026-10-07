param()
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Security

$SecretRoot = Join-Path $env:LOCALAPPDATA "Personal_DC\secrets"
$SecretPath = Join-Path $SecretRoot "runtime-key.dpapi"
New-Item -ItemType Directory -Force -Path $SecretRoot | Out-Null

Write-Host ""
Write-Host "Personal DC secure runtime-key storage" -ForegroundColor Cyan
Write-Host "The key will be encrypted with Windows DPAPI for the current user."
Write-Host "It will not be stored in the repository or as plaintext."
Write-Host ""

$secure = Read-Host "CONTROL_PLANE_API_KEY" -AsSecureString
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    if ([string]::IsNullOrWhiteSpace($plain)) { throw "Runtime key cannot be empty." }
    $bytes = [Text.Encoding]::UTF8.GetBytes($plain)
    $protected = [System.Security.Cryptography.ProtectedData]::Protect(
        $bytes,
        $null,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    [IO.File]::WriteAllBytes($SecretPath, $protected)
    [Array]::Clear($bytes, 0, $bytes.Length)
    [Array]::Clear($protected, 0, $protected.Length)
}
finally {
    if ($ptr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
    $plain = $null
}

Write-Host ""
Write-Host "Runtime key stored with Windows DPAPI." -ForegroundColor Green
Write-Host "Path: $SecretPath"
Write-Host "You should not need to enter it again for normal restarts."
Read-Host "Press Enter to close"
