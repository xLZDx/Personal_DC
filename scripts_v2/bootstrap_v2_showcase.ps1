# Bootstrap the independent Personal DC v2 customer-showcase installation.
# Does not install/activate a tunnel or modify the v1 service.
[CmdletBinding()]
param()
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Security
$Root = Join-Path $env:LOCALAPPDATA "Personal_DC_V2"
$Original = "D:\Repo\Personal_DC\vendor\tunnel-client"
$Files = @("tunnel-client.exe", "cloudflared.exe", "cloudflared-manifest.json", "LICENSE", "NOTICE")
foreach ($relative in @("", "bin", "secrets", "logs", "profiles", "run")) {
    $path = if ($relative) { Join-Path $Root $relative } else { $Root }
    if (Test-Path -LiteralPath $path) {
        if ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "V2 installation directory cannot be a reparse point."
        }
    } else {
        New-Item -ItemType Directory -Path $path -ErrorAction Stop | Out-Null
    }
}
foreach ($file in $Files) {
    $from = Join-Path $Original $file
    $to = Join-Path (Join-Path $Root "bin") $file
    if (-not (Test-Path -LiteralPath $from -PathType Leaf)) { throw "Local tunnel component missing: $file" }
    $sourceHash = (Get-FileHash -LiteralPath $from -Algorithm SHA256).Hash
    if (Test-Path -LiteralPath $to) {
        if ((Get-FileHash -LiteralPath $to -Algorithm SHA256).Hash -ne $sourceHash) {
            throw "Existing V2 binary differs: $file. No overwrite performed."
        }
    } else {
        Copy-Item -LiteralPath $from -Destination $to -ErrorAction Stop
        if ((Get-FileHash -LiteralPath $to -Algorithm SHA256).Hash -ne $sourceHash) {
            throw "Copied V2 binary hash mismatch: $file"
        }
    }
}
$secret = Join-Path (Join-Path $Root "secrets") "backend-key.dpapi"
if (-not (Test-Path -LiteralPath $secret)) {
    $randomBytes = [byte[]]::new(32)
    $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $random.GetBytes($randomBytes) } finally { $random.Dispose() }
    $hex = -join ($randomBytes | ForEach-Object { $_.ToString("x2") })
    $plainBytes = [Text.Encoding]::ASCII.GetBytes($hex)
    try {
        $encrypted = [Security.Cryptography.ProtectedData]::Protect(
            $plainBytes, $null,
            [Security.Cryptography.DataProtectionScope]::CurrentUser)
        [IO.File]::WriteAllBytes($secret, $encrypted)
    } finally {
        [Array]::Clear($randomBytes,0,$randomBytes.Length)
        [Array]::Clear($plainBytes,0,$plainBytes.Length)
        if ($encrypted) { [Array]::Clear($encrypted,0,$encrypted.Length) }
        $hex = $null
    }
}
$src = Join-Path $Root "bin\tunnel-client.exe"
Write-Output "V2_BOOTSTRAP_READY"
Write-Output "V2_ROOT=$Root"
Write-Output "V2_BINARY_SHA256=$((Get-FileHash -LiteralPath $src -Algorithm SHA256).Hash.ToLowerInvariant())"
Write-Output "V2_BACKEND_DPAPI_PRESENT=$([bool](Test-Path -LiteralPath $secret))"
Write-Output "V1_UNCHANGED=True"
