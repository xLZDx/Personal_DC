# Personal DC v2 native supervisor (NO Docker). Single instance, ordered start, restart with backoff.
#
#  1. verify dependencies (python, DPAPI blobs, tunnel profile + client) - wait/retry if absent
#  2. start the native MCP backend (127.0.0.1:18766) and wait until it really answers
#  3. start the EXISTING tunnel profile personal-dc-v2 (health 127.0.0.1:18081); no new identity
#  4. if either process dies, stop what this supervisor started and restart with exponential backoff
#
# Credentials only travel through the child process environment, never through command lines or logs.
# Stop gracefully:  New-Item "$env:LOCALAPPDATA\Personal_DC_V2\run\supervisor.stop"
[CmdletBinding()]
param([switch]$BackendOnly)
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Security

$Repo       = Split-Path -Parent $PSScriptRoot
$Root       = Join-Path $env:LOCALAPPDATA "Personal_DC_V2"
$Run        = Join-Path $Root "run"
$Logs       = Join-Path $Root "logs"
$Python     = "C:\Python314\python.exe"
$Client     = Join-Path $Root "bin\tunnel-client.exe"
$ProfileDir = Join-Path $Root "profiles"
$BackendBlob = Join-Path $Root "secrets\backend-key.dpapi"
$RuntimeBlob = Join-Path $Root "secrets\runtime-key.dpapi"
$StopFile   = Join-Path $Run "supervisor.stop"
$StatusFile = Join-Path $Run "supervisor.json"
$PidFile    = Join-Path $Run "backend.pid"
New-Item -ItemType Directory -Force -Path $Run, $Logs | Out-Null

function Log([string]$Message) {
    try {   # logging must never take the supervisor down (disk full, locked file)
        $file = Join-Path $Logs ("supervisor-" + (Get-Date).ToString("yyyyMMdd") + ".log")
        Add-Content -LiteralPath $file -Value ("{0} {1}" -f (Get-Date).ToString("o"), $Message) -Encoding UTF8
    } catch { }
}
# Bounded authenticated MCP round trip (never hangs the supervisor). Returns the probe exit code, 99 on timeout.
function Probe-Backend([string]$Key) {
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $Python; $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    $psi.Arguments = '"' + (Join-Path $PSScriptRoot "probe_native_personal.py") + '"'
    $psi.EnvironmentVariables["PDC_V2_BACKEND_KEY"] = $Key
    $proc = [Diagnostics.Process]::Start($psi)
    if (-not $proc.WaitForExit(30000)) { try { $proc.Kill() } catch { }; return 99 }
    return $proc.ExitCode
}
function Prune-Logs { Get-ChildItem -LiteralPath $Logs -File -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-14) } | Remove-Item -Force -ErrorAction SilentlyContinue }
function Load-Dpapi([string]$Path) {
    $enc = [IO.File]::ReadAllBytes($Path); $clear = $null
    try {
        $clear = [Security.Cryptography.ProtectedData]::Unprotect($enc, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
        return [Text.Encoding]::UTF8.GetString($clear)
    } finally { [Array]::Clear($enc, 0, $enc.Length); if ($clear) { [Array]::Clear($clear, 0, $clear.Length) } }
}
function Port-Listening([int]$Port) {
    return [bool](Get-NetTCPConnection -LocalAddress "127.0.0.1" -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
}
function Is-OurBackend([int]$ProcessId) {
    $p = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction SilentlyContinue
    return [bool]($p -and $p.Name -ieq "python.exe" -and $p.CommandLine -match "dc_v2\.native_personal_mcp")
}
function Missing-Dependencies {
    $missing = @()
    foreach ($p in @($Python, $BackendBlob)) { if (-not (Test-Path -LiteralPath $p)) { $missing += $p } }
    if (-not $BackendOnly) {
        foreach ($p in @($Client, $RuntimeBlob)) { if (-not (Test-Path -LiteralPath $p)) { $missing += $p } }
        $prof = @(Get-ChildItem -LiteralPath $ProfileDir -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -in @("personal-dc-v2.yaml", "personal-dc-v2.yml") })
        if ($prof.Count -ne 1) { $missing += "profile personal-dc-v2.(yaml|yml)" }
    }
    return $missing
}
function Write-Status([hashtable]$s) {
    $s["updated"] = (Get-Date).ToUniversalTime().ToString("o"); $s["supervisor_pid"] = $PID
    ($s | ConvertTo-Json -Compress) | Set-Content -LiteralPath $StatusFile -Encoding UTF8
}

# --- single instance -------------------------------------------------------
$created = $false
$mutex = New-Object System.Threading.Mutex($true, "Global\Personal_DC_V2_Supervisor", [ref]$created)
if (-not $created) { Log "Another supervisor instance is already running; exiting."; exit 0 }
Remove-Item -LiteralPath $StopFile -ErrorAction SilentlyContinue
Log ("Supervisor started pid=" + $PID + " repo=" + $Repo)
Prune-Logs

$backoff = 5; $restarts = 0
try {
    while (-not (Test-Path -LiteralPath $StopFile)) {
        $missing = Missing-Dependencies
        if ($missing.Count -gt 0) {
            Log ("Missing dependencies: " + ($missing -join "; ") + ". Retrying in 60 s.")
            Write-Status @{ state = "waiting_dependencies"; missing = $missing; restarts = $restarts }
            for ($i = 0; $i -lt 60 -and -not (Test-Path -LiteralPath $StopFile); $i++) { Start-Sleep -Seconds 1 }
            continue
        }
        $backend = $null; $tunnel = $null; $startedAt = Get-Date; $weStartedBackend = $false
        try {
            $backendKey = Load-Dpapi $BackendBlob
            if ($backendKey -cnotmatch '^[0-9a-f]{64}$') { throw "Invalid v2 backend key blob." }
            # --- backend ------------------------------------------------------
            if (Port-Listening 18766) {
                $existing = $null
                if (Test-Path -LiteralPath $PidFile) { $existing = [int]([IO.File]::ReadAllText($PidFile).Trim()) }
                if (-not $existing -or -not (Is-OurBackend $existing)) { throw "Port 18766 is held by an unverified process; refusing to start." }
                $backend = Get-Process -Id $existing -ErrorAction Stop
                Log ("Adopted verified running backend pid=" + $backend.Id)
            } else {
                $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssfff")
                $env:PDC_V2_BACKEND_KEY = $backendKey
                $env:CONTROL_PLANE_API_KEY = $null; $env:OPENAI_ADMIN_KEY = $null
                try {
                    $backend = Start-Process -FilePath $Python -ArgumentList "-m", "dc_v2.native_personal_mcp" -WorkingDirectory $Repo `
                        -WindowStyle Hidden -PassThru `
                        -RedirectStandardOutput (Join-Path $Logs "native-$stamp.out.log") `
                        -RedirectStandardError  (Join-Path $Logs "native-$stamp.err.log")
                } finally { $env:PDC_V2_BACKEND_KEY = $null }
                $weStartedBackend = $true
                [IO.File]::WriteAllText($PidFile, [string]$backend.Id)
                $deadline = (Get-Date).AddSeconds(30)
                while ((Get-Date) -lt $deadline -and -not (Port-Listening 18766) -and -not $backend.HasExited) { Start-Sleep -Milliseconds 250 }
                if (-not (Port-Listening 18766)) { throw "Backend did not bind 127.0.0.1:18766 (see native-$stamp.err.log)." }
                Log ("Backend started pid=" + $backend.Id)
            }
            # readiness = a real authenticated MCP round trip, not just an open port
            $probe = Probe-Backend $backendKey
            if ($probe -ne 0) { throw "Backend readiness probe failed (exit $probe)." }
            Log "Backend ready."
            if ($BackendOnly) { Write-Status @{ state = "backend_only_ready"; backend_pid = $backend.Id }; $backend.WaitForExit(); throw "Backend exited." }

            # --- tunnel (existing profile) -----------------------------------------
            if (Port-Listening 18081) { throw "Tunnel health port 18081 already in use; not starting a duplicate." }
            $runtimeKey = Load-Dpapi $RuntimeBlob
            if ([string]::IsNullOrWhiteSpace($runtimeKey) -or $runtimeKey.Length -lt 20) { throw "Missing v2 tunnel runtime key." }
            $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssfff")
            $env:CONTROL_PLANE_API_KEY = $runtimeKey; $env:PDC_V2_BACKEND_KEY = $backendKey
            $env:TUNNEL_CLIENT_PROFILE = $null; $env:TUNNEL_CLIENT_PROFILE_DIR = $null; $env:OPENAI_ADMIN_KEY = $null
            try {
                $tunnel = Start-Process -FilePath $Client -WindowStyle Hidden -PassThru -WorkingDirectory $Repo `
                    -ArgumentList "run", "--profile", "personal-dc-v2", "--profile-dir", $ProfileDir,
                        "--mcp.extra-headers", '"X-PDC-V2-Demo-Auth: env:PDC_V2_BACKEND_KEY"',
                        "--mcp.discovery-extra-headers", '"X-PDC-V2-Demo-Auth: env:PDC_V2_BACKEND_KEY"',
                        "--log.level", "info" `
                    -RedirectStandardOutput (Join-Path $Logs "tunnel-$stamp.out.log") `
                    -RedirectStandardError  (Join-Path $Logs "tunnel-$stamp.err.log")
            } finally {
                $env:CONTROL_PLANE_API_KEY = $null; $env:PDC_V2_BACKEND_KEY = $null; $runtimeKey = $null
            }
            Log ("Tunnel started pid=" + $tunnel.Id)
            Write-Status @{ state = "running"; backend_pid = $backend.Id; tunnel_pid = $tunnel.Id; restarts = $restarts }

            $nextProbe = (Get-Date).AddSeconds(60); $probeFails = 0
            while (-not (Test-Path -LiteralPath $StopFile)) {
                if ((Get-Date) -ge $nextProbe) {   # periodic health: a hung backend with an open port is a failure too
                    $nextProbe = (Get-Date).AddSeconds(60)
                    if ((Probe-Backend $backendKey) -eq 0) { $probeFails = 0 } else { $probeFails++ }
                    if ($probeFails -ge 3) { Log "Backend failed 3 consecutive health probes; restarting."; break }
                    Write-Status @{ state = "running"; backend_pid = $backend.Id; tunnel_pid = $tunnel.Id; restarts = $restarts; probe_failures = $probeFails }
                }
                if ($tunnel.HasExited) { Log ("Tunnel exited code=" + $tunnel.ExitCode); break }
                if ($backend.HasExited) { Log ("Backend exited code=" + $backend.ExitCode); break }
                Start-Sleep -Seconds 2
            }
        } catch {
            Log ("ERROR: " + $_.Exception.Message)
        } finally {
            $env:CONTROL_PLANE_API_KEY = $null; $env:PDC_V2_BACKEND_KEY = $null; $backendKey = $null
            if ($tunnel -and -not $tunnel.HasExited) { Stop-Process -Id $tunnel.Id -ErrorAction SilentlyContinue }
            if ($weStartedBackend -and $backend -and -not $backend.HasExited -and (Is-OurBackend $backend.Id)) {
                Stop-Process -Id $backend.Id -ErrorAction SilentlyContinue
            }
        }
        if (Test-Path -LiteralPath $StopFile) { break }
        # a run that lasted > 5 minutes resets the backoff
        if (((Get-Date) - $startedAt).TotalMinutes -gt 5) { $backoff = 5 }
        $restarts++
        Log ("Restarting in " + $backoff + " s (restart #" + $restarts + ").")
        Write-Status @{ state = "backoff"; backoff_s = $backoff; restarts = $restarts }
        for ($i = 0; $i -lt $backoff -and -not (Test-Path -LiteralPath $StopFile); $i++) { Start-Sleep -Seconds 1 }
        $backoff = [Math]::Min($backoff * 2, 120)
    }
    Log "Stop requested; supervisor exiting."
    Write-Status @{ state = "stopped"; restarts = $restarts }
} finally {
    $mutex.ReleaseMutex(); $mutex.Dispose()
}
