param()

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Security
if (-not ("PersonalDC.ProcessJob" -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace PersonalDC {
    public static class ProcessJob {
        [StructLayout(LayoutKind.Sequential)]
        private struct BasicLimitInformation {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IoCounters {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ExtendedLimitInformation {
            public BasicLimitInformation BasicLimitInformation;
            public IoCounters IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateJobObject(IntPtr attributes, string name);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetInformationJobObject(IntPtr job, int infoClass, ref ExtendedLimitInformation info, uint length);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        public static IntPtr CreateKillOnCloseJob() {
            IntPtr job = CreateJobObject(IntPtr.Zero, null);
            if (job == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            ExtendedLimitInformation info = new ExtendedLimitInformation();
            info.BasicLimitInformation.LimitFlags = 0x00002000;
            if (!SetInformationJobObject(job, 9, ref info, (uint)Marshal.SizeOf(typeof(ExtendedLimitInformation)))) {
                int error = Marshal.GetLastWin32Error();
                CloseHandle(job);
                throw new System.ComponentModel.Win32Exception(error);
            }
            return job;
        }

        public static void Assign(IntPtr job, IntPtr process) {
            if (!AssignProcessToJobObject(job, process))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }

        public static void Close(IntPtr job) {
            if (job != IntPtr.Zero) CloseHandle(job);
        }
    }
}
'@
}

$Repo = Split-Path -Parent $PSScriptRoot
$Client = Join-Path $Repo "vendor\tunnel-client\tunnel-client.exe"
$SecretPath = Join-Path $env:LOCALAPPDATA "Personal_DC\secrets\runtime-key.dpapi"
$LogPath = Join-Path $Repo "logs\autostart.log"
$BackendOut = Join-Path $Repo "logs\backend.stdout.log"
$BackendErr = Join-Path $Repo "logs\backend.stderr.log"
$TunnelOut = Join-Path $Repo "logs\tunnel.stdout.log"
$TunnelErr = Join-Path $Repo "logs\tunnel.stderr.log"
$BackendUrl = "http://127.0.0.1:18765/mcp"
$TunnelHealthBase = "http://127.0.0.1:18080"
$Mutex = $null
$MutexHeld = $false
$JobHandle = [IntPtr]::Zero
$Backend = $null
$Tunnel = $null
$FailureCount = 0

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $LogPath) | Out-Null

function Write-Event([string]$Level, [string]$Event, [hashtable]$Data = @{}) {
    $entry = [ordered]@{
        timestamp = (Get-Date).ToString("o")
        level = $Level
        event = $Event
        data = $Data
    }
    Add-Content -LiteralPath $LogPath -Value ($entry | ConvertTo-Json -Compress -Depth 5) -Encoding UTF8
}

function Redact-Message([string]$Message) {
    if ($env:CONTROL_PLANE_API_KEY) { $Message = $Message.Replace($env:CONTROL_PLANE_API_KEY, "[REDACTED]") }
    $Message = $Message -replace '(?i)(authorization|api[_-]?key|token)(\s*[:=]\s*)[^\s,;]+', '$1$2[REDACTED]'
    return $Message
}

function Test-PortFree([int]$Port) {
    $listener = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue
    return -not [bool]$listener
}

function Test-McpHealth {
    $headers = @{ Accept = "application/json, text/event-stream" }
    $initializeBody = @{
        jsonrpc = "2.0"
        id = 1
        method = "initialize"
        params = @{
            protocolVersion = "2025-03-26"
            capabilities = @{}
            clientInfo = @{ name = "Personal DC readiness probe"; version = "1.0" }
        }
    } | ConvertTo-Json -Compress -Depth 6

    try {
        $initialized = Invoke-RestMethod -Method Post -Uri $BackendUrl -Headers $headers `
            -ContentType "application/json" -Body $initializeBody -TimeoutSec 5
        if (-not $initialized.result.protocolVersion) { return $false }

        $headers["MCP-Protocol-Version"] = [string]$initialized.result.protocolVersion
        $callBody = @{
            jsonrpc = "2.0"
            id = 2
            method = "tools/call"
            params = @{ name = "health"; arguments = @{} }
        } | ConvertTo-Json -Compress -Depth 6
        $response = Invoke-RestMethod -Method Post -Uri $BackendUrl -Headers $headers `
            -ContentType "application/json" -Body $callBody -TimeoutSec 5
        if ($response.result.structuredContent.ok -eq $true) { return $true }
        if ($response.result.content.Count -gt 0 -and $response.result.content[0].text) {
            $content = $response.result.content[0].text | ConvertFrom-Json
            return $content.ok -eq $true
        }
    }
    catch {
        return $false
    }
    return $false
}

function Test-TunnelReady {
    try {
        $health = Invoke-WebRequest -UseBasicParsing -Uri ($TunnelHealthBase + "/healthz") -TimeoutSec 3
        $ready = Invoke-WebRequest -UseBasicParsing -Uri ($TunnelHealthBase + "/readyz") -TimeoutSec 3
        return ($health.Content.Trim() -eq "live" -and $ready.Content.Trim() -eq "ready")
    }
    catch {
        return $false
    }
}

function Stop-OwnedProcess($Process, [string]$Name) {
    if (-not $Process) { return }
    try {
        $Process.Refresh()
        if (-not $Process.HasExited) {
            Stop-Process -Id $Process.Id -Force -ErrorAction Stop
            $Process.WaitForExit(5000) | Out-Null
            Write-Event "INFO" "owned_process_stopped" @{ name = $Name; pid = $Process.Id }
        }
    }
    catch {
        Write-Event "ERROR" "owned_process_stop_failed" @{ name = $Name; pid = $Process.Id; error = $_.Exception.Message }
    }
}

function Start-ManagedProcess([string]$FilePath, [string[]]$Arguments, [string]$WorkingDirectory, [string]$Stdout, [string]$Stderr) {
    $process = Start-Process -FilePath $FilePath -ArgumentList $Arguments `
        -WorkingDirectory $WorkingDirectory -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput $Stdout -RedirectStandardError $Stderr
    try {
        [PersonalDC.ProcessJob]::Assign($JobHandle, $process.Handle)
        return $process
    }
    catch {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        throw
    }
}

try {
    Write-Event "INFO" "supervisor_starting" @{ repository = $Repo; task = "Personal_DC_V2_Tunnel" }

    $Mutex = [Threading.Mutex]::new($false, "Local\Personal_DC_V2_Tunnel_Supervisor")
    try { $MutexHeld = $Mutex.WaitOne(0) }
    catch [Threading.AbandonedMutexException] { $MutexHeld = $true }
    if (-not $MutexHeld) {
        Write-Event "WARN" "duplicate_instance_refused" @{}
        exit 0
    }

    $PythonCommand = Get-Command "python.exe" -ErrorAction Stop
    $Python = $PythonCommand.Source
    if (-not (Test-Path -LiteralPath $Client -PathType Leaf)) { throw "Tunnel client missing from repository vendor directory." }
    if (-not (Test-Path -LiteralPath $SecretPath -PathType Leaf)) { throw "DPAPI runtime key file is missing." }
    if (-not (Test-Path -LiteralPath (Join-Path $Repo "personal_dc\server.py") -PathType Leaf)) { throw "Personal DC server module is missing." }

    foreach ($port in @(18765, 18080)) {
        if (-not (Test-PortFree $port)) { throw "Required loopback port $port is already in use; refusing to start a duplicate or interfere with another service." }
    }
    $JobHandle = [PersonalDC.ProcessJob]::CreateKillOnCloseJob()

    $env:PERSONAL_DC_HOME = $Repo
    $env:PERSONAL_DC_TRANSPORT = "streamable-http"
    $env:PERSONAL_DC_PORT = "18765"

    while ($true) {
        $Backend = $null
        $Tunnel = $null
        $env:CONTROL_PLANE_API_KEY = $null
        try {
            Write-Event "INFO" "backend_starting" @{ port = 18765; python = $Python }
            $Backend = Start-ManagedProcess $Python @("-m", "personal_dc.server") $Repo $BackendOut $BackendErr

            $backendDeadline = (Get-Date).AddSeconds(30)
            $backendReady = $false
            do {
                Start-Sleep -Milliseconds 500
                $Backend.Refresh()
                if ($Backend.HasExited) { throw "Personal DC backend exited during startup with code $($Backend.ExitCode)." }
                $backendReady = Test-McpHealth
            } until ($backendReady -or (Get-Date) -ge $backendDeadline)
            if (-not $backendReady) { throw "Personal DC Streamable HTTP initialize/health check did not succeed within 30 seconds." }
            Write-Event "INFO" "backend_ready" @{ endpoint = $BackendUrl; protocol = "streamable-http"; tool = "health" }

            $protected = [IO.File]::ReadAllBytes($SecretPath)
            try {
                $bytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
                    $protected, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser
                )
                try {
                    $env:CONTROL_PLANE_API_KEY = [Text.Encoding]::UTF8.GetString($bytes)
                    if ([string]::IsNullOrWhiteSpace($env:CONTROL_PLANE_API_KEY)) { throw "Decrypted runtime key is empty." }
                }
                finally {
                    [Array]::Clear($bytes, 0, $bytes.Length)
                }
            }
            finally {
                [Array]::Clear($protected, 0, $protected.Length)
            }

            Write-Event "INFO" "tunnel_starting" @{ profile = "personal-dc"; health_port = 18080 }
            $Tunnel = Start-ManagedProcess $Client @("run", "--profile", "personal-dc") $Repo $TunnelOut $TunnelErr
            $env:CONTROL_PLANE_API_KEY = $null

            $tunnelDeadline = (Get-Date).AddSeconds(45)
            $tunnelReady = $false
            do {
                Start-Sleep -Seconds 1
                $Tunnel.Refresh()
                if ($Tunnel.HasExited) { throw "Secure MCP Tunnel exited during startup with code $($Tunnel.ExitCode)." }
                $tunnelReady = Test-TunnelReady
            } until ($tunnelReady -or (Get-Date) -ge $tunnelDeadline)
            if (-not $tunnelReady) { throw "Secure MCP Tunnel did not report live and ready within 45 seconds." }
            Write-Event "INFO" "tunnel_ready" @{ health_endpoint = $TunnelHealthBase; profile = "personal-dc" }
            $healthySince = Get-Date

            while ($true) {
                Start-Sleep -Seconds 15
                $Backend.Refresh()
                $Tunnel.Refresh()
                if ($Backend.HasExited) { throw "Personal DC backend exited with code $($Backend.ExitCode)." }
                if ($Tunnel.HasExited) { throw "Secure MCP Tunnel exited with code $($Tunnel.ExitCode)." }
                if (-not (Test-McpHealth)) { throw "Personal DC MCP health check failed." }
                if (-not (Test-TunnelReady)) { throw "Secure MCP Tunnel health or readiness check failed." }
                if (((Get-Date) - $healthySince).TotalMinutes -ge 5) {
                    $FailureCount = 0
                    $healthySince = Get-Date
                }
            }
        }
        catch {
            $message = Redact-Message $_.Exception.Message
            Write-Event "ERROR" "supervised_runtime_failure" @{ error = $message }
            $FailureCount++
        }
        finally {
            $env:CONTROL_PLANE_API_KEY = $null
            Stop-OwnedProcess $Tunnel "tunnel-client"
            Stop-OwnedProcess $Backend "personal-dc-backend"
            $Tunnel = $null
            $Backend = $null
        }

        $delay = [Math]::Min(300, [Math]::Pow(2, [Math]::Min($FailureCount, 8)) * 5)
        Write-Event "WARN" "restart_backoff" @{ consecutive_failures = $FailureCount; seconds = [int]$delay }
        Start-Sleep -Seconds ([int]$delay)
    }
}
catch {
    $message = Redact-Message $_.Exception.Message
    Write-Event "ERROR" "supervisor_fatal" @{ error = $message }
    exit 1
}
finally {
    $env:CONTROL_PLANE_API_KEY = $null
    Stop-OwnedProcess $Tunnel "tunnel-client"
    Stop-OwnedProcess $Backend "personal-dc-backend"
    if ($MutexHeld -and $Mutex) { $Mutex.ReleaseMutex() }
    if ($Mutex) { $Mutex.Dispose() }
    if ($JobHandle -ne [IntPtr]::Zero) { [PersonalDC.ProcessJob]::Close($JobHandle) }
}
