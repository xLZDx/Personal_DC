param(
    [Parameter(Mandatory = $true)]
    [string]$TunnelId
)

$ErrorActionPreference = "Stop"
$Repo = Split-Path -Parent $PSScriptRoot
$Client = Join-Path $Repo "vendor\tunnel-client\tunnel-client.exe"
$StatusPath = Join-Path $Repo "logs\connect-status.json"

function Write-Status([string]$Stage, [bool]$Ok, [string]$Message) {
    @{
        ts = (Get-Date).ToString("o")
        stage = $Stage
        ok = $Ok
        message = $Message
        tunnel_id = $TunnelId
    } | ConvertTo-Json | Set-Content -Encoding UTF8 $StatusPath
}

try {
    Write-Status "awaiting_runtime_key" $false "Waiting for local runtime key entry."

    if (-not (Test-Path $Client)) {
        throw "OpenAI tunnel-client is not installed."
    }

    Write-Host ""
    Write-Host "Personal DC / OpenAI Secure MCP Tunnel" -ForegroundColor Cyan
    Write-Host "Tunnel: $TunnelId"
    Write-Host ""
    Write-Host "Paste your Runtime API Key here. It will stay only in this process memory." -ForegroundColor Yellow

    $secure = Read-Host "CONTROL_PLANE_API_KEY" -AsSecureString
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
        if ([string]::IsNullOrWhiteSpace($plain)) { throw "Runtime key cannot be empty." }
        $env:CONTROL_PLANE_API_KEY = $plain
    }
    finally {
        if ($ptr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
        $plain = $null
    }

    Write-Status "connecting" $false "Runtime key received locally; starting managed tunnel runtime."

    $McpCommand = "python D:/Repo/Personal_DC/run_server.py"
    & $Client runtimes connect --alias "personal-dc" --profile "personal-dc" --tunnel-id $TunnelId --runtime-api-key "env:CONTROL_PLANE_API_KEY" --mcp-command $McpCommand --json
    if ($LASTEXITCODE -ne 0) { throw "tunnel-client runtimes connect failed with exit code $LASTEXITCODE." }

    Start-Sleep -Seconds 2
    $status = & $Client runtimes status "personal-dc" --json
    if ($LASTEXITCODE -ne 0) { throw "tunnel-client runtimes status failed with exit code $LASTEXITCODE." }

    @{
        ts = (Get-Date).ToString("o")
        stage = "connected"
        ok = $true
        message = "Managed runtime created. See runtime_status."
        tunnel_id = $TunnelId
        runtime_status = ($status | ConvertFrom-Json)
    } | ConvertTo-Json -Depth 10 | Set-Content -Encoding UTF8 $StatusPath

    Write-Host ""
    Write-Host "Personal DC tunnel connected." -ForegroundColor Green
    $status | Write-Host
    Write-Host ""
    Write-Host "You can close this window after ChatGPT sees the connector." -ForegroundColor Cyan
}
catch {
    Write-Status "error" $false $_.Exception.Message
    Write-Host ""
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}
