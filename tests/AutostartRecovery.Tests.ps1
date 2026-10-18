$ErrorActionPreference = 'Stop'

$sourcePath = Join-Path $PSScriptRoot '..\scripts\start-autostart.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path -LiteralPath $sourcePath),
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors.Count -gt 0) {
    throw "Supervisor source did not parse: $($parseErrors[0].Message)"
}

# Load only pure probe/redaction helpers. Never execute the supervisor's startup loop.
$helperNames = @('Write-Event', 'Redact-Message', 'Test-PortFree', 'Test-McpHealth', 'Test-TunnelReady')
foreach ($functionAst in $ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -in $helperNames
}, $true)) {
    Invoke-Expression $functionAst.Extent.Text
}

$script:BackendUrl = 'http://127.0.0.1:18765/mcp'
$script:TunnelHealthBase = 'http://127.0.0.1:18080'
$script:McpCalls = @()
$script:McpHealthOk = $true
$script:InitializeHasProtocol = $true
$script:TunnelResponses = @('live', 'ready')
$script:TunnelCalls = @()
$script:PortHasListener = $false
$script:CheckedPorts = @()

$script:PortGuardAst = $ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.ForEachStatementAst] -and
        $node.Extent.Text -match 'Test-PortFree\s+\$port' -and
        $node.Extent.Text -match '18765' -and $node.Extent.Text -match '18080'
}, $true) | Select-Object -First 1

$script:RuntimeFailureCatchAst = $ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.CatchClauseAst] -and
        $node.Extent.Text -match 'supervised_runtime_failure'
}, $true) | Select-Object -First 1
$script:RuntimeFailureCatchBody = if ($script:RuntimeFailureCatchAst) {
    ($script:RuntimeFailureCatchAst.Body.Statements | ForEach-Object { $_.Extent.Text }) -join "`r`n"
} else { '' }

function Invoke-RestMethod {
    param($Method, $Uri, $Headers, $ContentType, $Body, $TimeoutSec)

    $request = $Body | ConvertFrom-Json
    $script:McpCalls += [pscustomobject]@{
        Uri = $Uri
        Method = $request.method
        ProtocolVersion = $Headers['MCP-Protocol-Version']
    }
    if ($request.method -eq 'initialize') {
        if ($script:InitializeHasProtocol) {
            return [pscustomobject]@{ result = [pscustomobject]@{ protocolVersion = '2025-03-26' } }
        }
        return [pscustomobject]@{ result = [pscustomobject]@{} }
    }
    if ($request.method -eq 'tools/call') {
        return [pscustomobject]@{
            result = [pscustomobject]@{ structuredContent = [pscustomobject]@{ ok = $script:McpHealthOk } }
        }
    }
    throw "Unexpected MCP method: $($request.method)"
}

function Invoke-WebRequest {
    param([switch]$UseBasicParsing, $Uri, $TimeoutSec)
    $script:TunnelCalls += $Uri
    $index = $script:TunnelCalls.Count - 1
    return [pscustomobject]@{ Content = $script:TunnelResponses[$index] }
}

function Get-NetTCPConnection {
    param($State, $LocalPort, $ErrorAction)
    $script:CheckedPorts += $LocalPort
    if ($script:PortHasListener) { return [pscustomobject]@{ LocalPort = $LocalPort } }
    return $null
}

Describe 'Personal DC autostart recovery probes' {
    BeforeEach {
        $script:McpCalls = @()
        $script:McpHealthOk = $true
        $script:InitializeHasProtocol = $true
        $script:TunnelResponses = @('live', 'ready')
        $script:TunnelCalls = @()
        $script:PortHasListener = $false
        $script:CheckedPorts = @()
        $script:LogPath = $null
    }

    It 'requires MCP initialize and health tool success, including protocol negotiation' {
        (Test-McpHealth) | Should Be $true
        $script:McpCalls.Count | Should Be 2
        $script:McpCalls[0].Method | Should Be 'initialize'
        $script:McpCalls[1].Method | Should Be 'tools/call'
        $script:McpCalls[1].ProtocolVersion | Should Be '2025-03-26'

        $script:McpHealthOk = $false
        (Test-McpHealth) | Should Be $false

        $script:InitializeHasProtocol = $false
        (Test-McpHealth) | Should Be $false
    }

    It 'requires both tunnel liveness and readiness endpoints' {
        (Test-TunnelReady) | Should Be $true
        $script:TunnelCalls.Count | Should Be 2
        $script:TunnelCalls[0] | Should Be 'http://127.0.0.1:18080/healthz'
        $script:TunnelCalls[1] | Should Be 'http://127.0.0.1:18080/readyz'

        $script:TunnelResponses = @('live', 'not-ready')
        $script:TunnelCalls = @()
        (Test-TunnelReady) | Should Be $false
    }

    It 'refuses a port already owned by another listener' {
        (Test-PortFree 18765) | Should Be $true
        $script:PortHasListener = $true
        (Test-PortFree 18765) | Should Be $false
    }

    It 'aborts the production startup preflight on the first occupied loopback port' {
        $script:PortGuardAst | Should Not Be $null
        $script:PortHasListener = $true
        $failureMessage = $null
        try {
            Invoke-Expression $script:PortGuardAst.Extent.Text
        }
        catch {
            $failureMessage = $_.Exception.Message
        }

        $failureMessage | Should Match 'Required loopback port 18765 is already in use'
        $script:CheckedPorts.Count | Should Be 1
        $script:CheckedPorts[0] | Should Be 18765
    }

    It 'writes authentication failures through the production redaction path without logging secrets' {
        $script:RuntimeFailureCatchAst | Should Not Be $null
        $script:RuntimeFailureCatchBody | Should Match 'Redact-Message \$_.Exception.Message'
        $script:RuntimeFailureCatchBody | Should Match 'Write-Event "ERROR" "supervised_runtime_failure"'

        $testRoot = Join-Path ([IO.Path]::GetTempPath()) ("PersonalDC-AuthFailure-{0}" -f [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $testRoot | Out-Null
        $script:LogPath = Join-Path $testRoot 'autostart.log'
        $previousKey = $env:CONTROL_PLANE_API_KEY
        $env:CONTROL_PLANE_API_KEY = 'fixture-auth-secret'
        $script:FailureCount = 0
        try {
            try {
                throw [System.Exception]::new('authentication failed fixture-auth-secret token=second-fixture-secret')
            }
            catch {
                Invoke-Expression $script:RuntimeFailureCatchBody
            }

            $log = Get-Content -LiteralPath $script:LogPath -Raw
            $log | Should Match 'supervised_runtime_failure'
            $log | Should Match '\[REDACTED\]'
            $log | Should Not Match 'fixture-auth-secret'
            $log | Should Not Match 'second-fixture-secret'
        }
        finally {
            $env:CONTROL_PLANE_API_KEY = $previousKey
            Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
            $script:LogPath = $null
        }
    }

    It 'redacts runtime credentials from messages and key-value fields' {
        $previousKey = $env:CONTROL_PLANE_API_KEY
        try {
            $env:CONTROL_PLANE_API_KEY = 'test-only-secret'
            $message = Redact-Message 'request failed test-only-secret token=other-secret'
            $message | Should Be 'request failed [REDACTED] token=[REDACTED]'
        }
        finally {
            $env:CONTROL_PLANE_API_KEY = $previousKey
        }
    }
}
