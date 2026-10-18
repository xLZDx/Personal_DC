param()
$ErrorActionPreference = "Stop"
$SecretPath = Join-Path $env:LOCALAPPDATA "Personal_DC\secrets\runtime-key.dpapi"
$TaskName = "Personal_DC_V2_Tunnel"
$HealthBase = "http://127.0.0.1:18080"
$McpUrl = "http://127.0.0.1:18765/mcp"

$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
$result = [ordered]@{
    SecretExists = Test-Path $SecretPath
    TaskExists = [bool]$task
    TaskState = if ($task) { [string]$task.State } else { "Missing" }
    TaskAction = if ($task -and $task.Actions.Count -gt 0) { [string]$task.Actions[0].Execute + " " + [string]$task.Actions[0].Arguments } else { "Missing" }
    LastRunTime = if ($task) { (Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue).LastRunTime } else { $null }
    LastTaskResult = if ($task) { (Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue).LastTaskResult } else { $null }
    Health = $false
    Ready = $false
    HealthBase = $HealthBase
    McpHealth = $false
    McpEndpoint = $McpUrl
}

try {
    $result.Health = ((Invoke-WebRequest -UseBasicParsing ($HealthBase + "/healthz") -TimeoutSec 3).Content.Trim() -eq "live")
    $result.Ready = ((Invoke-WebRequest -UseBasicParsing ($HealthBase + "/readyz") -TimeoutSec 3).Content.Trim() -eq "ready")
} catch {
    $result.HealthError = $_.Exception.Message -replace '(?i)(authorization|api[_-]?key|token)(\s*[:=]\s*)[^\s,;]+', '$1$2[REDACTED]'
}

try {
    $headers = @{ Accept = "application/json, text/event-stream" }
    $initializeBody = @{
        jsonrpc = "2.0"
        id = 1
        method = "initialize"
        params = @{
            protocolVersion = "2025-03-26"
            capabilities = @{}
            clientInfo = @{ name = "Personal DC status probe"; version = "1.0" }
        }
    } | ConvertTo-Json -Compress -Depth 6
    $initialized = Invoke-RestMethod -Method Post -Uri $McpUrl -Headers $headers `
        -ContentType "application/json" -Body $initializeBody -TimeoutSec 5
    if (-not $initialized.result.protocolVersion) { throw "MCP initialize response was invalid." }

    $headers["MCP-Protocol-Version"] = [string]$initialized.result.protocolVersion
    $callBody = @{
        jsonrpc = "2.0"
        id = 2
        method = "tools/call"
        params = @{ name = "health"; arguments = @{} }
    } | ConvertTo-Json -Compress -Depth 6
    $response = Invoke-RestMethod -Method Post -Uri $McpUrl -Headers $headers `
        -ContentType "application/json" -Body $callBody -TimeoutSec 5
    $result.McpHealth = ($response.result.structuredContent.ok -eq $true)
    if (-not $result.McpHealth -and $response.result.content.Count -gt 0 -and $response.result.content[0].text) {
        $content = $response.result.content[0].text | ConvertFrom-Json
        $result.McpHealth = ($content.ok -eq $true)
    }
    if (-not $result.McpHealth) { $result.McpError = "MCP health tool did not report ok=true." }
}
catch {
    $result.McpError = $_.Exception.Message -replace '(?i)(authorization|api[_-]?key|token)(\s*[:=]\s*)[^\s,;]+', '$1$2[REDACTED]'
}

[pscustomobject]$result | Format-List
