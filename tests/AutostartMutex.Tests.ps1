$ErrorActionPreference = 'Stop'

# REC-01 acceptance: the persistent supervisor is logon-started only and ignores
# duplicate launches; a separate recovery task runs at logon and every minute.
# REC-02 acceptance: recovery uses one SID-scoped global mutex with explicit
# user/SYSTEM access, checks scheduler state under that lock, confirms activation,
# and safely handles abandoned locks and start races.
# All scheduler commands are mocks in child processes. Mutexes use unique test
# names and logs/files live under a temporary directory; production tasks and
# services are never queried, changed, or started.

$installerPath = Join-Path $PSScriptRoot '..\scripts\install-autostart.ps1'
$recoveryPath = Join-Path $PSScriptRoot '..\scripts\recover-autostart.ps1'
$retentionPath = Join-Path $PSScriptRoot '..\scripts\PersonalDCLogRetention.ps1'
$installer = Get-Content -LiteralPath $installerPath -Raw
$recovery = Get-Content -LiteralPath $recoveryPath -Raw

function Invoke-RecoveryFixture {
    param(
        [string[]]$States,
        [string]$MutexName = ("Global\Personal_DC_Test_{0}" -f [guid]::NewGuid().ToString('N')),
        [switch]$StartThrows,
        [string]$StartError = 'simulated start refusal'
    )

    $root = Join-Path ([IO.Path]::GetTempPath()) ("PersonalDC-Recovery-{0}" -f [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $root | Out-Null
    $scriptPath = Join-Path $root 'recovery-fixture.ps1'
    $getCountPath = Join-Path $root 'get-count.txt'
    $startCountPath = Join-Path $root 'start-count.txt'
    $stdoutPath = Join-Path $root 'fixture.stdout.log'
    $stderrPath = Join-Path $root 'fixture.stderr.log'
    $statesJsonLiteral = (ConvertTo-Json -InputObject @($States) -Compress).Replace("'", "''")
    $throwOnStart = if ($StartThrows) { '$true' } else { '$false' }
    $startErrorLiteral = $StartError.Replace("'", "''")
    $getCountLiteral = $getCountPath.Replace("'", "''")
    $startCountLiteral = $startCountPath.Replace("'", "''")

    $mockPrefix = @"
`$script:FixtureStates = ConvertFrom-Json -InputObject '$statesJsonLiteral'
`$script:FixtureGetCount = 0
function Get-ScheduledTask {
    param([string]`$TaskName, [string]`$ErrorAction)
    `$index = [Math]::Min(`$script:FixtureGetCount, `$script:FixtureStates.Count - 1)
    `$script:FixtureGetCount++
    Set-Content -LiteralPath '$getCountLiteral' -Value `$script:FixtureGetCount
    if (`$script:FixtureStates.Count -eq 0 -or `$script:FixtureStates[`$index] -eq '__MISSING__') { return `$null }
    return [pscustomobject]@{ State = `$script:FixtureStates[`$index] }
}
function Start-ScheduledTask {
    param([string]`$TaskName, [string]`$ErrorAction)
    `$count = 0
    if (Test-Path -LiteralPath '$startCountLiteral') {
        `$count = [int](Get-Content -LiteralPath '$startCountLiteral' -Raw)
    }
    Set-Content -LiteralPath '$startCountLiteral' -Value (`$count + 1)
    if ($throwOnStart) { throw '$startErrorLiteral' }
}
"@
    $fixtureSource = $recovery -replace '^\s*param\(\)\s*', ''
    Copy-Item -LiteralPath $retentionPath -Destination (Join-Path $root 'PersonalDCLogRetention.ps1')
    $fixtureSource = $fixtureSource.Replace(
        '$LogDirectory = Join-Path (Split-Path -Parent $PSScriptRoot) "logs"',
        ('$LogDirectory = "' + $root.Replace('"', '""') + '"')
    )
    $fixtureSource = $fixtureSource.Replace(
        '$mutexName = "Global\Personal_DC_V2_Tunnel_Recovery_$($userSid.Value)"',
        ('$mutexName = "' + $MutexName + '"')
    )
    Set-Content -LiteralPath $scriptPath -Value ($mockPrefix + "`r`n" + $fixtureSource) -Encoding UTF8

    try {
        $powershell = (Get-Command powershell.exe -ErrorAction Stop).Source
        $process = Start-Process -FilePath $powershell `
            -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $scriptPath + '"')) `
            -PassThru -Wait -WindowStyle Hidden -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
        $logFiles = @(Get-ChildItem -LiteralPath $root -Filter 'autostart-????????.log' -File -ErrorAction SilentlyContinue)
        $log = if ($logFiles.Count -gt 0) { ($logFiles | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join "`r`n" } else { '' }
        $getCount = if (Test-Path -LiteralPath $getCountPath) { [int](Get-Content -LiteralPath $getCountPath -Raw) } else { 0 }
        $startCount = if (Test-Path -LiteralPath $startCountPath) { [int](Get-Content -LiteralPath $startCountPath -Raw) } else { 0 }
        $stderr = if (Test-Path -LiteralPath $stderrPath) { Get-Content -LiteralPath $stderrPath -Raw } else { '' }
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            Log = $log
            GetCount = $getCount
            StartCount = $startCount
            Stderr = $stderr
            MutexName = $MutexName
            Root = $root
        }
    }
    finally {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Start-AbandonedMutexOwner {
    param([string]$MutexName)

    $root = Join-Path ([IO.Path]::GetTempPath()) ("PersonalDC-MutexOwner-{0}" -f [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $root | Out-Null
    $scriptPath = Join-Path $root 'abandon.ps1'
    $markerPath = Join-Path $root 'acquired.txt'
    $mutexLiteral = $MutexName.Replace("'", "''")
    $markerLiteral = $markerPath.Replace("'", "''")
    $ownerSource = @"
`$userSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
`$security = [System.Security.AccessControl.MutexSecurity]::new()
`$rights = [System.Security.AccessControl.MutexRights]::FullControl
`$allow = [System.Security.AccessControl.AccessControlType]::Allow
`$security.AddAccessRule([System.Security.AccessControl.MutexAccessRule]::new(`$userSid, `$rights, `$allow))
`$systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
`$security.AddAccessRule([System.Security.AccessControl.MutexAccessRule]::new(`$systemSid, `$rights, `$allow))
`$created = `$false
`$mutex = [Threading.Mutex]::new(`$false, '$mutexLiteral', [ref]`$created, `$security)
`$mutex.WaitOne(0) | Out-Null
Set-Content -LiteralPath '$markerLiteral' -Value 'acquired'
exit 0
"@
    Set-Content -LiteralPath $scriptPath -Value $ownerSource -Encoding UTF8
    $stdoutPath = Join-Path $root 'owner.stdout.log'
    $stderrPath = Join-Path $root 'owner.stderr.log'
    try {
        $powershell = (Get-Command powershell.exe -ErrorAction Stop).Source
        $process = Start-Process -FilePath $powershell `
            -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $scriptPath + '"')) `
            -PassThru -Wait -WindowStyle Hidden -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
        $stderr = if (Test-Path -LiteralPath $stderrPath) { Get-Content -LiteralPath $stderrPath -Raw } else { '' }
        if ($process.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $markerPath)) {
            throw "Could not acquire isolated abandonment mutex (exit=$($process.ExitCode)): $stderr"
        }
    }
    finally {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Start-HeldMutexOwner {
    param([string]$MutexName)

    $root = Join-Path ([IO.Path]::GetTempPath()) ("PersonalDC-MutexHolder-{0}" -f [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $root | Out-Null
    $scriptPath = Join-Path $root 'hold.ps1'
    $markerPath = Join-Path $root 'acquired.txt'
    $mutexLiteral = $MutexName.Replace("'", "''")
    $markerLiteral = $markerPath.Replace("'", "''")
    $ownerSource = @"
`$userSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
`$security = [System.Security.AccessControl.MutexSecurity]::new()
`$rights = [System.Security.AccessControl.MutexRights]::FullControl
`$allow = [System.Security.AccessControl.AccessControlType]::Allow
`$security.AddAccessRule([System.Security.AccessControl.MutexAccessRule]::new(`$userSid, `$rights, `$allow))
`$systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
`$security.AddAccessRule([System.Security.AccessControl.MutexAccessRule]::new(`$systemSid, `$rights, `$allow))
`$created = `$false
`$mutex = [Threading.Mutex]::new(`$false, '$mutexLiteral', [ref]`$created, `$security)
`$mutex.WaitOne(0) | Out-Null
Set-Content -LiteralPath '$markerLiteral' -Value 'acquired'
Start-Sleep -Seconds 30
"@
    Set-Content -LiteralPath $scriptPath -Value $ownerSource -Encoding UTF8
    $stdoutPath = Join-Path $root 'owner.stdout.log'
    $stderrPath = Join-Path $root 'owner.stderr.log'
    try {
        $powershell = (Get-Command powershell.exe -ErrorAction Stop).Source
        $process = Start-Process -FilePath $powershell `
            -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $scriptPath + '"')) `
            -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
        $deadline = [DateTime]::UtcNow.AddSeconds(5)
        while (-not (Test-Path -LiteralPath $markerPath) -and [DateTime]::UtcNow -lt $deadline -and -not $process.HasExited) {
            Start-Sleep -Milliseconds 50
        }
        $stderr = if (Test-Path -LiteralPath $stderrPath) { Get-Content -LiteralPath $stderrPath -Raw } else { '' }
        if ($process.HasExited -or -not (Test-Path -LiteralPath $markerPath)) {
            throw "Could not hold isolated test mutex (exit=$($process.ExitCode)): $stderr"
        }
        return [pscustomobject]@{ Process = $process; Root = $root }
    }
    catch {
        if ($process -and -not $process.HasExited) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
        throw
    }
}

Describe 'Personal DC scheduled recovery contract' {
    It 'registers the main supervisor without triggers, uses IgnoreNew, and omits restart retry settings' {
        $installer | Should Match '\$SupervisorSettings\s*=\s*New-ScheduledTaskSettingsSet(?s:.*?) -MultipleInstances IgnoreNew'
        $installer | Should Not Match '\$SupervisorSettings\s*=\s*New-ScheduledTaskSettingsSet(?s:.*?)-Restart(Count|Interval)'
        $installer | Should Match 'Register-ScheduledTask(?s:.*?) -TaskName \$TaskName(?s:.*?) -Settings \$SupervisorSettings'
        $installer | Should Not Match 'Register-ScheduledTask(?s:.*?) -TaskName \$TaskName(?s:.*?) -Trigger'
    }

    It 'registers recovery with logon and minute/daily triggers, Parallel, and a 30-second action limit' {
        $installer | Should Match '\$RecoveryLogonTrigger\s*=\s*New-ScheduledTaskTrigger\s+-AtLogOn'
        $installer | Should Match '\$RecoveryDailyTrigger\s*=\s*New-ScheduledTaskTrigger\s+-Daily'
        $installer | Should Match 'Interval\s*=\s*"PT1M"'
        $installer | Should Match 'Duration\s*=\s*"P1D"'
        $installer | Should Match '\$RecoveryTriggers\s*=\s*@\(\$RecoveryLogonTrigger,\s*\$RecoveryDailyTrigger\)'
        $installer | Should Match '\$RecoverySettings\s*=\s*New-ScheduledTaskSettingsSet(?s:.*?) -MultipleInstances Parallel'
        $installer | Should Match '\$RecoverySettings\s*=\s*New-ScheduledTaskSettingsSet(?s:.*?)-AllowStartIfOnBatteries'
        $installer | Should Match '\$RecoverySettings\s*=\s*New-ScheduledTaskSettingsSet(?s:.*?)-DontStopIfGoingOnBatteries'
        $installer | Should Match '-ExecutionTimeLimit \(New-TimeSpan -Seconds 30\)'
    }

    It 'creates a SID-scoped Global mutex with explicit user and SYSTEM ACL before state checks' {
        $recovery | Should Match '\$userSid\s*=\s*\[Security\.Principal\.WindowsIdentity\]::GetCurrent\(\)\.User'
        $recovery | Should Match 'Global\\Personal_DC_V2_Tunnel_Recovery_\$\(\$userSid\.Value\)'
        $recovery | Should Match 'MutexAccessRule.*?\$userSid.*?\$fullControl.*?\$allow'
        $recovery | Should Match 'S-1-5-18'
        $recovery.IndexOf('$Mutex = [Threading.Mutex]::new') | Should BeLessThan $recovery.IndexOf('Get-ScheduledTask -TaskName $TaskName')
        $recovery | Should Match 'catch \[Threading\.AbandonedMutexException\] \{ \$MutexHeld = \$true \}'
    }

    It 'treats Running and Queued as successful no-ops while holding a unique Global test mutex' {
        foreach ($state in @('Running', 'Queued')) {
            $fixtureMutex = "Global\Personal_DC_Test_$([guid]::NewGuid().ToString('N'))"
            $result = Invoke-RecoveryFixture -States @($state) -MutexName $fixtureMutex
            if ($result.ExitCode -ne 0) { throw "Fixture for $state failed: $($result.Stderr)" }
            $result.ExitCode | Should Be 0
            $result.GetCount | Should Be 1
            $result.StartCount | Should Be 0
            $result.Log | Should Match 'recovery_noop_supervisor_active'
            $result.Log | Should Match $state
        }
    }

    It 'requests one start and confirms Running or Queued scheduler state' {
        foreach ($activeState in @('Running', 'Queued')) {
            $result = Invoke-RecoveryFixture -States @('Ready', $activeState)
            if ($result.ExitCode -ne 0) { throw "Ready fixture for $activeState failed: $($result.Stderr)" }
            $result.ExitCode | Should Be 0
            $result.StartCount | Should Be 1
            $result.Log | Should Match 'recovery_start_confirmed'
            $result.Log | Should Match $activeState
        }
        $recovery | Should Match '\$startDeadline\s*=\s*\[DateTime\]::UtcNow\.AddSeconds\(10\)'
        $recovery | Should Match 'until \(\(\$current -and \[string\]\$current\.State -in @\("Running", "Queued"\)\) -or \[DateTime\]::UtcNow -ge \$startDeadline\)'
    }

    It 'treats a start refusal followed by a confirmed active state as a successful race' {
        foreach ($activeState in @('Running', 'Queued')) {
            $result = Invoke-RecoveryFixture -States @('Ready', $activeState) -StartThrows -StartError 'authorization token=fixture-secret denied'
            if ($result.ExitCode -ne 0) { throw "Race fixture for $activeState failed: $($result.Stderr)" }
            $result.ExitCode | Should Be 0
            $result.StartCount | Should Be 1
            $result.Log | Should Match 'recovery_start_race_already_active'
            $result.Log | Should Match $activeState
            $result.Log | Should Not Match 'fixture-secret'
        }
    }

    It 'treats an abandoned Global mutex as owned and proceeds to the scheduler state check' {
        $fixtureMutex = "Global\Personal_DC_Test_Abandoned_$([guid]::NewGuid().ToString('N'))"
        Start-AbandonedMutexOwner -MutexName $fixtureMutex
        $result = Invoke-RecoveryFixture -States @('Running') -MutexName $fixtureMutex
        if ($result.ExitCode -ne 0) { throw "Abandoned mutex fixture failed: $($result.Stderr)" }
        $result.ExitCode | Should Be 0
        $result.GetCount | Should Be 1
        $result.Log | Should Match 'recovery_noop_supervisor_active'
    }

    It 'does not inspect task state or start when another recovery action owns the Global mutex' {
        $fixtureMutex = "Global\Personal_DC_Test_Busy_$([guid]::NewGuid().ToString('N'))"
        $owner = Start-HeldMutexOwner -MutexName $fixtureMutex
        try {
            $result = Invoke-RecoveryFixture -States @('Ready') -MutexName $fixtureMutex
            $result.ExitCode | Should Be 0
            $result.GetCount | Should Be 0
            $result.StartCount | Should Be 0
            $result.Log | Should Be ''
        }
        finally {
            if (-not $owner.Process.HasExited) { Stop-Process -Id $owner.Process.Id -Force -ErrorAction SilentlyContinue }
            Remove-Item -LiteralPath $owner.Root -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'fails safely for missing, Disabled, and other non-startable states' {
        foreach ($state in @('__MISSING__', 'Disabled', 'Unknown')) {
            $result = Invoke-RecoveryFixture -States @($state)
            $result.ExitCode | Should Be 1
            $result.StartCount | Should Be 0
            $result.Log | Should Match 'recovery_failed'
            $result.Log | Should Match 'ERROR'
        }
    }

    It 'redacts credentials from scheduler failure details' {
        $result = Invoke-RecoveryFixture -States @('Ready') -StartThrows -StartError 'authorization token=fixture-secret denied'
        $result.ExitCode | Should Be 1
        $result.Log | Should Match 'recovery_failed'
        $result.Log | Should Match '\[REDACTED\]'
        $result.Log | Should Not Match 'fixture-secret'
    }
}
