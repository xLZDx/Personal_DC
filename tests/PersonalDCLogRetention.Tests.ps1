$ErrorActionPreference = 'Stop'

$helperPath = Join-Path $PSScriptRoot '..\scripts\PersonalDCLogRetention.ps1'
$supervisorPath = Join-Path $PSScriptRoot '..\scripts\start-autostart.ps1'
. (Resolve-Path -LiteralPath $helperPath)

function New-RetentionFixture {
    $path = Join-Path ([IO.Path]::GetTempPath()) ("PersonalDC-Retention-{0}" -f [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $path | Out-Null
    return $path
}

function Set-FixtureLogTime([string]$Path, [datetime]$LastWriteTimeUtc) {
    [IO.File]::WriteAllText($Path, 'fixture')
    [IO.File]::SetLastWriteTimeUtc($Path, $LastWriteTimeUtc)
}

Describe 'Personal DC seven-day log retention' {
    It 'builds dated stream paths from the UTC calendar day' {
        $directory = New-RetentionFixture
        try {
            $instant = [DateTimeOffset]::new(2026, 10, 18, 0, 30, 0, [TimeSpan]::FromHours(3))
            $localTimeForInstant = $instant.LocalDateTime
            foreach ($stream in @('autostart', 'backend.stdout', 'backend.stderr', 'tunnel.stdout', 'tunnel.stderr')) {
                $path = Get-PersonalDCLogPath -Directory $directory -Stream $stream -TimestampUtc $localTimeForInstant
                [IO.Path]::GetFileName($path) | Should Be ("{0}-20261017.log" -f $stream)
            }
        }
        finally {
            Remove-Item -LiteralPath $directory -Recurse -Force
        }
    }

    It 'expires event logs only when they are strictly older than seven days and preserves unrelated files' {
        $directory = New-RetentionFixture
        $now = [DateTime]::SpecifyKind([datetime]'2026-10-18T12:00:00', [DateTimeKind]::Utc)
        $cutoff = $now.AddDays(-7)
        $expiredLegacy = Join-Path $directory 'autostart.log'
        $expiredDated = Join-Path $directory 'autostart-20261001.log'
        $atBoundary = Join-Path $directory 'autostart-20261011.log'
        $recent = Join-Path $directory 'autostart-20261018.log'
        $unrelated = Join-Path $directory 'notes.log'
        $oldChildStream = Join-Path $directory 'backend.stdout.log'
        $recentChildStream = Join-Path $directory 'backend.stderr-20261018.log'
        try {
            Set-FixtureLogTime $expiredLegacy $cutoff.AddTicks(-1)
            Set-FixtureLogTime $expiredDated $cutoff.AddDays(-1)
            Set-FixtureLogTime $atBoundary $cutoff
            Set-FixtureLogTime $recent $now.AddDays(-1)
            Set-FixtureLogTime $unrelated $now.AddDays(-30)
            Set-FixtureLogTime $oldChildStream $now.AddDays(-30)
            Set-FixtureLogTime $recentChildStream $now.AddDays(-1)

            Remove-ExpiredPersonalDCLogs -Directory $directory -NowUtc $now

            (Test-Path -LiteralPath $expiredLegacy) | Should Be $false
            (Test-Path -LiteralPath $expiredDated) | Should Be $false
            (Test-Path -LiteralPath $atBoundary) | Should Be $true
            (Test-Path -LiteralPath $recent) | Should Be $true
            (Test-Path -LiteralPath $unrelated) | Should Be $true
            # Child handles are cleaned only after the supervisor has stopped its owned processes.
            (Test-Path -LiteralPath $oldChildStream) | Should Be $true

            Remove-ExpiredPersonalDCLogs -Directory $directory -NowUtc $now -IncludeChildStreams
            (Test-Path -LiteralPath $oldChildStream) | Should Be $false
            (Test-Path -LiteralPath $recentChildStream) | Should Be $true
            (Test-Path -LiteralPath $unrelated) | Should Be $true
        }
        finally {
            Remove-Item -LiteralPath $directory -Recurse -Force
        }
    }

    It 'serializes concurrent event appends into complete, parseable JSONL records' {
        $directory = New-RetentionFixture
        $workerPath = Join-Path $directory 'write-events.ps1'
        $workerSource = @'
param([string]$HelperPath, [string]$Directory, [string]$Worker, [int]$Count)
$ErrorActionPreference = 'Stop'
. $HelperPath
for ($index = 0; $index -lt $Count; $index++) {
    Write-PersonalDCEvent -Directory $Directory -Level 'INFO' -Event 'parallel_fixture' -Data @{ worker = $Worker; index = $index }
}
'@
        Set-Content -LiteralPath $workerPath -Value $workerSource -Encoding UTF8
        $workerCount = 6
        $eventsPerWorker = 20
        $processes = @()
        try {
            $powershell = (Get-Command powershell.exe -ErrorAction Stop).Source
            for ($worker = 0; $worker -lt $workerCount; $worker++) {
                $arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -HelperPath "{1}" -Directory "{2}" -Worker "{3}" -Count {4}' -f `
                    $workerPath, (Resolve-Path -LiteralPath $helperPath).Path, $directory, $worker, $eventsPerWorker
                $processes += Start-Process -FilePath $powershell -ArgumentList $arguments -PassThru -WindowStyle Hidden
            }

            foreach ($process in $processes) {
                if (-not $process.WaitForExit(30000)) {
                    $process.Kill()
                    throw "Event writer process $($process.Id) exceeded the 30-second fixture timeout."
                }
                $process.ExitCode | Should Be 0
            }

            $eventPath = Get-PersonalDCLogPath -Directory $directory -Stream 'autostart' -TimestampUtc ([DateTime]::UtcNow)
            $lines = [IO.File]::ReadAllLines($eventPath)
            $lines.Count | Should Be ($workerCount * $eventsPerWorker)
            $records = @($lines | ForEach-Object { $_ | ConvertFrom-Json })
            $records.Count | Should Be ($workerCount * $eventsPerWorker)
            @($records | ForEach-Object { '{0}:{1}' -f $_.data.worker, $_.data.index } | Select-Object -Unique).Count |
                Should Be ($workerCount * $eventsPerWorker)
            @($records | Where-Object { $_.event -ne 'parallel_fixture' }).Count | Should Be 0
        }
        finally {
            foreach ($process in $processes) {
                if (-not $process.HasExited) { $process.Kill() }
                $process.Dispose()
            }
            Remove-Item -LiteralPath $directory -Recurse -Force
        }
    }

    It 'wires UTC-day rollover to stop owned children before child-log expiration and restart' {
        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            (Resolve-Path -LiteralPath $supervisorPath), [ref]$tokens, [ref]$parseErrors
        )
        $parseErrors.Count | Should Be 0
        $supervisor = Get-Content -LiteralPath $supervisorPath -Raw
        $portGuard = $supervisor.IndexOf('foreach ($port in @(18765, 18080))', [StringComparison]::Ordinal)
        $startupCleanup = $supervisor.IndexOf('Remove-ExpiredPersonalDCLogs -Directory $LogDirectory -NowUtc ([DateTime]::UtcNow) -IncludeChildStreams', [StringComparison]::Ordinal)
        $rolloverCheck = $supervisor.IndexOf('if ([DateTime]::UtcNow.Date -ne $logDay)', [StringComparison]::Ordinal)
        $ownedStop = $supervisor.IndexOf('Stop-OwnedProcess $Tunnel "tunnel-client"', $rolloverCheck, [StringComparison]::Ordinal)
        $backendStop = $supervisor.IndexOf('Stop-OwnedProcess $Backend "personal-dc-backend"', $ownedStop, [StringComparison]::Ordinal)
        $stopFailureGuard = $supervisor.IndexOf('if (-not $ownedProcessesStopped)', $backendStop, [StringComparison]::Ordinal)
        $postStopCleanup = $supervisor.IndexOf('Remove-ExpiredPersonalDCLogs -Directory $LogDirectory -NowUtc ([DateTime]::UtcNow) -IncludeChildStreams', $startupCleanup + 1, [StringComparison]::Ordinal)
        $rolloverContinue = $supervisor.IndexOf('if ($dailyLogRollover)', $postStopCleanup, [StringComparison]::Ordinal)
        $datePathArguments = [regex]::Matches($supervisor, '-TimestampUtc \(\[DateTime\]::UtcNow\)')

        ($portGuard -ge 0) | Should Be $true
        ($startupCleanup -gt $portGuard) | Should Be $true
        ($rolloverCheck -gt $startupCleanup) | Should Be $true
        ($ownedStop -gt $rolloverCheck) | Should Be $true
        ($backendStop -gt $ownedStop) | Should Be $true
        ($stopFailureGuard -gt $backendStop) | Should Be $true
        ($postStopCleanup -gt $stopFailureGuard) | Should Be $true
        ($postStopCleanup -gt $backendStop) | Should Be $true
        ($rolloverContinue -gt $postStopCleanup) | Should Be $true
        $datePathArguments.Count | Should Be 4
        $supervisor.Substring($stopFailureGuard, $postStopCleanup - $stopFailureGuard) |
            Should Match 'An owned Personal DC child did not stop; refusing to start another instance or expire its active log\.'
        $supervisor.Substring($rolloverCheck, $ownedStop - $rolloverCheck) | Should Match '\$dailyLogRollover\s*=\s*\$true[\s\S]*?break'
        $supervisor.Substring($rolloverContinue, [Math]::Min(300, $supervisor.Length - $rolloverContinue)) |
            Should Match 'daily_log_rollover_complete[\s\S]*?continue'
    }
}
