# Windows autostart recovery

## Managed components

`Personal_DC_V2_Tunnel` is the supported logon task. Its action must run
`scripts/start-autostart.ps1` from this checkout as the interactive Windows user that owns the
DPAPI runtime key. The disabled `Personal_DC_Tunnel` legacy task is separate and is not modified by
the v2 installer.

The PowerShell supervisor owns normal backend and tunnel recovery. It holds a per-session mutex,
checks the Streamable HTTP `initialize` and `health` tool exchange on `127.0.0.1:18765/mcp`, checks
the tunnel client's `/healthz` and `/readyz` endpoints on `127.0.0.1:18080`, and restarts only the
two processes it launched. Retry delay grows exponentially and is capped at five minutes. The
previous task registration configured five Task Scheduler recovery attempts at one-minute intervals,
but controlled isolated failures did not produce a retry. The installer splits recovery between two tasks:
the long-running supervisor has no triggers and keeps `MultipleInstances=IgnoreNew`; the short-lived
recovery task has both a user logon trigger and a daily trigger repeating every minute for one day.
It starts the supervisor only when Task Scheduler reports it `Ready`. The recovery task uses
`MultipleInstances=Parallel` so simultaneous logon and minute triggers do not get refused by
Task Scheduler; a SID-scoped mutex in the Global namespace serializes competing recovery actions
before they inspect or start the supervisor. Cross-session runtime was unavailable and remains
`NOT_RUN`. This avoids repeatedly triggering the still-running
supervisor, which produced `0x800710E0` under `IgnoreNew`, and avoids relying on the supervisor's
session-scoped mutex for cross-session serialization. The recovery action is bounded to 30 seconds
and exits immediately when the supervisor is already running. The repetition uses
`StopAtDurationEnd=false` (the Task Scheduler XML omits this optional default-false element), so the
window boundary does not terminate a running task. In-process recovery of backend/tunnel failures
passed its isolated scenarios. The daily fallback's next-minute restart passed in an isolated task;
a full 24-hour rollover has not been observed. See [Microsoft's repetition pattern documentation](https://learn.microsoft.com/en-us/windows/win32/taskschd/taskschedulerschema-stopatdurationend-repetitiontype-element).
This scheduler-state watchdog recovers an exited task; it does not detect a supervisor that remains
`Running` while hung. Child-service and health failures remain the supervisor's responsibility.

Structured, secret-safe startup events are appended to `logs/autostart.log`. Backend and tunnel
standard output/error remain in their dedicated log files. The DPAPI key remains in the existing
per-user store and is not emitted to logs.

## Install or repair the task

Run from an elevated PowerShell session only if the current account has permission to register the
task:

```powershell
Set-Location D:\Repo\Personal_DC
.\scripts\install-autostart.ps1
.\scripts\status-autostart.ps1
```

The installer configures two current-user tasks. `Personal_DC_V2_Tunnel` has no triggers,
`IgnoreNew`, and the repository's absolute start-script path. `Personal_DC_V2_Tunnel_Recovery` has a
logon trigger and a daily trigger repeating every minute for one day; its action uses a global
mutex and starts the supervisor only when its registered task state is `Ready`. The watchdog does
not stop a running supervisor. Isolated scheduler scenarios confirmed repeated no-op ticks, natural
exit recovery in 54.007 seconds, preservation of the active PID during task re-registration, and
serialization of overlapping recovery actions with one acquired and one denied mutex attempt. The
combined fixture's overlap assertion sampled the supervisor before releasing its own test barrier;
the scenario was rerun separately with corrected synchronization and passed. No `0x800710E0` was
observed in the passing candidate scenarios. The design is installed on the live user task. A fresh
backup of the previous main task definition is
`%LOCALAPPDATA%\Personal_DC\backups\Personal_DC_V2_Tunnel-20261018-161323.xml` (3,992 bytes).
After installation the original supervisor PID 7724 remained running, both recovery minute ticks
completed with result 0, and Personal DC Showcase health returned `ok`. The main task's displayed
`LastTaskResult` still contains its pre-install historical `0x800710E0`; because its triggers are
now absent, that value is not a new post-install attempt. The recovery task result is 0. Cross-session
mutex use and the full 24-hour repetition rollover remain `NOT_RUN`; the separate historical
`RestartOnFailure` behavior remains unexplained and is not relied upon. The installer does not
create a tunnel, replace the profile, or regenerate credentials.

## Roll back a task registration

Before changing the live task, export its exact XML to
`%LOCALAPPDATA%\Personal_DC\backups\Personal_DC_V2_Tunnel-<timestamp>.xml`:

```powershell
$backupDir = Join-Path $env:LOCALAPPDATA 'Personal_DC\backups'
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
$backup = Join-Path $backupDir ("Personal_DC_V2_Tunnel-{0}.xml" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
Export-ScheduledTask -TaskName Personal_DC_V2_Tunnel | Set-Content -LiteralPath $backup -Encoding utf8
Get-Item -LiteralPath $backup | Select-Object FullName,Length
```

If `Personal_DC_V2_Tunnel_Recovery` already exists, export its XML to a separate timestamped file
in the same directory before replacing it. The installer registers the recovery task before
updating the supervisor task, so the existing supervisor can remain running while the new
registration is applied.

Confirm the file exists and is non-empty before changing the task. To restore that saved
registration:

```powershell
$backup = 'C:\Users\<user>\AppData\Local\Personal_DC\backups\Personal_DC_V2_Tunnel-<timestamp>.xml'
$xml = Get-Content -LiteralPath $backup -Raw
Register-ScheduledTask -TaskName Personal_DC_V2_Tunnel -Xml $xml -Force
```

This restores the selected task definition, not the service runtime state. If rolling back to a
backup from before the recovery task existed, remove `Personal_DC_V2_Tunnel_Recovery` after restoring
the old supervisor definition. Start/stop the supervisor separately only after inspecting its
restored action and principal; do not terminate the existing production process as part of the
definition rollback.

## Roll back the tunnel profile

Before changing the profile, save
`%LOCALAPPDATA%\Personal_DC\backups\personal-dc-<timestamp>.yaml`. To restore that exact profile,
copy the selected backup over `%APPDATA%\tunnel-client\personal-dc.yaml`, then restart
`Personal_DC_V2_Tunnel` so the client reloads it. Verify the tunnel ID and MCP target before starting.

## Troubleshooting

Check `logs/autostart.log` for `supervisor_fatal`, `supervised_runtime_failure`,
`backend_ready`, `tunnel_ready`, and `restart_backoff` events. Do not treat a listening TCP port as
proof of a working MCP service; the supervisor requires a protocol initialization and `health` tool
response. Do not stop a process solely because it uses port `21080`; that port is outside Personal
DC's configured backend and tunnel health ports.

## Isolated supervisor recovery evidence

On 2026-10-18, an E2E owner exercised a disposable copy of the supervisor on loopback ports
`14941` and `14942`, with synthetic MCP backend/tunnel processes and a synthetic DPAPI key. The run
passed startup/health, backend failure/restart, fake-tunnel failure/restart, and Job Object cleanup
(4/4 scenarios). It did not invoke the real tunnel client, use real credentials, contact cloud
services, register a scheduled task, or modify this checkout. The supervisor copy used nine
explicit substitutions; this evidence covers orchestration and process ownership with fakes, not
the real backend/tunnel binaries or Windows Task Scheduler crash-retry behavior.

The complete disposable run and result remain under:
`D:\Temp\Personal_DC_recovery_E2E_retry_3e33a8d1cd00429b831b6c32a1678b83`.

```powershell
& (Join-Path $PSHOME 'pwsh.exe') -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File 'D:\Temp\Personal_DC_recovery_E2E_retry_3e33a8d1cd00429b831b6c32a1678b83\run_recovery_e2e.ps1'
```

## Isolated Task Scheduler retry observation

On 2026-10-18, two E2E runs used uniquely named per-user scheduled tasks with real one-shot triggers
and `RestartOnFailure` Count=2 / Interval=PT1M. In the first run,
`Personal_DC_TriggeredRetry_E2E_ada242400f734df49473fa52b833b58d` launched its action at
`14:20:32.505 +03:00`; after verifying PID 3560 belonged to the exact synthetic command, the owner
ended only that process. No second attempt appeared over the next 130 seconds. In the second run,
`Personal_DC_NaturalFailure_E2E_3d87828e3c4840be98d2299bbd79dba9` naturally returned exit code 37.
No second attempt appeared during more than 138 seconds of observation; the task returned to
`Ready`, `LastTaskResult=37`, and `NextRunTime` was empty. The exported XML confirmed the retry
settings, `ExecutionTimeLimit=PT0S`,
`MultipleInstancesPolicy=IgnoreNew`, the one-shot trigger, and the action path. The
`Microsoft-Windows-TaskScheduler/Operational` channel was disabled before and after the run, so no
matching events were available. The test task, action process, fixture directory, and runner were
removed. The production task and unrelated processes were not changed.

This is an observed failure to retry in the isolated fixture; its cause is not established. The
result also occurred with a natural nonzero exit, not only process termination. Microsoft documents
`RestartOnFailure` as retrying when a task fails, with both Count and Interval set. The local result
does not match that expected behavior; see [Microsoft's RestartOnFailure schema](https://learn.microsoft.com/en-us/windows/win32/taskschd/taskschedulerschema-restartonfailure-settingstype-element).

An additional disposable task verified that a one-shot trigger with a two-minute repetition window
can launch the next scheduled attempt after a natural exit 37: the first action exited at
`14:43:09.073 +03:00`; the second began at `14:44:10.739 +03:00` and exited 0 at
`14:44:25.787 +03:00`. `MultipleInstancesPolicy=IgnoreNew` prevented overlapping action processes.
The task ended after exactly two attempts with no next run. This proves short-window trigger
repetition, not a durable daily schedule. A proposed daily trigger with `P3M` repetition duration
was rejected during registration as out of range (`Duration:P3M`); no task or action was created.
A first `P1D` fixture used `StopAtDurationEnd=true` and demonstrated recovery within its window, but
that setting can terminate the currently running supervisor at the window boundary and is not used
by the installer. The corrected combined-trigger fixture omitted the optional
`StopAtDurationEnd` XML element (default `false`). It registered a logon trigger and a daily
calendar trigger (`DaysInterval=1`, repetition `PT1M` / `P1D`, `MultipleInstancesPolicy=IgnoreNew`).
After action PID 38536 naturally exited 37 at `15:02:28.607 +03:00`, PID 11932 started at
`15:03:29.246` and exited 0 at `15:03:39.309`. The interval was 60.639 seconds and there were no
overlapping action processes. The fixture was removed before the 24-hour boundary, so runtime
renewal across that boundary is `NOT_RUN`; the daily recurrence is defined by `DaysInterval=1`.

Live task update on 2026-10-18: the corrected installer registered both triggers. A read-only XML
query confirmed `DaysInterval=1`, `Interval=PT1M`, `Duration=P1D`, omitted/default-false
`StopAtDurationEnd`, `MultipleInstancesPolicy=IgnoreNew`, five configured restart attempts, the
current user's limited interactive principal, and the existing repository action. The task
remained `Running`; Personal DC Showcase health returned `ok`. The original pre-change XML backup
is `C:\Users\koros\AppData\Local\Personal_DC\backups\Personal_DC_V2_Tunnel-20261018-145757.xml`.
The intermediate configuration using `StopAtDurationEnd=true` was also backed up before correction
at `C:\Users\koros\AppData\Local\Personal_DC\backups\Personal_DC_V2_Tunnel-20261018-150406.xml`;
do not restore that intermediate configuration. The full 24-hour rollover remains `NOT_RUN`.

The separate `RestartOnFailure` diagnostic is still open: obtain authorization from the Windows
configuration owner to enable/read the Task Scheduler Operational channel, then repeat its fixture
while capturing event IDs and the exact state/result timeline. That policy owner is not identified
in available records. Do not inject failures into `Personal_DC_V2_Tunnel`. A Hyper-V inventory
permission is not required for these per-user fixtures because they ran safely on the host.

A read-only query after the corrected update confirmed `State=Running`, `RestartCount=5`,
`RestartInterval=PT1M`, `MultipleInstances=IgnoreNew`, and `ExecutionTimeLimit=PT0S`. At `15:05:06`,
`LastTaskResult=2147946720` (`0x800710E0`) and the next run was scheduled for `15:06:06`; the
Task Scheduler Operational channel is disabled, so no production event explains this result. A
disposable 75-second action reproduced the same code when a minute trigger arrived while its prior
instance was still running under `IgnoreNew`: the task stayed `Running`, launched no overlapping
action, and reported `0x800710E0` until the action exited 0, after which `LastTaskResult` returned
to 0. This supports interpreting the production snapshot as a refused overlapping start, but does
not prove that was its cause. The direct Personal DC Showcase health call returned `ok`. These
settings confirm the configured retry policy, not successful `RestartOnFailure` recovery. The
isolated natural-failure scenario above produced no retry within more than 138 seconds. The daily
fallback is installed on the production task; no failure was injected into that task. The 24-hour
rollover remains `NOT_RUN`.
