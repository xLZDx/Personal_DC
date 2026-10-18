# Record isolated Task Scheduler retry evidence

## Change

Updated the autostart recovery, security, and ChatGPT setup documentation to distinguish the
configured Task Scheduler retry policy from runtime-proven behavior. Added backlog item BL-02 for
the unconfirmed supervisor-failure recovery path.

## Why

An isolated task with the configured one-shot trigger and retry settings did not start a second
attempt after the action naturally returned a nonzero exit code. Documentation that said Scheduler
retries a failed supervisor as a fact overstated the available evidence.

## Evidence

E2E owner ran on 2026-10-18:

```powershell
& (Join-Path $PSHOME 'pwsh.exe') -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File 'D:\Temp\Personal_DC_natural_failure_runner_f611aeb0290b46fcac016f016a4677e7.ps1'
```

Synthetic task `Personal_DC_NaturalFailure_E2E_3d87828e3c4840be98d2299bbd79dba9` used a real
one-shot trigger at `2026-10-18 14:38:17.5515661 +03:00`. Its exact PowerShell action started at
`14:38:18.567993 +03:00` and naturally returned 37. Observation ended at
`14:40:37.0550759`, more than 138 seconds after action start. Only one attempt occurred. Final
state was `Ready`, `LastTaskResult=37`, `NextRunTime` absent, and missed runs 0. Exported XML
confirmed `RestartOnFailure` Count=2 / Interval=PT1M, `ExecutionTimeLimit=PT0S`,
`MultipleInstancesPolicy=IgnoreNew`, the one-shot trigger, and the synthetic action path.

The `Microsoft-Windows-TaskScheduler/Operational` channel was disabled before and after the run;
`Get-WinEvent` returned `No events were found that match the specified selection criteria`. The
synthetic task, PID 29912, fixture directory, and runner were removed. Production task, other
processes, and repository code were not modified by the E2E run.

Two follow-up trigger experiments used disposable per-user tasks. A one-shot trigger with a
two-minute repetition window started a second action after the first naturally exited 37; the
second exited 0. `MultipleInstancesPolicy=IgnoreNew` prevented overlapping action processes.
Exactly two attempts occurred and there was no next run after the window. A daily trigger with
duration `P3M` was rejected at registration as out of range (`Duration:P3M`); the task was not
registered and no action ran. A first daily `P1D` trigger included `StopAtDurationEnd=true` and
restarted its synthetic action after a natural exit 37 within 66 seconds. Review found that this
setting can terminate a still-running task at the end of the window, so that configuration was
rejected. The corrected fallback omits the optional element (default `false`); its exact
combined-trigger E2E is recorded in `2026-10-18-daily-task-recovery.md`. Runtime rollover remains
`NOT_RUN`.

Microsoft's [RestartOnFailure schema](https://learn.microsoft.com/en-us/windows/win32/taskschd/taskschedulerschema-restartonfailure-settingstype-element)
describes the expected retry policy. The local result conflicts with that expectation, but does not
identify the cause. No change to the production trigger or retry configuration is made in this
commit.

## Verification state

The isolated `RestartOnFailure` scenarios observed **no retry**. A daily repeating fallback
recovered after a natural exit within 60.686 seconds and passed without overlaps in a synthetic task.
The proposed three-month daily repetition was rejected by Task Scheduler. The current production
task was not fault-injected. The original documentation investigation did not change its
configuration; the separate installer change and later live application are detailed in
`2026-10-18-daily-task-recovery.md`.

## Ownership

The operator is accountable for the delegated Personal DC task; Codex executed the documentation
update. The host administrator/event-channel policy owner is not identified in available records.
The next diagnostic requires authorized access to enable/read the Task Scheduler Operational
channel and repeat the isolated scenario.
