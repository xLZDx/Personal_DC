# Add a daily Task Scheduler recovery trigger

## Change

Updated `scripts/install-autostart.ps1` to retain the current user's logon trigger and add a daily
calendar trigger that repeats every minute for one day. The repeating trigger uses
`MultipleInstances=IgnoreNew` and default-false `StopAtDurationEnd`, preserving the running
supervisor as well as the process overlap guard. Updated recovery,
setup, and security documentation with the actual Task Scheduler observations and limits.

## Why

Two isolated tasks configured with `RestartOnFailure` did not relaunch after controlled process
termination or a natural exit code 37. A bounded daily repeating trigger did relaunch after a
natural failure and gives the supervisor another start opportunity on the next minute while
retaining protection against overlapping task instances.

## E2E evidence

The E2E owner ran a disposable synthetic task on 2026-10-18 using the corrected trigger construction
as the installer. The optional `StopAtDurationEnd` XML element was omitted, which is its default
`false`; Microsoft's schema says `true` stops a running task at the end of the repetition duration.
The rejected candidate with `true` could have stopped the long-running supervisor and is not used.
Command:

```powershell
& (Join-Path $PSHOME 'pwsh.exe') -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File 'D:\Temp\Personal_DC_combined_false_runner_4fdd474b25c748e798b35ec4b32312e9.ps1'
```

Task: `Personal_DC_CombinedFalse_E2E_a85264f27ac4465eb0487e1f85a2b172`. Exported XML had the
current user's `LogonTrigger`, a `CalendarTrigger` with `DaysInterval=1`, repetition `PT1M` / `P1D`
and no `StopAtDurationEnd` element (default `false`), and `MultipleInstancesPolicy=IgnoreNew`.
Attempt 1 (PID 38536) started at `15:02:28.607 +03:00` and naturally exited 37. Attempt 2 (PID
11932) started at `15:03:29.246` and exited 0 at `15:03:39.309`. The gap was 60.639 seconds; the
observed overlap list was empty. Final task state was `Ready`, `LastTaskResult=0`, with the next
repetition scheduled. Cleanup confirmed the synthetic task, fixture directory, runner, and both
action PIDs were absent. No production task or unrelated process was changed.

A prior `P1D` fixture independently showed the same next-minute behavior. A `P3M` duration was
rejected by Task Scheduler at registration and is not used. The full 24-hour rollover was not
observed; the fixture was removed well before its next daily boundary.

## Production application and rollback

Before the first installer application, exported the original task XML to
`C:\Users\koros\AppData\Local\Personal_DC\backups\Personal_DC_V2_Tunnel-20261018-145757.xml`
(1687 bytes). After review rejected the `StopAtDurationEnd=true` candidate, exported that
intermediate configuration before correction to
`C:\Users\koros\AppData\Local\Personal_DC\backups\Personal_DC_V2_Tunnel-20261018-150406.xml`
(2048 bytes); do not restore the intermediate configuration. The corrected installer updated the
live task without stopping its running supervisor. Read-only inspection confirmed two triggers
(`LogonTrigger`, `CalendarTrigger`), daily interval 1, repetition PT1M/P1D, omitted/default-false
`StopAtDurationEnd`, `MultipleInstancesPolicy=IgnoreNew`, five configured restart attempts at PT1M,
the existing action path, and the same limited interactive principal. The task remained `Running`;
Personal DC Showcase health returned `ok`. At the 15:05:06 scheduled boundary, the result snapshot
was `2147946720` (`0x800710E0`) with a next run at 15:06:06. The Operational event channel is
disabled, so no production event explains that result. A disposable 75-second action reproduced the
same code when a minute trigger arrived while its prior instance was still running under
`IgnoreNew`. Synthetic task `Personal_DC_IgnoreNewOverlap_E2E_4e1261f87ba741d5a9faafe3e7b690c0`
ran action PID 33400 from `15:08:57.886` to `15:10:12.921`. At the next trigger, the task remained
`Running`; `LastTaskResult` changed from `267009` (`0x00041301`) to `2147946720` (`0x800710E0`)
while the original action remained active. The next run advanced by one minute, attempt count
remained one, and maximum concurrent action count was one. After natural exit 0, the result returned
to 0. Cleanup removed the task, fixture directory, runner, and action PID. The Operational channel
was disabled, so event corroboration was unavailable. This supports interpreting the production
snapshot as a refused overlapping start, but does not prove that was its cause. The direct health
check returned `ok`; no failure was injected into the production task. To return to the original
definition, restore the 14:57 XML backup using the procedure in `docs/AUTOSTART_RECOVERY.md`.

## Verification state

The synthetic daily recovery E2E and the separate long-action `IgnoreNew` overlap E2E passed with no
overlapping action processes. Functional tests for
the backend/tunnel supervisor previously passed 4/4 and isolated supervisor E2E scenarios passed
4/4; their detailed record is `docs/commits/2026-10-18-autostart-recovery-tests.md`. The current
live task update, rollback export, XML inspection and Personal DC Showcase health recheck are
complete. The 24-hour daily rollover and Task Scheduler Operational event corroboration are
`NOT_RUN`. No primary-session test suite was run; the primary session reviewed the exact final
staged diff and performed read-only task XML and health verification.

## Ownership

The operator is accountable for the delegated Personal DC restoration; Codex implemented the
installer change. The E2E agent owns the focused synthetic test. No canonical human owner for the
host Task Scheduler event-channel policy was found; diagnosing the separate `RestartOnFailure`
behavior requires that owner to authorize enabling/reading the Operational event channel.
