# Separate Personal DC recovery from the long-running supervisor

## Problem

The production `Personal_DC_V2_Tunnel` supervisor runs continuously and had a daily trigger
repeating every minute. With `MultipleInstances=IgnoreNew`, an isolated 75-second action reproduced
Task Scheduler result `0x800710E0` when a repeated trigger arrived while the previous instance was
still running. Production MCP health remained `ok`; a production snapshot showed the same result,
but Task Scheduler Operational events were disabled, so that snapshot alone did not prove its
cause.

## Decision

Do not use `MultipleInstances=Parallel` with the existing
`Local\Personal_DC_V2_Tunnel_Supervisor` mutex. The mutex is scoped to one Windows session, so a
second session could acquire a different mutex and attempt to start another supervisor. A same-
session isolated fixture showed the proposed parallel action exited without a second mutex holder,
but that evidence does not close the cross-session risk.

The first separate-watchdog candidate moved only the minute repetition; an isolated controlled race
with the main task's logon trigger reproduced `0x800710E0` even though only one supervisor process
ran. The revised candidate removes every trigger from the main task and moves both logon and minute
triggers to a short recovery task. The main task retains `IgnoreNew` as a safety guard, but only the
recovery action starts it. The recovery task uses `Parallel` plus a SID-named `Global\` mutex whose
ACL permits that user and SYSTEM, so simultaneous recovery actions contend on one machine-wide
object before they inspect or start the supervisor. Cross-session runtime was not available to
verify. The action exits successfully while the supervisor is `Running` or `Queued`, and requests a start
only when it is `Ready`. A race with an explicit external/manual start is treated as successful only
after Task Scheduler reports the supervisor active. A missing, disabled, or otherwise non-startable
task is logged as an error. The recovery action never stops the supervisor or its child processes.

## Affected paths

- `scripts/install-autostart.ps1`: registers the short recovery task first, then registers the
  long-running supervisor with no triggers and `IgnoreNew`.
- `scripts/recover-autostart.ps1`: implements the state-based bounded recovery action, acquires a
  machine-wide named mutex, and emits secret-safe structured events to `logs/autostart.log`.
- `scripts/start-autostart.ps1`: retains the per-session mutex as defense against duplicate direct
  invocations within one session. Task Scheduler's main-task `IgnoreNew` setting is the cross-session
  serialization boundary.
- `tests/AutostartMutex.Tests.ps1`: replace the previous same-session `Parallel` candidate coverage
  with watchdog state, race, failure, scheduling, and duplicate-start acceptance tests.
- `docs/AUTOSTART_RECOVERY.md`, `docs/CHATGPT_SETUP.md`, `docs/SECURITY.md`, and `docs/BACKLOG.md`:
  document the split-task design, evidence, rollback, and remaining limits.

## Verification state

Prior evidence for the root cause includes the isolated 75-second Task Scheduler fixture, which
reported `0x800710E0` during the overlap and returned to zero after natural completion. A separate
same-session `Parallel` fixture passed but was not selected due to the session-scoped mutex. The
original task XML backup is
`C:\Users\koros\AppData\Local\Personal_DC\backups\Personal_DC_V2_Tunnel-20261018-145757.xml`.
The intermediate `StopAtDurationEnd=true` backup at
`C:\Users\koros\AppData\Local\Personal_DC\backups\Personal_DC_V2_Tunnel-20261018-150406.xml`
must not be restored.

The focused functional suite passed 14 tests with no failures or skips on 2026-10-18. Command:
`Invoke-Pester -Script @('D:\Repo\Personal_DC\tests\AutostartMutex.Tests.ps1','D:\Repo\Personal_DC\tests\AutostartRecovery.Tests.ps1') -EnableExit`.
The host was PowerShell 7.6.7 / Pester 3.4.0; child worker was Windows PowerShell 5.1.26100.9711.
`tests/AutostartMutex.Tests.ps1` SHA-256 was
`0915301E840D58E0BD59519B36CC0AD34E4554D0AB640DE8C3038AC6B3BF06E3`. Functional tests mocked
ScheduledTasks and did not change the production task or services.

The isolated scheduler candidate source fingerprints were `recover-autostart.ps1`
`79766A02457E6B706A242DB8DE83658B5ED487E7EC9C6DCD6E5A1E67A58E6D7D` and `install-autostart.ps1`
`140CDAB55451787A4B3DBC64804A7F228D0C9A3C3E3FD81381D6B52173DFB697`. Fixture-only scenarios
passed for two no-op ticks, recovery after natural exit in 54.007 seconds, re-registration preserving
the running PID, and a corrected standalone overlap run: two recovery attempts produced one
acquired and one denied mutex attempt, then exactly one supervisor ran without `0x800710E0`. The
combined runner's overlap assertion sampled the task before releasing its own test barrier and
reported a harness-only failure; the focused corrected overlap runner passed with exit 0. The full
fixture and targeted overlap evidence, JSONL logs, and runner hashes are retained under
`D:\Temp\Personal_DC_recovery_global_mutex_e2e_8265d9d0fbbb43088216337ba26f6e06` and
`D:\Temp\Personal_DC_recovery_overlap_e2e_63d65b687be64590b4e374d4e302849d`. Fixture cleanup
confirmed no tasks, supervisor processes, or active marker files remained. Cross-session runtime
was `NOT_RUN`: only console session 1 was active. The full 24-hour repetition rollover and the
separate prior `RestartOnFailure` behavior remain unobserved/unexplained.

Before live application, the prior main task XML was backed up to
`C:\Users\koros\AppData\Local\Personal_DC\backups\Personal_DC_V2_Tunnel-20261018-161323.xml`
(3,992 bytes). `scripts/install-autostart.ps1` then registered the recovery task and updated the
main task without stopping the existing supervisor. Read-only post-install checks showed the main
task had no triggers, `IgnoreNew`, and PT0S execution limit; the recovery task had logon + daily
one-minute triggers, `Parallel`, and a 30-second execution limit. The existing supervisor PID 7724
remained active. Recovery minute runs at 16:14:34 and 16:15:35 +03:00 both returned 0. Personal DC
Showcase health returned `ok:true` before and after registration. The main task's
`LastTaskResult=0x800710E0` remains its pre-install historical result because its already-running
instance has not completed; no post-install main trigger exists to repeat that result. No
production failure was injected.

## Ownership

The operator is accountable for the delegated Personal DC restoration; Codex is the executor.
Functional and E2E agents own required focused test authoring/execution. No technical Windows task
service owner is identified in canonical project records.

## Review record

- `functional-test-reviewer` ran the 14-case focused suite described above; all passed with no skips.
- `e2e-runner` ran isolated Task Scheduler scenarios on the exact recovery-script source fingerprint.
  The combined run's overlap assertion was a timing false negative; its no-op, restart, and
  re-registration assertions passed, and the corrected standalone overlap scenario passed.
- Runtime model/effort metadata for the inherited functional/E2E agent launches was not exposed in
  their agent contexts; no model/effort value is inferred from the required role configuration.
- `code-reviewer` (GPT-6 Luna, medium effort) reviewed the final installer/recovery code and found no
  blocker, major, or minor code issue. The initial documentation-current-state inconsistency was
  corrected in this record, the recovery runbook, setup/security text, and BL-02.
- `reliability-reviewer` (GPT-6 Luna, medium effort) found the design internally consistent. It
  accepted cross-session execution, 24-hour rollover, and prior `RestartOnFailure` as documented
  residuals under the current acceptance; none is claimed as runtime-proven. It also recorded the
  existing minute-level INFO logging volume and interactive-user-context limitation.
- Final primary review was performed against the Personal DC-only diff before commit. No AEVE code,
  AEVE backlog entries, or AEVE change record are part of this change.
