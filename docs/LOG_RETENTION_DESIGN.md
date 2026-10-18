# Personal DC diagnostic log retention design

## Goal

Keep Personal DC diagnostics useful for seven days across supervisor events and backend and tunnel
output. This is BL-01 from `docs/BACKLOG.md`. The operator authorized one-week retention on
2026-10-18; the implementation uses UTC-dated log files and removes matching files whose last
write is older than seven days.

## Previous behavior and constraints

`scripts/start-autostart.ps1` appends JSONL events to `logs/autostart.log` and redirects stdout and
stderr for the backend and tunnel to four fixed files. `scripts/recover-autostart.ps1` also appends
to `autostart.log` once per recovery tick while the supervisor is active. The supervisor and
recovery task can therefore write to the shared event log from separate processes. The child
redirect handles remain open for the lifetime of each child process.

The live snapshot recorded on 2026-10-18 had `autostart.log` at 7,525 bytes, backend stdout at
89,663 bytes, backend stderr at 258,371 bytes, tunnel stdout at 145,659 bytes, and tunnel stderr at
0 bytes. These are point-in-time sizes, not retention guarantees. Repeated recovery events and
long-running child output can grow without bound.

The operator's task constraints require approval before deleting or overwriting files. The operator
authorized seven-day retention, including removal of expired Personal DC log files. The scripts
retain the existing base-name logs as eligible legacy files and remove them only after their last
write is older than seven days. Live activation still requires a controlled supervisor restart so
the child output handles use the new dated paths.

## Retention policy

1. **Keep the current logs indefinitely.** This preserves all evidence, but leaves retention
   unbounded and does not meet BL-01.
2. **Retain logs for seven days (selected).** Use one UTC-dated file per stream and remove matching
   Personal DC logs after their last write is more than seven days old. This gives a clear time
   window, but does not impose a byte cap within that week.
3. **Use the Windows event log.** This avoids application-managed file rotation, but depends on
   event-channel retention and host policy; the Task Scheduler Operational channel is currently
   disabled and its policy owner is not identified.

The selected policy satisfies the requested age limit. Log volume within the seven-day window is not
byte-bounded; adding a byte cap would be a separate policy choice and is outside the authorized
scope.

## Implementation contract

- Use one shared logging helper for both PowerShell scripts so the recovery task and supervisor
  use the same UTC-dated paths, UTF-8 behavior, secret-safe event data, and expiration rule.
- Serialize event-log append and expiration cleanup with a machine-wide mutex scoped to the
  current user's SID. Keep the critical section limited to one append/cleanup operation; handle an abandoned
  mutex as acquired and release it in `finally`.
- For child stdout/stderr, use UTC-dated files. The supervisor must stop only its owned backend and
  tunnel processes at the UTC day boundary, which closes their redirect handles before starting
  them against the new day's files. This creates a brief daily service restart.
- Expire all five Personal DC streams, including legacy base-name files, when their last write is
  older than seven days. Event appends and expiration cleanup use the SID-scoped logging mutex.
  Event logs are swept on event writes; inactive child logs are swept about once a minute by the
  supervisor, while its four active child-log filenames are excluded. On startup and after child
  processes stop, the supervisor can sweep all child streams because their handles are closed.
- A per-file expiration failure is returned as a diagnostic and logged as
  `log_expiration_cleanup_incomplete`; other eligible files are still processed and the next sweep
  retries the failure. A transient file lock must not stop healthy backend/tunnel children.
- If the logging mutex or event append fails, do not silently discard the error; surface it through
  the supervisor/recovery failure path. A per-file expiration failure is instead recorded as a
  warning and retried on the next minute sweep, without a tight retry loop.
- Existing base-name log files are matched by cleanup and remain until their last-write age exceeds
  seven days. No extra copy is created during rollout.

## Failure matrix

| Failure point | Resulting state | Recovery | Verification |
|---|---|---|---|
| Two processes append to the current dated event log concurrently | Both contend on the shared SID-scoped mutex | One writer performs the operation at a time; abandoned ownership is recovered | Parallel writer test checks valid JSONL and no interleaved records |
| UTC day boundary arrives while a child emits output | The current dated files remain open until owned children exit | Stop only owned children, close redirected handles, then start against the new UTC-dated files | Isolated child crosses the boundary; verify handles close and service restarts |
| Cleanup races with event appends | Supervisor and recovery process compete for log maintenance | Both use the same SID-scoped mutex; abandoned ownership is recovered | Parallel writer/cleanup test checks valid JSONL and retention |
| A child log passes the seven-day age threshold while the child is still running | Its file handle must remain valid; expired inactive files should not wait for the next UTC rollover | Sweep inactive child logs about once a minute, excluding the four currently open child-log filenames | Isolated fixture verifies old inactive files are removed while active filenames and unrelated files remain |
| An expired child log is temporarily locked or cannot be deleted | One stale file should not stop healthy Personal DC services or prevent other cleanup | Return a per-file diagnostic, emit a warning event, and retry at the next sweep | Isolated failure injection verifies a visible warning and no supervisor/child restart |
| Disk full or access denied | New record cannot be persisted | Return a visible failure through supervisor/recovery exit status; avoid a silent-success fallback | Isolated filesystem failure confirms nonzero/visible result and no secret leakage |
| A child emits unusually large output within the week | File size can grow even though its age is bounded | Expire the file after seven days; no byte limit is imposed by this policy | Document as a limitation; disk-volume cap is out of scope |
| System UTC clock jumps forward or backward | Age-based expiry may remove logs earlier or later than seven elapsed days | Keep the host clock synchronized; expiry follows the system's UTC file timestamps | Clock-jump behavior remains a documented operational limit |
| Daily rollover stops a child with application output still buffered | The forceful owned-process stop can lose user-space buffered tail bytes; no graceful drain contract currently exists | Stop only the owned child and verify it exited before expiring or reopening files; accept possible loss of the final buffered tail | Isolated rollover verifies child exit and file-handle release, not preservation of an application-buffered final marker |

## Rollout, rollback, and test plan

The implementation was applied to the live supervisor on 2026-10-18 after review. The task returned
to `Running`, MCP `initialize` succeeded, and the `health` tool returned `ok: true`; new UTC-dated
event and child-output files were created. The focused functional suite covers UTC path generation, seven-day expiration, unrelated-file
preservation, concurrent event writes, logger routing, and supervisor rollover ordering. An
isolated E2E fixture covers child handle closure/new-day paths, expiry after simulated age, unrelated
process isolation, and stop/logging failures. Disk-full and access-denied behavior and clock jumps
were not injected. Logging and cleanup errors propagate to the supervisor/recovery failure path.
The operator authorized the retention period; it is active on the live task.

Rollback is a code revert to the pre-retention revision. Logs expired after the retention policy is
activated cannot be recovered. Existing base-name logs remain readable until they are more than
seven days past their last write; no extra copy is created.

## Decision and ownership

- **Decision:** retain Personal DC diagnostic files for seven days based on last-write time.
- **Owner:** the operator authorized the period; Codex is the executor. No separate technical
  human owner is recorded for the Personal DC local service.
- **Next step:** monitor routine operation; no further rollout action is required. The first real
  seven-day expiration boundary has not elapsed yet.
