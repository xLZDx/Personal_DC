# Personal DC diagnostic log retention design

## Goal

Keep Personal DC diagnostics useful while bounding disk use across supervisor events and backend
and tunnel output. This is BL-01 from `docs/BACKLOG.md`; no logging behavior or live task is changed
by this design note.

## Current behavior and constraints

`scripts/start-autostart.ps1` appends JSONL events to `logs/autostart.log` and redirects stdout and
stderr for the backend and tunnel to four fixed files. `scripts/recover-autostart.ps1` also appends
to `autostart.log` once per recovery tick while the supervisor is active. The supervisor and
recovery task can therefore write to the shared event log from separate processes. The child
redirect handles remain open for the lifetime of each child process.

The current live snapshot on 2026-10-18 had `autostart.log` at 7,525 bytes, backend stdout at
89,663 bytes, backend stderr at 258,371 bytes, tunnel stdout at 145,659 bytes, and tunnel stderr at
0 bytes. These are point-in-time sizes, not retention guarantees. Repeated recovery events and
long-running child output can grow without bound.

The operator's task constraints prohibit deleting or overwriting files without explicit operator
approval. A rolling retention policy would irreversibly replace old diagnostics, so implementation
and live activation are gated on that approval. No current log file has been rotated, truncated, or
removed.

## Options and recommendation

1. **Keep the current logs indefinitely.** This preserves all evidence, but leaves disk growth
   unbounded and does not meet BL-01.
2. **Use a bounded rolling set per stream (recommended).** Cap each of the five streams at 4 MiB
   per file with four retained generations, for a 20 MiB per-stream limit and a 100 MiB combined
   maximum. This preserves recent diagnostics and makes the storage bound explicit, while older
   logs are overwritten.
3. **Use the Windows event log.** This avoids application-managed file rotation, but depends on
   event-channel retention and host policy; the Task Scheduler Operational channel is currently
   disabled and its policy owner is not identified.

Option 2 best matches the bounded-storage acceptance. The 4 MiB × five generations setting is a
proposal based on the observed current files; the operator may select a different cap before any
implementation. Do not enable rotation until overwrite of expired logs is explicitly authorized.

## Design if authorized

- Use one shared logging helper for both PowerShell scripts so the recovery task and supervisor
  use the same paths, UTF-8 behavior, redaction, size limits, and rotation rules.
- Serialize event-log append and rotation with a machine-wide mutex scoped to the current user's
  SID. Keep the critical section limited to one append/rotation operation; handle an abandoned
  mutex as acquired and release it in `finally`.
- For child stdout/stderr, replace direct redirection to long-lived files with a bounded stream
  writer owned by the supervisor. It must continue draining both pipes while rotating, preserve
  complete lines where possible, cap a single oversized line with an explicit truncation marker,
  and close both readers/writers during child shutdown.
- Keep the active file plus four numbered generations for each stream. Rotate oldest to newest
  while holding the logging mutex. Files outside the retained set are overwritten only under the
  approved policy.
- If the logging lock, write, or rotation fails, do not silently discard the error. Surface it on
  the supervisor/recovery exit path so Task Scheduler state/result remains observable. Do not
  retry indefinitely when disk or filesystem errors persist.
- Before enabling the policy, preserve the current logs as a one-time legacy snapshot. This keeps
  the pre-change evidence while bounding future files; the snapshot's retention also requires the
  same operator decision before it is ever removed.

## Failure matrix

| Failure point | Resulting state | Recovery | Verification |
|---|---|---|---|
| Two processes append `autostart.log` concurrently | Both contend on the shared SID-scoped mutex | One writer performs the operation at a time; abandoned ownership is recovered | Parallel writer test checks valid JSONL and no interleaved records |
| Rotation begins while a child emits output | Writer remains the owner of the pipe and file handles | Rotate between complete writes while continuing to drain the pipes | Isolated child emits across multiple caps; verify no pipe deadlock and retained size/count |
| Process crashes during archive rotation | At least the active/newest files may be incomplete | On next write, inspect archive names/sizes under the mutex and continue with the newest valid generation | Kill fixture writer at each rotation step and restart it |
| Disk full or access denied | New record cannot be persisted | Return a visible failure through supervisor/recovery exit status; avoid a silent-success fallback | Isolated filesystem failure confirms nonzero/visible result and no secret leakage |
| One child emits an oversized line | A single record exceeds ordinary size assumptions | Cap that line with a clear truncation marker while continuing to drain output | Fixture emits an oversized record; verify marker and bounded file |
| Shutdown occurs while output is buffered | Final bytes may be lost if readers are not drained | Stop owned child, drain both streams to EOF, flush and close before releasing the writer | Controlled child exit verifies final marker is retained |

## Rollout, rollback, and test plan

After authorization, implement the shared writer and tests first. Run the functional suite and an
isolated E2E fixture for concurrent writers, size/count caps, crash-window rotation, active child
output, oversized records, disk-full/access-denied behavior, restart, and secret redaction. Do not
rotate production logs or restart the live task until the implementation is reviewed and the
operator authorizes applying it.

Rollback is a code revert to the pre-retention revision. The one-time legacy snapshot preserves
the logs that existed before the first rotation. Rollback cannot recover generations overwritten
after the retention policy is activated.

## Open decision and ownership

- **Decision required:** authorize bounded replacement of old Personal DC diagnostics, with the
  proposed 4 MiB × five generations per stream, or specify another bound.
- **Recommended choice:** approve the proposed 100 MiB combined cap. It retains four archived
  generations per stream and bounds all five streams while keeping the design explicit.
- **Owner:** the operator owns the deletion/overwrite decision. Codex is the executor. No separate
  technical human owner is recorded for the Personal DC local service.
- **Next step:** after the operator approves a retention bound, implement the helper and mapped
  tests; until then, keep current logs untouched.
