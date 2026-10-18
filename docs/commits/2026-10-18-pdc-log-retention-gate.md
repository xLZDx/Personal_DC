# Document Personal DC log-retention approval gate

## Change and reason

Recorded the unbounded diagnostic-log finding as a concrete operator decision gate. The existing
recovery task and supervisor both append to the same event log, while child stdout/stderr handles
stay open for the lifetime of their processes. Meeting BL-01's bounded-retention acceptance means
overwriting expired logs, which the task's deletion constraint reserves for explicit operator
authorization.

## Changed paths

- `docs/LOG_RETENTION_DESIGN.md`: current behavior, alternatives, proposed cap, ownership, failure
  matrix, isolated verification plan, and rollback limits.
- `docs/AUTOSTART_RECOVERY.md`: links the design and states that logs remain unbounded until
  authorization.
- `docs/BACKLOG.md`: changes BL-01 to `Design documented; implementation blocked pending explicit
  operator authorization to overwrite expired diagnostic logs` and records the recommended path.

No source, live log, scheduled task, credential, AEVE path, ERP process, or runtime configuration
was changed. No log was rotated, truncated, deleted, or archived.

## Decision requested

Recommended: authorize the proposed rolling bound of 4 MiB per file with four archived generations
for each of five streams (100 MiB total), or name another explicit cap. Rotation replaces the oldest
history, improving the disk bound while reducing how far back local incident review can look.

Alternative: keep unbounded logs. This preserves all historical files but leaves disk use without a
maximum and leaves BL-01 open.

## Verification state

This is documentation-only. No tests or runtime changes were performed. The current live file sizes
and exact failure behavior are in `docs/LOG_RETENTION_DESIGN.md`; implementation and isolated tests
remain pending the operator's deletion/overwrite decision.
