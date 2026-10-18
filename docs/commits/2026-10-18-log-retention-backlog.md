# Record the log-retention follow-up

## Change

Added `docs/BACKLOG.md` item `BL-01` for bounded retention of supervisor, backend and tunnel logs.

## Why

The reliability review identified unbounded diagnostic log growth as a non-blocking MINOR risk.
Safe rotation requires an explicit retention policy and validation with child-process file handles;
silently truncating active logs would harm incident evidence.

## Verification state

Documentation-only backlog entry. No runtime code or log files changed, and no tests/checks were
run. The item records the evidence, recommended action, owner gap and acceptance criteria for a
future isolated implementation.

## Ownership

Operator is accountable for the delegated restoration request; Codex executed the backlog entry.
No technical service owner for log retention is established by canonical project records.
