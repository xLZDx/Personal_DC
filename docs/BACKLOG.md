# Personal DC follow-up backlog

## BL-01 — Bound diagnostic log storage

- **State:** Deferred, non-blocking MINOR reliability finding from the 2026-10-18 autostart recovery review.
- **Finding:** `logs/autostart.log` and the backend/tunnel redirected output files have no rotation or retention limit. Long-running or repeatedly failing sessions can grow them until disk space is constrained.
- **Evidence:** `scripts/start-autostart.ps1` appends structured supervisor events and redirects child output to persistent log files. Reliability review found no confirmed blocker or major defect; disk exhaustion behavior was not tested.
- **Recommended action:** Design bounded log rotation/retention that preserves useful incident evidence and does not truncate files still held open by child processes. Validate the policy in an isolated runtime before applying it to the live task.
- **Owner:** No technical service owner is recorded. The operator remains accountable for the delegated restoration request; Codex can implement the follow-up when scheduled.
- **Acceptance:** Maximum retained size/count are explicit; active child log handles are rotated safely; supervisor logging remains diagnosable after rotation; isolated checks cover restart and disk-bound behavior.
