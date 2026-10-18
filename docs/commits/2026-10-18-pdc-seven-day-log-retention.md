# Personal DC seven-day log retention

## Request and decision

The operator requested one-week retention for Personal DC logs and explicitly authorized expiration of files older than that window. This change is limited to Personal DC; AEVE is unrelated and was not included. Retention is measured by each matching file's last-write time in UTC. The cutoff is strictly older than seven days. A byte-volume cap was not requested and is not part of this change.

## Changed paths

- `scripts/PersonalDCLogRetention.ps1`: shared UTC-dated path, JSONL event writer, SID-scoped append/cleanup mutex, and seven-day expiration helper.
- `scripts/start-autostart.ps1`: use dated child logs; clean expired child logs only after owned processes stop; restart owned backend and tunnel at UTC day rollover; refuse another start or cleanup if an owned process failed to stop; guarantee Job Object closure in nested `finally` blocks.
- `scripts/recover-autostart.ps1`: use the shared event writer and dated event-log path.
- `tests/PersonalDCLogRetention.Tests.ps1`, `tests/AutostartRecovery.Tests.ps1`, `tests/AutostartMutex.Tests.ps1`: focused retention, locking, expiry, failure-guard, and recovery coverage.
- `docs/LOG_RETENTION_DESIGN.md`, `docs/AUTOSTART_RECOVERY.md`, and the BL-01 section only in `docs/BACKLOG.md`: policy, operational contract, evidence, and limitations.

## Contract and limitations

Five Personal DC streams use UTC-day filenames: `autostart-YYYYMMDD.log`, `backend.stdout-YYYYMMDD.log`, `backend.stderr-YYYYMMDD.log`, `tunnel.stdout-YYYYMMDD.log`, and `tunnel.stderr-YYYYMMDD.log`. Matching legacy base-name logs are also eligible for expiry. Event append and cleanup use the same SID-scoped mutex, with a 10-second bounded wait; an abandoned mutex is treated as acquired and failures propagate.

The supervisor checks for a UTC date change every 15 seconds. At rollover it closes its redirected child handles by stopping only its owned backend and tunnel, then starts them with the new day's files. This is a brief daily restart and may lose application-buffered tail output. The policy bounds age, not bytes created within the seven-day window. System clock jumps can make age-based expiration early or late. A full seven-day wall-clock wait has not elapsed; synthetic-age tests exercised expiration.

## Verification evidence

- Functional owner: `functional-test-reviewer` (`/root/pdc_log_retention_functional`), GPT-6 Luna, medium effort. Command: `Invoke-Pester -Script @('D:\Repo\Personal_DC\tests\PersonalDCLogRetention.Tests.ps1','D:\Repo\Personal_DC\tests\AutostartRecovery.Tests.ps1','D:\Repo\Personal_DC\tests\AutostartMutex.Tests.ps1') -EnableExit`. PowerShell 7.6.7 / Pester 3.4.0: 20 passed, 0 failed, exit 0, 19.37 seconds. The test suite also launches Windows PowerShell 5.1 children for concurrent JSONL writers.
- E2E owner: `e2e-runner` (`/root/pdc_log_retention_e2e`), GPT-6 Luna, low effort. Isolated Windows PowerShell 5.1.26100.9711 fixture command: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File D:\Temp\PersonalDC_Retention_E2E_20261018\run-retention-e2e.ps1`. Result: PASS 4/4. It exercised UTC day rollover, owned-child stop and handle closure, expiry, unrelated-sentinel preservation, and stop/logging failure guards. Fixture artifacts were retained at `D:\Temp\PersonalDC_Retention_E2E_20261018\` under the no-delete constraint.
- Reliability owner: `reliability-reviewer` (`/root/pdc_log_retention_reliability`), GPT-6 Luna, medium effort: no BLOCKER or MAJOR findings; verified mutex scope, bounded wait, rollover ownership, cleanup ordering, and Job Object closure.
- Code owner: `code-reviewer` (`/root/pdc_log_retention_review`), GPT-6 Luna, low effort: reviewed process-stop error handling, Job Object cleanup, and PowerShell 5.1 UTC argument parsing; no unresolved BLOCKER or MAJOR finding. The final source-and-test implementation diff reviewed by the primary GPT has Git blob hash `0bff263983a24cb4028cb7d2cf7b15a8ce4380b1` (`git diff --cached --binary -- <six implementation/test paths> | git hash-object --stdin`). Primary GPT reviewed the exact staged implementation and test diff and found no issue that blocks the requested contract; review does not substitute for the recorded runtime evidence above.

## Live activation evidence

The corrected Personal DC supervisor was started through its scheduled task after the focused tests and isolated E2E. The task was Running; backend and tunnel reported ready; MCP `initialize` succeeded and `health` returned `ok: true`, Personal DC version `0.1.0`, with `deletion_tool_exposed: false`. The active daily files included `autostart-20261018.log`, `backend.stdout-20261018.log`, and `tunnel.stdout-20261018.log`. The complete seven-day elapsed period is not claimed as observed.

The first activation exposed a Windows PowerShell 5.1 argument-parsing defect: unparenthesized `[DateTime]::UtcNow` was bound as a string. All four child-log path calls now pass `([DateTime]::UtcNow)`. The failed supervisor attempt was stopped; no Personal DC backend or tunnel child had started during that attempt. A separate ERP tunnel process was left untouched. After correction, the supervisor and health check succeeded. A historical Task Scheduler `LastTaskResult` value was not used as a current health result; the Running state and MCP health response are the live evidence.

## Review and delivery

Primary GPT reviewed the exact staged implementation/test diff identified above and the staged Personal DC documentation/backlog scope before commit. The commit is restricted to the nine listed PDC paths plus this record; unrelated AEVE worktree changes remain uncommitted and unstaged. Tests are not rerun by the primary session; all test commands/results above belong to the designated test agents.