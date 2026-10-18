# E2E evidence: Personal DC retention sweep

## Scope and revision

This record adds isolated E2E evidence for the code commit `8d447e18cb4982897ed484602d354c9ec46ef217` (`Sweep expired Personal DC logs every minute`). Product source and the live Personal DC service were not changed during the run.

## Command and environment

```powershell
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File D:\Temp\PersonalDC_Retention_E2E_20261018\run-latest-steady-loop.ps1
```

Result: exit code 0, E2E PASS, PowerShell `5.1.26100.9711`, one isolated journey with three acceptance points. Source SHA-256 values were `2326361E346ACFDC7576E502240115DE64C51B97700869FD6B179F9C8860A87E` for `scripts/start-autostart.ps1` and `4080FEA11D0A862F0CA4078A89058DEF65F68D43C131BFBBBF063D3439516F93` for `scripts/PersonalDCLogRetention.ps1`.

## Results

1. The disposable fixture became ready at `2026-10-18T14:49:07.0949796Z`. Its first sweep ran at `2026-10-18T14:49:09.1101245Z`; expired inactive `backend.stdout-19990101.log` was removed.
2. The four active child-log paths remained present and open. The unrelated `customer-data.log` remained.
3. A held expired `tunnel.stderr-19990101.log` produced a visible `WARN log_expiration_cleanup_incomplete` event with operation `delete` and error type `System.IO.IOException`. After the harness released the lock, a later call to `Invoke-LogExpirationSweep` inside the same running supervisor removed the file. Supervisor PID `42792` and child PIDs `30864` and `11952` were unchanged through the retry.

## Fixture limits and artifacts

Only the disposable copies were modified to accelerate the scenario: the one-minute interval became two seconds, and the 15-second loop sleep became 100 milliseconds. The copied helper used an isolated fixture-only mutex. The later retry sweep was triggered by a fixture signal inside the still-running supervisor; this proved retry behavior without a restart, but did not measure a full production minute or independently prove that the production timer naturally reaches the later sweep. Functional source assertions cover the one-minute scheduling condition; no seven-day wait was performed.

The machine's live Personal DC process PID `24064` remained running and was not touched. All fixture processes exited during cleanup. The detailed result is preserved at `D:\Temp\PersonalDC_Retention_E2E_20261018\latest-9f861726b59e430b86ef80e8ed1e43ba\latest-sweep-result.json`; fixture root: `D:\Temp\PersonalDC_Retention_E2E_20261018\latest-9f861726b59e430b86ef80e8ed1e43ba`.

The required focused functional suite was separately run by `functional-test-reviewer`: 22 passed, 0 failed, exit code 0. `code-reviewer` and `reliability-reviewer` found no remaining blocking source defect; the reliability review confirmed per-file failures do not terminate healthy children. Their invocation model/effort metadata was not retained in the available review records.

## Delivery decision

Primary GPT review of the exact code/test diff at commit `8d447e18cb4982897ed484602d354c9ec46ef217`, together with the focused functional result and this E2E artifact, approves pushing that code. The code is unchanged from the reviewed commit. This evidence-only commit does not modify product behavior. Unrelated AEVE worktree edits remain excluded.
