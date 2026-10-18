# Change record: bounded Personal DC log retention sweeps

## Summary

Follow-up to `Add seven-day Personal DC log retention` (commit `4c89809`) to ensure inactive child logs are removed soon after crossing the seven-day threshold, rather than waiting until the next daily log rollover. Cleanup now runs about once per minute while the supervisor is healthy, excludes its four currently open child-log files, and reports per-file deletion failures without stopping healthy child processes.

## Why

The original seven-day policy was enforced for child logs during supervisor startup and after a UTC-day rollover. Since the supervisor checks for rollover every 15 seconds but rollover happens only once daily, a stale inactive child log could remain nearly another day after it became eligible for deletion. A transient lock or access failure on one expired file could also interrupt the supervisor's cleanup path.

## Changed paths and contracts

- `scripts/start-autostart.ps1`: added a mutex-protected cleanup wrapper; sweep inactive child logs approximately once a minute; exclude the active backend/tunnel stdout and stderr filenames; log a warning for returned cleanup diagnostics; retain startup and post-stop full sweeps.
- `scripts/PersonalDCLogRetention.ps1`: return enumeration/deletion diagnostics; continue processing other eligible files after an individual delete failure; include event-log cleanup diagnostics in the next JSONL event record when available.
- `tests/PersonalDCLogRetention.Tests.ps1`: functional coverage for inactive versus active/unrelated files and per-file failure continuation, plus cadence/warning source assertions. Test ownership and execution: `functional-test-reviewer`.
- `docs/LOG_RETENTION_DESIGN.md`, `docs/AUTOSTART_RECOVERY.md`, `docs/BACKLOG.md`: document the cadence, active-file exclusions, warning/retry behavior, and isolated E2E acceptance.

The retention contract remains seven days by file last-write time, includes legacy base-name logs, and imposes no byte-volume cap. Active child files are not deleted while owned processes hold their redirected handles. A per-file failure emits `log_expiration_cleanup_incomplete` and is retried by the next sweep. Mutex and event-append failures remain visible through the existing failure path.

## Review and verification

- Primary GPT review: reviewed the exact staged implementation and functional-test blob set before this record was added. Implementation/test patch hash (`git hash-object` over the binary staged diff for the three code/test paths): `3fee55248654273d28a4a242b117078c44c4eb97`. No blocking defect identified. Approval covers a local commit; push remains gated on the isolated E2E acceptance below.
- `code-reviewer` re-review: no evidence-backed defect reported in the current implementation. Findings included active filename exclusions and per-file cleanup diagnostics/warning behavior.
- `reliability-reviewer` follow-up: the earlier concern that one locked expired file could disrupt healthy services was resolved; cleanup continues for other files and retries on the next minute sweep. A failure to persist the warning event remains visible as a logging failure.
- Reviewer model/effort metadata: the reports available at commit preparation identify the roles and findings but do not preserve their invocation metadata; no model/effort value is inferred here.
- Functional command, owned and run by `functional-test-reviewer`:

  ```powershell
  Invoke-Pester -Script @('D:\Repo\Personal_DC\tests\PersonalDCLogRetention.Tests.ps1','D:\Repo\Personal_DC\tests\AutostartRecovery.Tests.ps1','D:\Repo\Personal_DC\tests\AutostartMutex.Tests.ps1') -EnableExit
  ```

  Result: 22 passed, 0 failed, 0 skipped, 0 pending, 0 inconclusive; exit code 0; PowerShell 7.6.7 with Pester 3.4.0. These are functional results, not runtime proof of the real supervisor cadence.
- Current-source isolated E2E remains `NOT_RUN` for acceptance purposes. The latest-hash attempt reached readiness with two children and four open log handles but did not observe the one-minute sweep signal or expired-file removal before its 100-second stop ceiling. The shortened disposable-fixture attempt failed to reach readiness within 30 seconds and therefore did not exercise the sweep. No live Personal DC service was modified; both disposable runs were stopped and their artifacts preserved under `D:\Temp\PersonalDC_Retention_E2E_20261018\`. Earlier isolated retention and stop-log-failure E2Es passed, but they do not prove this newly added cadence and retry behavior.
- No full seven-day wait was performed. This change has not been deployed or activated in the running service. The previously pushed seven-day retention implementation remains at commit `4c89809`.

## Delivery state and remaining gate

This record accompanies the local follow-up commit. Do not push this follow-up until `e2e-runner` completes an isolated run against the exact committed source that reaches fixture readiness and proves: (1) an expired inactive child log is removed on the minute sweep, (2) all four active child-log filenames and unrelated files remain, and (3) a forced per-file deletion failure is visible and retried without restarting healthy children or the supervisor. Record exact source hash, command, result, and artifact path in the follow-up evidence record or commit record before push. The accountable task owner is the operator; Codex is the executor. `e2e-runner` owns the E2E work. A named technical service owner is not established in the inspected canonical records.

Unrelated AEVE worktree changes were intentionally excluded from this commit.
