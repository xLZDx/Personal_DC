# Clarify Personal DC recovery test helper loading

## Change

Corrected one comment in `tests/AutostartRecovery.Tests.ps1`: the test extracts `Write-Event` as
well as probe and redaction helpers. The updated comment now accurately states that helpers are
loaded without executing the supervisor startup loop.

## Review and verification

- Functional test reviewer owned and changed only `tests/AutostartRecovery.Tests.ps1`.
- The final focused suite command was:

  ```powershell
  Invoke-Pester -Script @('D:\Repo\Personal_DC\tests\AutostartRecovery.Tests.ps1','D:\Repo\Personal_DC\tests\AutostartMutex.Tests.ps1') -EnableExit
  ```

- Result: 16 passed, 0 failed, 0 skipped in 12.18 seconds.
- Runtime: PowerShell 7.6.7 / Pester 3.4.0.
- Final test-file SHA-256:
  `F98D1FDFC1CCCECDEB7330D641E681F2DF987239F1DABD5AC6017A15D56A5326`.
- `tests/AutostartMutex.Tests.ps1` SHA-256 remains
  `0915301E840D58E0BD59519B36CC0AD34E4554D0AB640DE8C3038AC6B3BF06E3`.
- Production scripts and runtime tasks were not changed. No AEVE or unrelated worktree paths were
  staged or modified.

The repository HEAD when the reviewer captured the verification evidence was
`b38199ccb48c9d284d96fa912cbb8043ac03ded5`; this follow-up changes only the test comment and its
evidence record.
