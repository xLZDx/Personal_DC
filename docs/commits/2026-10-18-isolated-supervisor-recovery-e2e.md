# Record isolated supervisor recovery evidence

## Change

Added the isolated supervisor recovery result and its exact command to
`docs/AUTOSTART_RECOVERY.md`.

## Verification

The E2E owner ran from `D:\Repo\Personal_DC` on Windows 11 Pro build `26300`, PowerShell `7.6.7`,
Python `3.14.3`, source HEAD `ebd83845a65d50ecd4c70162596f1b6f09181c26`:

```powershell
& (Join-Path $PSHOME 'pwsh.exe') -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File 'D:\Temp\Personal_DC_recovery_E2E_retry_3e33a8d1cd00429b831b6c32a1678b83\run_recovery_e2e.ps1'
```

Result: 4/4 scenarios PASS using a disposable supervisor copy, synthetic backend/tunnel processes,
synthetic DPAPI key, and free loopback ports `14941`/`14942`. Scenarios: healthy startup, recovery
after fake backend termination, recovery after fake tunnel termination, and Job Object child cleanup.
The fake processes were confirmed exited. Full `result.json`, harness and logs remain under the
unique `D:\Temp\Personal_DC_recovery_E2E_retry_3e33a8d1cd00429b831b6c32a1678b83` directory; no
temporary artifacts were removed.

An earlier isolated attempt was red because its PID-count predicate could misidentify a process from
the prior generation as a new launch. The E2E owner corrected the predicate, used a separate temp
directory for the final run, and the corrected result passed. Production source and runtime were
not modified. This fake-service run does not verify the real tunnel client, real backend binary, or
Task Scheduler's crash-retry behavior.

## Ownership

Operator is accountable for the delegated Personal DC restoration; the E2E-runner role owns the
test evidence; Codex recorded it. No named human E2E service owner is established in project
records.
