# Personal DC autostart recovery test evidence

## Change

Added `tests/AutostartRecovery.Tests.ps1` for the supervisor's pure readiness and safety probes.
The suite parses `scripts/start-autostart.ps1`, extracts only `Redact-Message`, `Test-PortFree`,
`Test-McpHealth` and `Test-TunnelReady`, and replaces network and port calls with deterministic
test doubles. It never runs the supervisor's infinite startup loop, reads the DPAPI store, binds a
production port, or changes a running service.

## Acceptance mapping and test result

| Incident criterion | Test coverage | Result |
| --- | --- | --- |
| MCP protocol readiness | Requires `initialize`, negotiated protocol version and successful `health`; rejects missing version and failed health | PASS |
| Tunnel readiness | Requires both `/healthz`=`live` and `/readyz`=`ready`; rejects a non-ready tunnel | PASS |
| Port conflict safety | Accepts a free port and refuses an occupied port | PASS |
| Secret-safe error logging | Redacts the configured runtime key and token-like fields | PASS |

Test owner command:

```powershell
Invoke-Pester -Script D:\Repo\Personal_DC\tests\AutostartRecovery.Tests.ps1 -EnableExit
```

Result: 4 passed, 0 failed, 0 skipped. Environment: Windows `10.0.26300.0`, PowerShell `7.6.7`,
Pester `3.4.0`, Python `3.14.3` at `C:\Python314\python.exe`. The first test-harness attempt
failed because its `Invoke-WebRequest` test double did not declare the `-UseBasicParsing` switch;
the test owner corrected the double and the recorded rerun passed. Product source and runtime state
were not changed by that correction.

The e2e-runner also completed six read-only runtime assertions against the current committed
Personal DC instance: scheduled-task action, tunnel liveness/readiness, Streamable HTTP MCP
initialize/health, ChatGPT Customer Showcase health, and read-only project listing. All six passed
at product commit `f62a3390079424bb17fa7062368602d7b8d74b86`; no process was stopped or restarted.

## Not run

Recovery after process failure, Windows restart, occupied live ports and duplicate supervisor
startup were not injected. They require an isolated runtime; interrupting the active workstation
instance is outside the authorized safe test scope. The AEVE source review remains separate and
`NOT_RUN` under the incident task's external reviewer/agent restriction.

## Scope

This commit adds test coverage and its evidence record only. It does not change runtime code,
scheduled-task registration, tunnel configuration, credentials, or ERP services.
