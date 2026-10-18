# Personal DC v2.2 MCP autostart and tunnel recovery

## Change

The v2 scheduled task pointed to `D:\Temp\Personal_DC_v2_2_full_20261008\scripts_v2\hidden_launch.vbs`
and `start_v2_native_supervisor.ps1`; neither file existed in that snapshot. The task therefore
failed before the repository startup script could write its expected log. The current ChatGPT
Customer Showcase connector also targeted tunnel ID `tunnel_6ac8aa4940108191bf19192c12b1475c`,
while the local `personal-dc` profile targeted `tunnel_6ac6060b2e248191bfeb2c0c2b6c31bc`.

## Files and behavior

- `scripts/start-autostart.ps1` is now a long-running supervisor. It checks required paths and
  ports, validates MCP `initialize` plus the `health` tool, waits for tunnel `/healthz` and
  `/readyz`, monitors both processes and restarts on transient failures with capped exponential
  backoff. A per-session mutex prevents duplicate instances. Secret-safe JSON events explain
  preflight, readiness, failures and retries.
- The supervisor assigns only its backend and tunnel-client processes to a Windows Job Object with
  kill-on-close, so ending the supervisor closes its owned children. Process startup fails closed if
  assignment cannot be made.
- `scripts/install-autostart.ps1` now installs the supported `Personal_DC_V2_Tunnel` task with the
  repository path, interactive current-user identity, limited privilege and five one-minute Task
  Scheduler recovery attempts. The disabled legacy task remains unchanged.
- `scripts/status-autostart.ps1` reports task action/result, tunnel health/readiness and an actual
  MCP initialization/health call.
- `README.md` and `docs/AUTOSTART_RECOVERY.md` document the supported task, monitoring and rollback.

The live task was backed up to
`C:\Users\koros\AppData\Local\Personal_DC\backups\Personal_DC_V2_Tunnel-20261018-132934.xml`.
The previous local tunnel profile was backed up to
`C:\Users\koros\AppData\Local\Personal_DC\backups\personal-dc-20261018-133216.yaml`.
The local profile was updated to use the already registered ChatGPT connector ID and the existing
loopback MCP endpoint. No tunnel or credential was created or regenerated.

## Verification state

- PowerShell parser passed for the startup, installer and status scripts; `git diff --check` passed.
- The Job Object native definition compiled, and Windows created and closed a kill-on-close Job
  Object successfully. The running task subsequently launched both owned processes and passed the
  backend and tunnel readiness gates. An injected task-stop/child-termination regression was not
  run against the live workstation service.
- `scripts/status-autostart.ps1` reported the task running, tunnel health and readiness true, and
  MCP health true. `tunnel-client health --port 18080 --pid <live PID>
  --require-control-plane-poll --json` returned `result: ok`.
- The ChatGPT Personal DC Customer Showcase `health` call and read-only `list_projects` call both
  succeeded after updating the local profile.
- AEVE CLI profile inventory returned 57 entries. `reliability-reviewer`, `reliability-contract`,
  `verification-contract` and `observability-contract` were each available. No AI reviewer/agent was
  launched, as the incident scope expressly prohibited external AI reviewers and agents; therefore
  the AEVE source review remains `NOT_RUN`.
- Frozen benchmark HEAD is `0b4c56d8d0fa7410534b51da77d90999e983ebf6`; its worktree was clean. The
  SHA-256 of `src/aeve/operations/worker.py` is
  `D996B91FFBE7883C70D206D6C5715087C73B2E284F4FCD2C09EFB0E5B9CB6738`.
- Failure injection for backend/tunnel recovery, restart-after-reboot, port conflict and duplicate
  instance behavior remains `NOT_RUN`; no isolated failure-injection environment was created.
  ERP_MCP, Apache, VPN, 1C and the unrelated `cloudflared.exe` process were not stopped or changed.

## Rollback

Restore the scheduled task with:

```powershell
$xml = Get-Content -LiteralPath 'C:\Users\koros\AppData\Local\Personal_DC\backups\Personal_DC_V2_Tunnel-20261018-132934.xml' -Raw
Register-ScheduledTask -TaskName Personal_DC_V2_Tunnel -Xml $xml -Force
```

Restore the earlier tunnel profile with:

```powershell
Copy-Item -LiteralPath 'C:\Users\koros\AppData\Local\Personal_DC\backups\personal-dc-20261018-133216.yaml' -Destination (Join-Path $env:APPDATA 'tunnel-client\personal-dc.yaml') -Force
```

Restart the v2 scheduled task after restoring the profile. Inspect its action and the profile target
before starting if reverting both changes.
