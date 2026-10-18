# Windows autostart recovery

## Managed components

`Personal_DC_V2_Tunnel` is the supported logon task. Its action must run
`scripts/start-autostart.ps1` from this checkout as the interactive Windows user that owns the
DPAPI runtime key. The disabled `Personal_DC_Tunnel` legacy task is separate and is not modified by
the v2 installer.

The PowerShell supervisor owns normal backend and tunnel recovery. It holds a per-session mutex,
checks the Streamable HTTP `initialize` and `health` tool exchange on `127.0.0.1:18765/mcp`, checks
the tunnel client's `/healthz` and `/readyz` endpoints on `127.0.0.1:18080`, and restarts only the
two processes it launched. Retry delay grows exponentially and is capped at five minutes. Task
Scheduler retries a crashed supervisor five times at one-minute intervals. These two paths cover
different failures: normal child-service failures are handled in the supervisor; a supervisor
process failure is handled by Task Scheduler.

Structured, secret-safe startup events are appended to `logs/autostart.log`. Backend and tunnel
standard output/error remain in their dedicated log files. The DPAPI key remains in the existing
per-user store and is not emitted to logs.

## Install or repair the task

Run from an elevated PowerShell session only if the current account has permission to register the
task:

```powershell
Set-Location D:\Repo\Personal_DC
.\scripts\install-autostart.ps1
.\scripts\status-autostart.ps1
```

The installer configures the current user, logon trigger, five bounded scheduler recovery attempts,
and the repository's absolute start-script path. It does not create a tunnel, replace the profile,
or regenerate credentials.

## Roll back a task registration

Before changing the live task, export its exact XML to
`%LOCALAPPDATA%\Personal_DC\backups\Personal_DC_V2_Tunnel-<timestamp>.xml`. To restore that saved
registration:

```powershell
$backup = 'C:\Users\<user>\AppData\Local\Personal_DC\backups\Personal_DC_V2_Tunnel-<timestamp>.xml'
$xml = Get-Content -LiteralPath $backup -Raw
Register-ScheduledTask -TaskName Personal_DC_V2_Tunnel -Xml $xml -Force
```

This restores the task definition, not the service runtime state. Start/stop the task separately
after inspecting the restored action and principal.

## Roll back the tunnel profile

Before changing the profile, save
`%LOCALAPPDATA%\Personal_DC\backups\personal-dc-<timestamp>.yaml`. To restore that exact profile,
copy the selected backup over `%APPDATA%\tunnel-client\personal-dc.yaml`, then restart
`Personal_DC_V2_Tunnel` so the client reloads it. Verify the tunnel ID and MCP target before starting.

## Troubleshooting

Check `logs/autostart.log` for `supervisor_fatal`, `supervised_runtime_failure`,
`backend_ready`, `tunnel_ready`, and `restart_backoff` events. Do not treat a listening TCP port as
proof of a working MCP service; the supervisor requires a protocol initialization and `health` tool
response. Do not stop a process solely because it uses port `21080`; that port is outside Personal
DC's configured backend and tunnel health ports.

## Isolated supervisor recovery evidence

On 2026-10-18, an E2E owner exercised a disposable copy of the supervisor on loopback ports
`14941` and `14942`, with synthetic MCP backend/tunnel processes and a synthetic DPAPI key. The run
passed startup/health, backend failure/restart, fake-tunnel failure/restart, and Job Object cleanup
(4/4 scenarios). It did not invoke the real tunnel client, use real credentials, contact cloud
services, register a scheduled task, or modify this checkout. The supervisor copy used nine
explicit substitutions; this evidence covers orchestration and process ownership with fakes, not
the real backend/tunnel binaries or Windows Task Scheduler crash-retry behavior.

The complete disposable run and result remain under:
`D:\Temp\Personal_DC_recovery_E2E_retry_3e33a8d1cd00429b831b6c32a1678b83`.

```powershell
& (Join-Path $PSHOME 'pwsh.exe') -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File 'D:\Temp\Personal_DC_recovery_E2E_retry_3e33a8d1cd00429b831b6c32a1678b83\run_recovery_e2e.ps1'
```

Task Scheduler crash-retry behavior remains `NOT_RUN`. A read-only environment inventory found
`WindowsSandbox.exe` unavailable and WSL containing only the running `docker-desktop` distribution,
not a Windows guest. `Get-VM` could not enumerate Hyper-V because the current non-elevated account
is not authorized. Do not inject failures into the production task. To unblock this final scenario,
an administrator of host `RAZER` must either grant the operator the required Hyper-V inventory
permission or perform a read-only VM/checkpoint inventory from an authorized session. Only an
existing disposable Windows guest should be used for the scheduler test.

A read-only query of the live task confirmed `State=Running`, `RestartCount=5`,
`RestartInterval=PT1M`, `MultipleInstances=IgnoreNew`, and `ExecutionTimeLimit=PT0S`. Its
`LastTaskResult=267009` is the scheduler's currently-running marker. These settings confirm the
configured retry policy, not that Scheduler actually restarted the task after a controlled crash.
