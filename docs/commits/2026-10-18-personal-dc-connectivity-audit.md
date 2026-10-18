# Personal DC connectivity audit after recovery rollout

## Purpose and scope

This follow-up reconciles the original Personal DC recovery request with the live connection after
installing the recovery watchdog. AEVE CLI, AEVE review, and frozen benchmark validation are outside
scope per the operator's clarification. No ERP service, credential, external tunnel, or unrelated
process was changed.

## Earlier outage root cause

The prior Personal DC change record, [`2026-10-18-mcp-autostart-recovery.md`](2026-10-18-mcp-autostart-recovery.md),
records that the V2 scheduled task pointed to nonexistent files under
`D:\Temp\Personal_DC_v2_2_full_20261008\scripts_v2`; the task failed before the repository startup
script could log the failure. It also records a mismatch between the local `personal-dc` profile
tunnel ID and the existing ChatGPT Customer Showcase connector ID. The repository startup path and
profile/connector routing were restored without creating a tunnel or regenerating credentials.

The later repeated `0x800710E0` was a separate Task Scheduler overlap issue. The dedicated
[`2026-10-18-scheduler-overlap-refusal.md`](2026-10-18-scheduler-overlap-refusal.md) record documents
its isolated reproduction, watchdog correction, regression evidence, live application, and rollback.

## Current verification

Read-only command:

```powershell
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `
  D:\Repo\Personal_DC\scripts\status-autostart.ps1
```

Observed: DPAPI secret file exists; `Personal_DC_V2_Tunnel` is `Running`; backend `/mcp` initialize
and `health` succeeded; tunnel `/healthz` and `/readyz` both returned healthy. The main task's
`LastTaskResult=0x800710E0` is its historical pre-install value; the existing supervisor remains
running and no main-task triggers are registered. Recovery LastTaskResult was 0 on two consecutive
minute runs.

Tunnel client status command:

```powershell
D:\Repo\Personal_DC\vendor\tunnel-client\tunnel-client.exe health --port 18080 --pid 5460 `
  --require-control-plane-poll --json
```

Observed `result: ok`, PID 5460 running, `/healthz` and `/readyz` HTTP 200, and a successful
control-plane poll. Current process tree showed supervisor PID 7724 owning backend PID 10324 and
Personal DC `tunnel-client.exe` PID 5460. Ports 18765 and 18080 belonged to those processes.

Through the Personal DC Customer Showcase connection, ChatGPT invoked `health` (`ok:true`) and the
read-only `list_projects` tool (`Personal_DC` exists). These calls prove the configured Showcase
route is reachable for the authorized read-only operations used here.

## Port 21080 cloudflared finding

Read-only inspection on 2026-10-18 found cloudflared PID 34660 at
`D:\Repo\Personal_DC\vendor\tunnel-client\cloudflared.exe`, with safe command arguments
`tunnel --no-autoupdate --url http://127.0.0.1:21080`. Port 21080 belonged to PID 21468, whose
process tree ran `testbed.idp` from `ERP_MCP-supplier-debt-runtime`. The cloudflared process recorded
parent PID 10628, which was no longer present during inspection. No registered Scheduled Task
action or Windows service referenced cloudflared or port 21080. The supported Personal DC task uses
a separate `tunnel-client.exe` process and port 18080.

Conclusion: cloudflared PID 34660 is outside the supported Personal DC MCP route and targets an ERP
identity-provider origin. It may be a stale or separately launched integration, but its intended
owner and lifecycle manager are unknown. The process was not stopped or reconfigured. BL-05 tracks
the owner/dependency gap; no ERP process was touched.

## Limits and rollback

The 24-hour repetition rollover and execution from a second Windows session remain `NOT_RUN`. No
Task Scheduler Operational channel change was made. The recovery-task rollback instructions and
pre-install XML backup are documented in [`AUTOSTART_RECOVERY.md`](../AUTOSTART_RECOVERY.md); the
supervisor PID was preserved during installation.

## Ownership

The operator is accountable for the delegated Personal DC restoration; Codex performed the audit.
The service owner for the unrelated ERP IdP and the launcher/owner of cloudflared PID 34660 are not
identified in available canonical records. The operator is the next assignment path for confirming
that ownership before any process action.
