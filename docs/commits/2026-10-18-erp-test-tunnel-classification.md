# Classify the ERP test IdP quick tunnel

## Scope

This documentation-only follow-up resolves the port 21080 process question from the Personal DC
outage audit. It does not change code, scheduled tasks, credentials, ERP services, the Personal DC
service, or the running tunnel processes. AEVE is out of scope.

## Finding

The `cloudflared.exe` process previously suspected to be a stale Personal DC tunnel is an intentional
part of the separate ERP_MCP real-1C test lane. Its command targets the ERP test IdP on port 21080.
The lane launcher is explicitly configured to start that quick tunnel and to reuse an already
running tunnel pointed at the same local origin. The launcher process exits after starting detached
components, so its child process remains while the scheduled lane task is `Ready`.

## Evidence

- Process `cloudflared.exe` PID 34660 runs from
  `D:\Repo\Personal_DC\vendor\tunnel-client\cloudflared.exe` with command
  `tunnel --no-autoupdate --url http://127.0.0.1:21080`.
- Port 21080 was owned by PID 21468 in the process tree running `testbed.idp` from
  `ERP_MCP-supplier-debt-runtime`.
- `D:\ERP_MCP_Testbed\real1c_e2e\autostart\start_lane.ps1` identifies itself as the idempotent
  ERP real-1C lane logon starter/watchdog. Its documented startup order includes a Cloudflare quick
  tunnel for the test IdP. Lines 120-129 detect an existing process targeting port 21080 and start
  the exact command above only when absent.
- Registered Scheduled Task `ERP_MCP_Lane_Autostart` is described as starting/watching the ERP lane.
  Its `wscript.exe` action invokes `C:\Users\koros\AppData\Local\HiddenLaunch\hidden_launch.vbs`
  with the lane's `start_lane.ps1` path. At inspection it was `Ready`, `LastTaskResult=0`; its
  children remained running after the launcher process exited.
- The Personal DC supervisor uses a separate `tunnel-client.exe` PID 5460 and port 18080; both
  tunnel control-plane poll and `/mcp` health passed.

No process or task was stopped, restarted, or reconfigured.

## Record updates

`docs/AUTOSTART_RECOVERY.md` now distinguishes the ERP test IdP tunnel from the supported Personal
DC tunnel. `docs/BACKLOG.md` closes BL-05 as classified. The full read-only audit is in
[`2026-10-18-personal-dc-connectivity-audit.md`](2026-10-18-personal-dc-connectivity-audit.md).

## Ownership

The technical/system owner is the registered `ERP_MCP_Lane_Autostart` task and its
`start_lane.ps1` launcher. Available records do not name a separate human owner. No human action is
needed for this classification because the ERP tunnel is intentional and outside Personal DC
scope.
