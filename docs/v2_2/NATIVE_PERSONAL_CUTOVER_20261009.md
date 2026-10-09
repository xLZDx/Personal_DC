# Personal DC v2 — native Windows personal profile (2026-10-09)

## Operator intent
No Docker for the personal mode. Real Windows file, Git, and test tools
are exposed through the existing separate v2 tunnel. Demo recordings
are replaced by actual Personal DC MCP operations.

## Implementation and verification
- Backend: `dc_v2.native_personal_mcp:main`.
- Listener: 127.0.0.1:18766, using independently stored v2 DPAPI local-hop
  secret injected by `start_v2_showcase.ps1`. The original v1 backend is
  127.0.0.1:18765.
- Remote control plane: existing tunnel ID
  `tunnel_6ac8aa4940108191bf19192c12b1475c`,
  profile `personal-dc-v2`, health 18081.
- Actual Windows tools: Personal DC v1's 16 FastMCP operations for bounded
  file reads/writes/replaces, Git, project list/status, and configured
  test runners. No Docker process is started by this service.
- Real MCP local E2E on 2026-10-09: session initialization, tool
  discovery, synthetic Windows file creation, read, replace and Git status
  PASS; generated synthetic file under
  `D:\Temp\Personal_DC_v2_2_isolated\native-smoke`.
- Focused Python test module: 3 passed (the legacy test suite can conflict
  with the active v1 port 18765, do not mistake that bind conflict for
  a native-v2 failure).
- Previous v2 tunnel /healthz and /readyz both `live`/`ready`.
- At-logon scheduled task `Personal_DC_V2_Tunnel` registered for current
  user, limited privileges; task action points to
  `scripts_v2\start_v2_showcase.ps1` which has been updated to start
  `dc_v2.native_personal_mcp` and call
  `scripts_v2\probe_native_personal.py`.
- V1 task `Personal_DC_Tunnel` DISABLED after v2 readiness checks.
  Running v1 process, files, keys, and tunnel were NOT removed or stopped.
- A real Windows logoff/reboot autostart verification remains NOT_RUN.

## Important acceptance boundary
This is a PERSONAL trusted-device profile, not a multi-tenant or
customer production execution gateway. It runs commands as the current
Windows user's process, subject to v1 Policy allowlisted roots and tools,
rather than through an independently secured OS account/VM. Existing
v1 policy roots include D:\Repo and D:\Temp; an authorized tool write can
change real project files. The v2 MCP backend requires its independent
local-hop secret, but ChatGPT tool invocations must also be reviewed
through app permissions. Do not give this plugin to external customers.

There is no generic PowerShell shell tool, persistent process management,
cross-process protected approval issuer, external audit anchor, or secure
software updater. G01–G13 are NOT globally passed. The existing 16 Windows
tools are useful for personal file/Git/test work, not Desktop Commander parity.

## Required ChatGPT action
The previously created v2 plugin cached six `demo_*` declarations.
After changing the backend, **refresh/rescan the plugin's MCP tools**
(or create a new plugin backed by the SAME v2 tunnel) and verify the
tool list now includes `health`, `read_text_file`,
`write_text_file`, `replace_text`, `project_git_status`,
and `run_project_tests`. The old demo tools should be absent.
Do NOT change No authentication to OAuth as a workaround; the tunnel and
private backend secret are already configured.

## Rollback
Enable scheduled task `Personal_DC_Tunnel` again and, if desired,
disable v2's task after explicit operator approval. Never delete old
v1 source or DPAPI keys during the transition. To avoid conflicts,
only one backend may bind 18766; verify the exact PID and image before
stopping any server. Keep Commander available until the v2 ChatGPT
plugin is confirmed with real tools.

## Status
Personal native MCP: LOCAL_E2E_PASS.
Remote ChatGPT native tool rediscovery: PENDING USER ACTION.
Automatic restart after Windows reboot: NOT_RUN.
Universal arbitrary CLI/power shell/long process: NOT_IMPLEMENTED.
Production security G01–G13: HOLD.
