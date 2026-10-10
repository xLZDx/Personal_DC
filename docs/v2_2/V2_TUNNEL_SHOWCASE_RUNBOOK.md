# Personal DC v1 + v2.2 — independent Secure MCP Tunnel runbook
Date: 2026-10-09. Target machine: authorized Razer Windows 11 Pro.
Status: LOCAL V2 SHOWCASE READY; TUNNEL V2 ID + RUNTIME KEY PENDING PLATFORM ACTION.
This is a PUBLIC-SYNTHETIC CUSTOMER SHOWCASE, not approval for the full
privileged production Developer Gateway.

## V1 (do not modify)
- Active checkout: D:\Repo\Personal_DC on main.
- MCP backend: http://127.0.0.1:18765/mcp.
- Tunnel profile: personal-dc (existing default profile directory).
- Tunnel health: http://127.0.0.1:18080/healthz and /readyz.
- Windows logon task: Personal_DC_Tunnel.
- Runtime key: current-user DPAPI %LOCALAPPDATA%\Personal_DC\secrets\runtime-key.dpapi.
- No branch switch, restart, tunnel/profile change, key reuse, or deleted data.

## V2.2 — independent customer showcase
- Source: D:\Temp\Personal_DC_v2_2_full_20261008, feature/developer-gateway-v2-2.
- MCP backend: http://127.0.0.1:18766/mcp; localhost only.
- Separate tunnel profile name: personal-dc-v2.
- Separate tunnel profile directory: %LOCALAPPDATA%\Personal_DC_V2\profiles.
- Separate tunnel health: http://127.0.0.1:18081/healthz and /readyz.
- Separate tunnel binary + companion: %LOCALAPPDATA%\Personal_DC_V2\bin.
- Separate current-user DPAPI backend secret:
  %LOCALAPPDATA%\Personal_DC_V2\secrets\backend-key.dpapi.
- Separate v2 OpenAI runtime API key (NOT YET STORED):
  %LOCALAPPDATA%\Personal_DC_V2\secrets\runtime-key.dpapi.
- The v2 script injects X-PDC-V2-Demo-Auth on the *local* HTTP hop only via
  tunnel-client --mcp.extra-headers and --mcp.discovery-extra-headers.
  The backend rejects requests missing/wrong the secret; it never publishes it.
- Six read-only tools: demo_health, demo_capabilities, demo_recorded_execution,
  demo_security_model, demo_architecture, demo_approval_example.
- All content is synthetic and records prior real Docker sandbox tests;
  the remotely exposed demo DOES NOT execute commands, read host files,
  access production data, approve operations, or run deployments.
- The real Docker executor remains in local development, pending G01–G13
  production isolation, authorization, approval, audit and promotion gates.

## 1 — Already prepared locally
1. A separate copy of tunnel-client v0.0.16 + cloudflared, matched by SHA-256.
2. New DPAPI local backend secret, not copied from V1.
3. Working v2 local MCP process on 127.0.0.1:18766.
4. Synthetic sanitized Docker evidence only, no host or company exports.
5. Tests: 12/12 real local SDK positive/negative requests + 23 unit security
   cases (check latest evidence before claiming an exact git HEAD).
6. Local status command:
   & 'D:\Temp\Personal_DC_v2_2_full_20261008\scripts_v2\status_v2_showcase.ps1'

## 2 — Owner action in OpenAI Platform
1. Log in to https://platform.openai.com/settings/organization/tunnels
2. Create a NEW tunnel named "Personal DC v2.2 — Customer Showcase".
   Do not change the tunnel ID used by V1. Associate the tunnel with the
   correct Platform organization and target ChatGPT workspace.
3. Copy the NEW tunnel_id (tunnel_ followed by 32 lowercase hex chars).
   Tunnel creation/manage permissions: Tunnels Read + Manage.
4. Create a DIFFERENT runtime API key at
   https://platform.openai.com/settings/organization/api-keys
   with Tunnels Read + Use permission. Do not create/use an admin key for
   the persistent tunnel client. Do not paste this runtime key into chat.
5. On Razer, use a local PowerShell console under the same Windows user
   running the v2 demo. The backend key and runtime key use current-user DPAPI.

## 3 — Finish local profile and store runtime secret
From PowerShell on Razer:

    Set-Location 'D:\Temp\Personal_DC_v2_2_full_20261008'
    .\scripts_v2\configure_v2_tunnel.ps1 -TunnelId 'tunnel_REPLACE_WITH_REAL_V2_ID'
    .\scripts_v2\save_v2_runtime_key.ps1

The second command prompts for the key invisibly. It refuses to overwrite an
existing v2 DPAPI key. No plaintext key is stored in source or logs.
A separate v2 profile is created by tunnel-client init with the official
sample_mcp_remote_no_auth (matching V1's MCP-level No authentication),
but v2 ALSO requires the local-hop static secret.

## 4 — Doctor and run the independent v2 tunnel
The v2 backend can remain on 18766 during setup. Then:

    .\scripts_v2\start_v2_showcase.ps1 -DoctorOnly
    .\scripts_v2\start_v2_showcase.ps1

The start script reads ONLY v2 key blobs, injects the secret header to the
private backend, and runs ONLY profile personal-dc-v2 with health 18081.
It does not stop V1 or change V1 profiles.
Check health:

    Invoke-WebRequest -UseBasicParsing http://127.0.0.1:18081/healthz
    Invoke-WebRequest -UseBasicParsing http://127.0.0.1:18081/readyz
    .\scripts_v2\status_v2_showcase.ps1

Expected health strings: live and ready. If health is up but ready is not,
check control-plane permissions, the tunnel ID, workspace association, and
MCP probe response. Do not disable backend auth as a workaround.
The Platform tunnel can require a short propagation interval after creation.

## 5 — Connect in ChatGPT (separate plugin)
1. Open ChatGPT Plugins -> + -> Add custom MCP server.
2. Name: Personal DC v2.2 — Customer Showcase.
3. Connection: Tunnel, choose the NEW V2 tunnel or paste its tunnel_id.
4. MCP authentication: No authentication (for this synthetic-only profile).
   The tunnel runtime itself is authenticated separately, and the local
   backend requires the locally injected static header.
5. Review the six tools and confirm that there are NO file-writing,
   shell, arbitrary task.start, upload or deployment tools.
6. Start a chat with @Personal DC v2.2 — Customer Showcase and ask:
   "Show the capabilities and the recorded Python, Node, npm and Git
   execution evidence. Which production gates remain open?"
7. Verify v1 still answers independently from its original ChatGPT app.
8. To demonstrate to a customer, use an explicitly authorized workspace
   association or screen sharing. Secure MCP Tunnel is private testing;
   it is NOT itself public marketplace distribution.

## 6 — Rollback / cancellation
- Disconnect only the new v2 ChatGPT app / stop the separate v2 tunnel
  console if a problem occurs.
- Leave V1 app, task, profile, DPAPI key, port and tunnel intact.
- Do NOT merge feature branch into main or copy v2 runtime files over V1.
- No automatic autostart was installed for V2. A persistent scheduled task
  requires separate owner review and trusted local installation.
- Never delete older v1 credentials or profiles as part of v2 demo setup.

## Honest limitations
The v2 demo is deliberately read-only with fixed recorded synthetic results.
The actual v2 isolated Docker executor can run commands locally but is not
safely exposed to a model until the protected broker, issuance/confirmation
mechanism, external audit, identity/tunnel and system acceptance are complete.
Using the same v1 No-auth sample for arbitrary RCE would bypass those gates.
For a real production client rollout, build an authenticated per-user MCP
gateway and a separately approved execution service.

References:
- https://developers.openai.com/api/docs/guides/secure-mcp-tunnels
- https://developers.openai.com/api/docs/guides/custom-mcp-server
- https://github.com/openai/tunnel-client/blob/master/docs/configuration.md
