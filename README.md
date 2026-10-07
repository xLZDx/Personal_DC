# Personal DC

Private, policy-enforced MCP gateway for connecting approved AI clients to this Windows workstation.

## Current status

- Local MCP server: implemented
- Python MCP SDK: supported through `mcp>=1.29,<2`
- Transport: stateless Streamable HTTP for persistent tunnel operation; stdio/SSE remain available for local development
- File access: allowlisted roots only
- Protected file/path filtering: enabled
- Git read operations: status, diff, log
- Git write operations: create branch, commit already-staged changes, normal push
- Test execution: predefined pytest / npm test
- Audit log: JSONL with secret-looking fields redacted
- Delete tool: intentionally not exposed
- OpenAI Secure MCP Tunnel client: installer and runner included
- Windows DPAPI runtime-key storage: supported
- Windows Task Scheduler autostart: supported

## Default allowed roots

- `D:\Repo`
- `D:\Downloads\gemeni videos`
- `D:\Temp`

Edit `config/policy.json` to change them.

## Configured project aliases

- `Personal_DC`
- `ERP_MCP`
- `PDCC`
- `AI_Trading`
- `Fitness_App`
- `PM_Bridge`

Edit `config/projects.json` to add or remove aliases.

## Run locally

```powershell
cd D:\Repo\Personal_DC
python -m personal_dc.doctor
python -m pytest -q
.\scripts\start-stdio.ps1
```

For local stateless Streamable HTTP testing:

```powershell
.\scripts\start-http.ps1
# endpoint: http://127.0.0.1:18765/mcp
```

Persistent OpenAI Secure MCP Tunnel operation uses this loopback HTTP endpoint behind the tunnel, which avoids stale stdio initialization state after Windows or tunnel restarts.

## Connect through OpenAI Secure MCP Tunnel

See `docs/CHATGPT_SETUP.md`.

## Persistent secure tunnel on Windows

After the tunnel profile is configured, store the runtime key with Windows DPAPI and install logon autostart:

```powershell
.\scripts\save-runtime-key.ps1
.\scripts\install-autostart.ps1
.\scripts\status-autostart.ps1
```

The encrypted key is stored outside the repository under `%LOCALAPPDATA%\Personal_DC\secrets` and is decryptable only by the current Windows user. The scheduled task `Personal_DC_Tunnel` starts the tunnel automatically at logon and is configured to restart on failure.

## Security model

See `docs/SECURITY.md`.

## Repository

https://github.com/xLZDx/Personal_DC
