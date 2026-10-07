# Personal DC

Private, policy-enforced MCP gateway for connecting approved AI clients to this Windows workstation.

## Current status

- Local MCP server: implemented
- Python MCP SDK: supported through `mcp>=1.29,<2`
- Transport: stdio, Streamable HTTP, SSE
- File access: allowlisted roots only
- Protected file/path filtering: enabled
- Git read operations: status, diff, log
- Git write operations: create branch, commit already-staged changes, normal push
- Test execution: predefined pytest / npm test
- Audit log: JSONL with secret-looking fields redacted
- Delete tool: intentionally not exposed
- OpenAI Secure MCP Tunnel client: installer and runner included

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

For local Streamable HTTP testing:

```powershell
.\scripts\start-http.ps1
# endpoint: http://127.0.0.1:8765/mcp
```

## Connect through OpenAI Secure MCP Tunnel

See `docs/CHATGPT_SETUP.md`.

## Security model

See `docs/SECURITY.md`.

## Repository

https://github.com/xLZDx/Personal_DC
