# ChatGPT / OpenAI setup

Personal DC is intentionally private. The MCP server binds locally and is designed to be reached through OpenAI Secure MCP Tunnel rather than an inbound public port.

## 1. Install the tunnel client

```powershell
cd D:\Repo\Personal_DC
.\scripts\install-tunnel-client.ps1
```

The installer resolves the current official `openai/tunnel-client` GitHub release and installs it only under:

```text
D:\Repo\Personal_DC\vendor\tunnel-client
```

## 2. Create an OpenAI tunnel

In OpenAI Platform, create or inspect a tunnel and obtain its `tunnel_id`.

You also need a runtime API key whose principal has Tunnels Read + Use permission.

Do not commit either credential to this repository.

## 3. First-time runtime key use

For the first tunnel configuration, put the runtime key in the current PowerShell process:

```powershell
$env:CONTROL_PLANE_API_KEY = "paste-runtime-key-here"
```

Do not place the key in the repository or in a plaintext `.env` file.

## 4. Configure the local tunnel profile

Replace the example id:

```powershell
.\scripts\configure-tunnel.ps1 -TunnelId "tunnel_0123456789abcdef0123456789abcdef"
```

The script configures the tunnel to start:

```text
python D:\Repo\Personal_DC\run_server.py
```

and runs `tunnel-client doctor --explain`.

## 5. Start the tunnel

```powershell
.\scripts\start-tunnel.ps1
```

Keep it running while ChatGPT or another supported OpenAI product uses Personal DC.

## 6. Add it to ChatGPT

In ChatGPT on the web:

1. Open Plugins / custom MCP server creation.
2. Add a custom MCP server.
3. Choose **Tunnel** as the connection.
4. Select the tunnel you created, or enter its `tunnel_id`.
5. Choose **No authentication** for the MCP server itself; Secure MCP Tunnel authenticates the tunnel runtime separately.
6. Scan/review the available tools.
7. Create/install the plugin/app for the allowed workspace/account.
8. In a chat, select or @mention Personal DC when a message needs local-machine access.

Availability of read/write actions depends on the ChatGPT plan/workspace and current OpenAI rollout.

## 7. Store the runtime key securely and enable Windows autostart

After the tunnel works interactively:

```powershell
.\scripts\save-runtime-key.ps1
.\scripts\install-autostart.ps1
.\scripts\status-autostart.ps1
```

`save-runtime-key.ps1` encrypts the key with Windows DPAPI using the current-user scope and writes only the encrypted blob under:

```text
%LOCALAPPDATA%\Personal_DC\secrets\runtime-key.dpapi
```

The scheduled task `Personal_DC_V2_Tunnel` runs with limited privileges and supervises the stateless MCP backend on `127.0.0.1:18765` together with the existing `personal-dc` tunnel profile on health port `127.0.0.1:18080`. The disabled legacy task `Personal_DC_Tunnel` is not used. A separate recovery task starts the supervisor at user logon and every minute while it is absent. The supervisor task has no triggers and uses `IgnoreNew`; the recovery task allows overlapping short actions but serializes them with a machine-wide mutex before starting the supervisor. This avoids sending simultaneous logon and minute starts to the long-running task. The supervisor validates MCP protocol readiness, monitors both services, and retries transient child-service failures. The previous task registration's five Task Scheduler `RestartOnFailure` attempts did not occur in the isolated natural-failure test and are no longer relied upon for recovery. See [AUTOSTART_RECOVERY.md](AUTOSTART_RECOVERY.md) for evidence, limits, and rollback.

## Suggested first prompts

```text
Use Personal DC and list my configured projects.
```

```text
Use Personal DC to show git status for ERP_MCP.
```

```text
Use Personal DC to read D:\Repo\ERP_MCP\README.md.
```

## Troubleshooting

Run:

```powershell
python -m personal_dc.doctor
.\vendor\tunnel-client\tunnel-client.exe doctor --profile personal-dc --explain
```

If ChatGPT cannot see the tunnel, verify that the tunnel is associated with the correct OpenAI Platform organization / ChatGPT workspace and that the runtime principal has Tunnels Read + Use.
