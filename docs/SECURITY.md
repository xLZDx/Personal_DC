# Security model

Personal DC assumes that model output and repository content can be untrusted. Safety is enforced in code, not only in MCP annotations.

## Filesystem boundary

All file tools resolve paths before access and permit only configured roots.

Default roots:

- `D:\Repo`
- `D:\Downloads\gemeni videos`
- `D:\Temp`

Protected components such as `.git`, `.ssh`, `.aws`, `.azure`, and `.gnupg` are blocked from file tools.

Common secret files such as `.env`, SSH private-key names, credentials files, and secret JSON files are blocked.

## Destructive operations

There is no file-delete tool in v0.1.

Git force operations are not exposed by the MCP API. The push tool builds a normal fixed-form `git push <remote> <branch>`.

## Process execution

The MCP API does not expose arbitrary PowerShell or arbitrary shell strings.

Commands are executed with `subprocess.run(..., shell=False)`, an executable allowlist, a bounded timeout, bounded captured output, and an allowed working directory.

## Audit

Personal DC writes JSON Lines audit records to:

```text
logs\audit.jsonl
```

Fields whose names look like credentials, tokens, secrets, API keys, or authorization values are redacted before logging.

## Runtime key storage

For persistent Windows operation, the runtime API key is encrypted with Windows DPAPI using the `CurrentUser` scope. The encrypted blob is stored outside the repository under `%LOCALAPPDATA%\Personal_DC\secrets`.

The plaintext key is not written to Git, logs, or a plaintext `.env` file. It is decrypted only at runtime into the environment of the tunnel process because `tunnel-client` consumes the configured `env:CONTROL_PLANE_API_KEY` reference.

## Autostart

The supported supervisor task `Personal_DC_V2_Tunnel` runs with limited privileges and has no triggers; the separate recovery task owns logon and minute triggers. It starts the supervisor only after checking that the task is `Ready`. `MultipleInstances=Parallel` on the short recovery task permits simultaneous trigger actions, while a SID-scoped mutex in the Global namespace serializes them before a start request; cross-session runtime was not available and remains `NOT_RUN`. The supervisor task retains `IgnoreNew` as a second guard against overlapping starts. The supervisor validates the MCP backend and existing tunnel profile, prevents duplicate direct invocations with its session mutex, and retries transient child-service failures with a capped delay. Isolated scheduler scenarios confirmed recovery after a natural exit and serialization of overlapping recovery actions; a controlled race also showed why the logon trigger must not remain on the main task. The previous task registration's five `RestartOnFailure` attempts did not occur in a separate 138-second observation and are not relied upon for recovery. See [AUTOSTART_RECOVERY.md](AUTOSTART_RECOVERY.md) for the full evidence and the unobserved 24-hour rollover. The legacy task `Personal_DC_Tunnel` is disabled and is not modified by the v2 installer.

## Network boundary

For persistent ChatGPT/OpenAI operation, Personal DC runs a stateless Streamable HTTP MCP endpoint on `127.0.0.1:18765`. It is loopback-only and is not exposed through the firewall or router. Local stdio/SSE modes remain available for development.

Secure MCP Tunnel connects to that loopback endpoint and makes an outbound HTTPS connection to OpenAI, so no new inbound public port is exposed.

## Operator rule

Deletion remains a human-controlled operation and is deliberately absent from this initial MCP surface.
