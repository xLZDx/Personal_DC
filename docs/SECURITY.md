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

## Network boundary

The MCP server defaults to stdio. Its optional HTTP transport binds to `127.0.0.1`.

For ChatGPT/OpenAI access, use Secure MCP Tunnel so that the workstation makes an outbound HTTPS connection rather than exposing a new inbound port.

## Operator rule

Deletion remains a human-controlled operation and is deliberately absent from this initial MCP surface.
