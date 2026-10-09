# Native Windows tools — reference

All tools are registered by `dc_v2/winops/registry.py` (`TOOL_NAMES`). Responses with `status: APPROVAL_REQUIRED`
mean "ask the owner" — see `ARCHITECTURE.md §3`.

## Commands
| Tool | Purpose |
|---|---|
| `command_execute(command, shell, argv, cwd, timeout_s, mode, env, approval_id, max_chars)` | run to completion. `shell`: `catalog` (legacy aliases: python_version, whoami, hostname, ipconfig, network_ports, processes, services, systeminfo, disk_free), `powershell` (EncodedCommand, UTF-8), `cmd`, `exec` (argv, no shell) |
| `command_start / command_status / command_output / command_cancel` | background command lifecycle; output paged by UTF-8-aligned byte offsets |
| `command_history(limit_rows, state)` | recent commands, redacted summaries |

`read_only`: catalog, allow-listed system exes with validated args, or a PowerShell pipeline of allow-listed `Get-*`
cmdlets with literal parameters (no `;&$(){}<>`, no scriptblocks, CIM classes allow-listed). `workspace_write`: cwd must be in
the policy roots; shells/unknown exes need approval. Timeout kills the whole tree (`state: timed_out`).

## Processes
`process_list`, `process_inspect(pid)`, `process_start(executable,args,cwd,timeout_s,mode,env,label,approval_id)`,
`process_status`, `process_output`, `process_stop`. Only managed ids can be stopped. Identity = pid + creation time.

## Services
`service_list`, `service_inspect` (SCM status, dependencies/dependents, `can_start/can_stop`, allowlist), `service_start`,
`service_stop`, `service_restart`, `service_wait`. Mutations need: exact name, allowlist entry for the action, not on the
denylist, approval (unless `approval_free`), no running dependents for stop; result includes `confirmed` state and a rollback id.

Allowlist (operator overlay `%LOCALAPPDATA%\Personal_DC_V2\config\native.json`):
```json
{"service_allowlist": [{"name": "Apache2.4", "actions": ["start","stop","restart"], "approval_free": []}]}
```

## Software / deployment
`software_inspect`, `installer_verify(path, expected_sha256)`, `deployment_plan(installer_path, expected_sha256, profile, install_dir)`,
`deployment_apply(plan_id, approval_id)`, `deployment_status`, `deployment_rollback`. Profiles: `msi`, `inno`, `nsis`.
Trust: valid Authenticode from `trusted_publishers`/`trusted_thumbprints`, or hash in `trusted_installer_sha256`; plus a
caller-pinned SHA-256. Staged copy is re-hashed before execution. MSI rollback = uninstall by ProductCode.

## Files
Existing v1 tools unchanged. Added: `binary_download_chunk`, `binary_upload_status`, `binary_upload_abort`, `file_info`.
Uploads never overwrite, publish via atomic rename, expire after 24 h, max 16 open, 25 MiB each; downloads ≤ 100 MiB.

## Security / audit
`native_security_status`, `native_audit_tail`. Verify the chain from the workstation: `python -m dc_v2.winops.approve verify-audit`.

## Operator quick start
```powershell
cd D:\Temp\Personal_DC_v2_2_full_20261008
C:\Python314\python.exe -m dc_v2.winops.approve init        # once
C:\Python314\python.exe -m dc_v2.winops.approve list
C:\Python314\python.exe -m dc_v2.winops.approve grant req-<id>
.\scripts_v2\update_v2_native_autostart.ps1 -DryRun         # then without -DryRun; -Rollback to undo
.\scripts_v2\status_v2_native.ps1
```
