# Commit note — native Windows operations layer (winops) core

Branch `feature/developer-gateway-v2-2`, starts from `5a78675`.

## What and why
Personal DC v2 needs to be a full personal Windows commander through the existing ChatGPT MCP
tunnel. This commit adds `dc_v2/winops/` (stdlib + ctypes only, no Docker, no new dependencies):

| Module | Role |
|---|---|
| `common.py` | state dir, DPAPI, redaction, hash-chained audit, operator approvals, path safety (reparse points), layered config |
| `procs.py` | ctypes process primitives: identity = (pid, creation FILETIME), Toolhelp snapshot, Job Objects, exact-identity terminate, tree kill |
| `process_tools.py` | managed process registry with durable meta + file-based output, monitor thread (timeout / output cap / cancel), restart recovery; `process_*` tools |
| `command_tools.py` | `command_*` tools; PowerShell (EncodedCommand, UTF-8), CMD, argv exec; structural read-only allowlists |
| `service_tools.py` | SCM API (ctypes) status/start/stop; allowlist + hard denylist + approval; rollback records |
| `onec_tools.py` | Apache/1C discovery, httpd -t, VRD parsing, OData GET probe (counts/metadata only), reversible repair, recovery plan |
| `deploy_tools.py` | software inventory, Authenticode + hash verification, MSI/inno/nsis profiles, plan/apply/status/rollback |
| `approve.py` | operator CLI (`python -m dc_v2.winops.approve`), never an MCP tool |
| `registry.py` | single registration point + `native_security_status`, `native_audit_tail` |

Also: `binary_transfer.py` hardened (reparse-safe paths, atomic rename publish, resume/abort/download, `file_info`),
`scripts_v2/start_v2_native_supervisor.ps1`, `update_v2_native_autostart.ps1` (reversible task update), `status_v2_native.ps1`,
`config/native.json`, `tests_winops/` (written, NOT executed at this commit — operator policy: tests run once, after the consolidated review).

## Key decisions
* **MCP front door is not authorization.** Anything beyond allow-listed dev tools or read-only catalogs returns
  `APPROVAL_REQUIRED` with a request id; the owner grants it out-of-band; approval binds to SHA-256 of
  (action, params), expires, single use, HMAC-signed with a DPAPI key.
* Read-only is a *structural* allowlist (cmdlet/exe/arg shapes), not a keyword blacklist.
* Server never elevates; installers needing admin report `needs_elevation`.
* Process control only for processes this layer launched; PID reuse is defeated by creation-time identity.
* `command_execute` keeps the legacy alias catalog (`whoami`, `services`, ...) and signature compatibility.

## Not done here / follow-ups
Documentation set, consolidated local review, final verification run and GPT request come in later commits.
