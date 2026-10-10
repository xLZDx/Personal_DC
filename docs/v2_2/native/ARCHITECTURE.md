# Personal DC v2 — Native Windows architecture

Version 2.0.0 · native Windows 11 · Python 3.14 · **no Docker**

## 1. Topology (unchanged identities)

```
ChatGPT ── OpenAI Secure MCP Tunnel (tunnel_6ac8aa49…, profile personal-dc-v2, health 127.0.0.1:18081)
              │  local hop: X-PDC-V2-Demo-Auth (DPAPI-provisioned 64-hex secret, loopback only)
              ▼
   LocalHopGuard (dc_v2/showcase_mcp.py)  ──►  FastMCP app  127.0.0.1:18766/mcp
                                                 ├─ v1 file/Git/test tools   (personal_dc.server)
                                                 ├─ windows_native_tools      (system_diagnostics, service_status)
                                                 ├─ binary_transfer           (upload/download/file_info)
                                                 └─ dc_v2.winops.registry     (this document)
```

The tunnel, plugin, keys, v1 (port 18765 / profile `personal-dc`) and `main` are not modified. The scheduled
task `Personal_DC_V2_Tunnel` is *upgraded in place* (reversible) to run the native supervisor.

## 2. Layers inside `dc_v2/winops`

| Layer | Modules | Responsibility |
|---|---|---|
| Foundation | `common.py` | state dir, DPAPI, redaction, audit chain, approvals, `safe_path`, config |
| OS primitives | `procs.py`, `sysrun.py` | ctypes process identity / Job Objects / Toolhelp; bounded runner for *server-authored* scripts only |
| Execution | `process_tools.py`, `command_tools.py` | the only path by which caller-supplied programs run |
| Domain tools | `service_tools.py`, `onec_tools.py`, `deploy_tools.py` | services, Apache/1C/OData, installers |
| Operator plane | `approve.py` | out-of-band approvals — **not** reachable from MCP |
| Wiring | `registry.py` | registers 34 tools, security status, audit tail |

Dependency direction: tools → execution → OS primitives → foundation. No module imports a tool module upward.

## 3. Trust modes and the approval boundary

| Mode | Meaning | Approval |
|---|---|---|
| `read_only` | system inspection through structural allowlists | never |
| `workspace_write` | development in `allowed_roots` | not for trusted dev tools (git/python/npm/node/dotnet resolved from the sanitized PATH); **required** for shells and any other executable |
| `elevated` | services, installers, publication repair, deployment | always |

Approval flow: tool returns `APPROVAL_REQUIRED{approval_id,digest,summary}` → owner runs
`python -m dc_v2.winops.approve grant <id>` (types the digest prefix) → caller repeats with `approval_id`.
Digest = SHA-256 over canonical JSON of `(action, params)`; grant is HMAC-signed with a DPAPI key, expires
(≤60 min, default 15), single-use (`.used` marker, exclusive create), deniable (`.denied`). Fail-closed when the key
is not provisioned. See `SECURITY_REVIEW.md` for the same-user limitation.

## 4. Process model

* Identity is `(pid, creation FILETIME)`; every control path re-verifies it. `terminate_exact` refuses on mismatch.
* Launch: `CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP`, assigned to a Job Object, then resumed
  (`NtResumeProcess`) — children cannot escape before tracking starts.
* Output goes to files (`procs/<id>/stdout.log|stderr.log`), so it survives server restarts; a monitor thread enforces
  timeout, output cap (2 × per-stream cap) and cancellation, then kills leaves-first with identity checks.
* Metadata in `procs/<id>/meta.json` (atomic replace). On start-up `ensure_recovered()` adopts live processes only if
  `(pid, creation time, image path)` match, otherwise marks `exited_unknown`.
* No `taskkill`, no name-based kill, no wildcard operations; `process_stop` accepts only managed ids.

## 5. State on disk (`%LOCALAPPDATA%\Personal_DC_V2`)

`secrets/` (DPAPI blobs, incl. `approval-key`, optional `odata-<ref>`), `approvals/`, `audit/native-audit.jsonl`
(hash chain), `procs/`, `deploy/`, `staging/`, `backups/`, `rollback/`, `config/native.json` (operator overlay),
`run/`, `logs/`. The whole directory plus `~/.claude`, `~/.ssh` and `%LOCALAPPDATA%\Personal_DC` are hard-denied to every
file tool (`safe_path`).

## 6. Failure semantics

Unknown mode/shell/action → `PolicyError`. Corrupt state files → `STATE_FILE_CORRUPT` (never silently re-created).
Audit write failure aborts the action. Post-change check failure (publication repair) restores the backup and reports
`FAILED_ROLLED_BACK`. A restart after a crash during an install shows the deployment as `failed`/`exited_unknown`, never
as success.

## 7. Autostart

`start_v2_native_supervisor.ps1` (single instance mutex) → dependency check/wait → backend start (or verified adoption)
→ real MCP readiness probe → existing tunnel profile → supervise both → backoff restart (5…120 s). Credentials only in the
child environment. `update_v2_native_autostart.ps1` exports the old task XML first; `-Rollback` restores it.
