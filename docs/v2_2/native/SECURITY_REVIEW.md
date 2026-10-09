# Personal DC v2 native layer — Security review

Scope: `dc_v2/winops/*`, `dc_v2/binary_transfer.py`, `personal_dc/policy.py` (shared v1/v2), `scripts_v2/*native*`.
Method: ONE consolidated local review by 10 independent perspectives (Windows/PowerShell architecture, Python/MCP,
security/privilege, process lifecycle, services/installers, 1C/Apache/OData, filesystem/binary, functional/back-compat,
performance/limits, adversarial threat-model). No GPT/CI during development. Findings were remediated as one batch.
Status words: FACT = read in code; NOT-RUN = needs the final verification run.

## Trust boundary (FACT)

* The MCP front door is "No authentication" behind a tunnel. It is **not** user authorization.
* Three trust modes: `read_only`, `workspace_write`, `elevated`. Anything that can execute arbitrary code, change
  services, install software or alter publications returns `APPROVAL_REQUIRED{approval_id,digest}`.
* Approval is granted out-of-band by the owner (`python -m dc_v2.winops.approve show|grant|deny`), bound to
  SHA-256(action, params), HMAC-signed with a DPAPI key, single-use (`.used` marker created exclusively), TTL-limited,
  deniable. The operator re-types the last 8 digest characters and sees the exact params.
* The server process never elevates and never bypasses UAC. Admin-requiring installers report `needs_elevation`.

## Findings and resolution (summary)

| Area | Finding (BLOCKER/MAJOR) | Resolution |
|---|---|---|
| Approval | interpreters (python/node/npm/pip/dotnet) were "trusted" and ran arbitrary code without approval | removed from the free set; only local git subcommands run free |
| Approval | v1 `write_text_file` could rewrite gateway config/logs | shared `Policy.write_protected` (`config`, `logs`) → `GATEWAY_CONTROL_PATH_PROTECTED` |
| Approval | v1 `git_push` / `run_project_tests` reachable without approval in v2 | `v1_gate.py` wraps them (delegates to the unchanged v1 function) |
| Paths | UNC, `\\?\`, drive-relative, ADS, trailing dot/space, device names | `syntactic_check()` before any filesystem access, shared by v1+v2 |
| Paths | credential files readable | `CREDENTIAL_SUFFIXES` + protected names blocked for read and write |
| Paths | junction/symlink inside an allowed root | lexical AND resolved chain checked by `assert_no_reparse_chain` |
| Env | backend key / control-plane keys inherited by children | `build_env`/`_child_env` allow-list; key popped from `os.environ` after read |
| PowerShell | keyword blacklist bypasses | structural token allowlist (`validate_readonly_powershell`), CIM class allowlist, caller data only via `PDC_ARG_*` env |
| Processes | pid reuse kill | identity is (pid, creation FILETIME); Job Objects; tree kill by exact identity |
| Processes | output unbounded / lost on restart | file-based output with monitor thread, bounded reads, adoption on restart |
| Services | arbitrary service control | allowlist + denylist, dependents check, state confirmation, rollback record |
| 1C/Apache | XML DTD/entity (billion laughs) beyond first bytes, UTF-16 evasion | full-buffer DOCTYPE/ENTITY scan, non-UTF-8 rejected |
| 1C/Apache | `ib=` credentials leaked (also in diffs, doubled quotes) | `_redact_conn` on every output path |
| 1C/Apache | `Include` traversal; degraded service discovery treated as "no Apache" | include containment to Apache roots; recovery plan fails closed on degraded discovery |
| 1C/Apache | repair/recovery used two different write paths | single `_apply_vrd_change`: backup, hash binding, atomic write, baseline-vs-after `httpd -t`, auto-restore |
| OData | SSRF, proxy use, userinfo, credential misuse | allowed hosts, `ProxyHandler({})`, no redirects, credential only for `$metadata`/root, no record contents returned |
| Files | publish verified a different copy than it renamed | hash computed while copying to the temp file in the target directory, compared before `rename` |
| Files | overwrite race | `os.rename` (fails if target exists); never `replace` |
| Audit | duplicate/unchained events | one hash-chained log (`common.audit`); `native_audit_tail` redacts |
| Autostart | tunnel header split by `Start-Process`; no health checks; task action lacked execution policy | quoted header, bounded readiness + periodic probes, `Global\` mutex, immutable ORIGINAL task export, action verified after update |

## Residual risks (see KNOWN_LIMITATIONS.md)

1. **Same-user approval authority.** The approval key is DPAPI-protected for the *same Windows user* that runs the
   server. Malware/model code running as that user could read the key. `native_security_status` reports
   `approval_authority_isolated=false`. Approval is a deliberate-intent control, not a privilege boundary.
2. Audit chain is unkeyed: tamper-evident against accidents, not against a determined same-user attacker.
3. No OS sandbox for managed processes beyond Job Objects (memory/active-process limits, kill-on-close).
4. Real 1C/Apache/installer behavior is validated only on what exists on this workstation (see FINAL_VERIFICATION.md).
