# Commit note — consolidated-review remediation (2026-10-09)

Context for a developer new to the project: `dc_v2/winops` is the native Windows operations layer served by the v2 MCP
backend. The previous commit (2e46ff3) added it; a 10-perspective local review then produced a BLOCKER/MAJOR batch. This
commit remediates that batch in one go. Nothing was executed yet (tests run only in the final verification phase).

## What changed
* `personal_dc/policy.py` (shared v1+v2, written once): syntactic path gate, credential suffix/name blocking, protected
  write prefixes (`config`, `logs`). `server.py`: protected names filtered from listings, `git_push` restricted to a
  configured remote name and strict branch regex. `executor.py`: sanitized child env.
* `dc_v2/winops/common.py`: DPAPI, hash-chained audit, approval engine (request/grant/deny/consume), `threaded`,
  `safe_path`, `redact`.
* `procs.py`, `process_tools.py`, `command_tools.py`: identity (pid, creation time), Job Objects, adoption on restart,
  structural read-only PowerShell, interpreters now require approval.
* `service_tools.py`, `deploy_tools.py`: confirmed state transitions, rollback records, plan freshness, HKCU WOW6432Node.
* `onec_tools.py` (rewritten): full-buffer XML safety, redaction, fail-closed discovery, single reversible repair path
  shared with recovery, hardened OData probe.
* `dc_v2/binary_transfer.py`: shared path gate, hash-while-copy, atomic metadata, idempotent finish, orphan purge,
  optional `expected_sha256` on download.
* `v1_gate.py` (new): approval wrappers for v1 `git_push`/`run_project_tests` that delegate to the v1 functions.
* `registry.py`, `approve.py`, `native_personal_mcp.py`: redacted disclosure, `threaded`, deny via engine, digest-suffix
  confirmation, backend key popped from the environment.
* `scripts_v2/*`: quoted tunnel header, bounded readiness + periodic health probes, `Global\` mutex, immutable original
  task export, action verified after update, cleanup on slow backend start.
* Tests under `tests_winops/` updated to the remediated behavior (not executed).

## How to verify / roll back
Final verification package: `docs/v2_2/native/FINAL_VERIFICATION.md`. Roll back with `git revert` of this commit; the
scheduled task has `task-Personal_DC_V2_Tunnel-ORIGINAL.xml` and `update_v2_native_autostart.ps1 -Rollback`.
