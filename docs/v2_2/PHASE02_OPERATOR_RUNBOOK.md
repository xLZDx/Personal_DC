# Phase 02 — local verification and later activation

Date: 2026-10-08. This is a read-only development build, not the running gateway.

## Current locations

Development clone: `D:\Temp\Personal_DC_v2_2_full_20261008` on `feature/developer-gateway-v2-2`.
Active gateway: `D:\Repo\Personal_DC` on main, intentionally unchanged.
Preparation and historical receipts: `D:\Temp\Personal_DC_v2_2_isolated\evidence`.
New raw evidence: development clone `evidence\phase02` (local only, untracked).

The clone contains all tracked source. It does not copy ignored tunnel keys, logs, vendor downloads or installation state. A normal branch switch is NOT a safe deployment/update protocol, and does not install the later protected architecture.

## Repeat the automatic checks

```powershell
Set-Location 'D:\Temp\Personal_DC_v2_2_full_20261008'
& 'C:\Python314\python.exe' scripts_v2/run_phase02_validation.py --label operator-check --legacy
& 'C:\Python314\python.exe' scripts_v2/mutation_phase02.py
& 'C:\Python314\python.exe' scripts_v2/mutation_check.py
```

These commands use synthetic fixtures and existing installed dependencies. They do not create real users, change firewall/ACL settings, retrieve owner credentials, restart the current gateway or open its tunnel. The HTTP integration test chooses an unused loopback port, shuts its server down and checks it is closed. Test-created temporary files are disposable; user data and branches are never deleted.

## Explicit source-mode bootstrap contract

Entry point: `python -m dc_v2.readonly_mcp --config <absolute-owner-controlled-config.json>` from the independent source checkout. This is for an approved local development fixture only. There is no auto-start installer or registration with the owner's active MCP client in this batch.

Config exact required fields: `profile` (must be `loopback-readonly-dev`), `port`, `issuer`, `snapshot_path`, `snapshot_sha256`, `audit_path`, `tokens`; optional `origins` (exact HTTPS origin allowlist). Each token record carries `token_sha256`, `subject`, `client_id`, `recipient_id`, `scopes`, `not_before`, `expires_at`; optional `revoked`. Do not put a plaintext token, real secret, `approved`, `role`, arbitrary host or execution flag in config/tool arguments. Credentials must be random and provisioned through a trusted local owner workflow; there is deliberately no MCP token-creation endpoint. Never reuse deterministic test credentials for an active listener.

Snapshot schema is `personal-dc.readonly.v2.2`. Projects contain explicit classification/recipients/revision/resources/tools. Resources contain explicit classification/recipients/kind/display_name/UTF-8 bytes and SHA-256. See the synthetic fixture in `tests_phase02/test_readonly.py` for the exact non-secret shape, not as an operator-approved real-data export manifest. Snapshot/config files must be protected from untrusted modification. This dev loader's link checks do not substitute for installed ACL protection.

## Example queries after an approved integration

List the tools actually available with `capabilities_list`. Read only a configured project with `project_describe {project_id}` and a configured resource with `file_read {project_id, resource_id, offset, limit}`. Use `git_inspect` only for the recorded diagnostic snapshot; it cannot answer whether a repository changed after capture. `tools_inspect` reports metadata, not whether a build has been tried. Do not tell a user that a build, Docker process or deployment ran based on these metadata responses.

## Failures

AUTH_REQUIRED: absent/expired/revoked/wrongly bound development credential. ACCESS_DENIED or EXPORT_DENIED: outside subject/project/recipient/data scope. MANIFEST_CHANGED: digest or loading consistency mismatch. AUDIT_UNAVAILABLE: no data response is allowed until the local audit is repaired by an authorized owner. QUOTA_EXCEEDED: request/output/admission bound. EXECUTION_HOLD: expected, not a defect; no shell workaround. LEGACY_MIGRATION_REQUIRED: this endpoint intentionally cannot delegate to the old tool.

Do not repair failures by disabling a gate, loosening allowed roots, dumping environment, giving the worker a token, or registering the old server as an invisible fallback.

## Stop, recovery and switching

The test listener is stopped in its fixture; no permanent Phase 02 listener is installed. Stop the particular manually created dev process through its owner-controlled session, never terminate all Python/WSL/Docker tasks. The local service latch is not the independent OS-level emergency controller required for Phase 03. A failed service must not reactivate the old unrestricted execution path.

Later activation must close P02-DEPLOY-01..05 in `PHASE02_GATE_EVIDENCE.md`, rerun applicable gates against the installed profile, obtain the explicitly deferred owner cutover permission, and test safe rollback/legacy revocation. Do not switch the active checkout in this phase.
