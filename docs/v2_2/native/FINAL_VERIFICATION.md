# Final verification (single run, 2026-10-09)

Interpreter: `C:\Python314\python.exe` (3.14), mcp 1.29.0. No Docker, no CI, no GPT used. HEAD of the verified code is
recorded in GPT_FINAL_REVIEW_REQUEST.md.

## Automated (FACT: executed)
`python -m pytest tests_phase03 tests_phase02 tests tests_v2 tests_winops -o addopts=""` →
**1231 passed, 4 skipped, 0 failed** (146.8 s). tests_winops = the new native layer (approval execution, command policy,
process lifecycle, services/1C/OData/deploy, transfer/registry, v1 gate); the other directories are the v1/v2 regression
suites (backward compatibility of file/Git/binary tools).
Defects found by this first execution and fixed (test-side unless noted): `_write_record` keyword collision, giant
parametrize ids with NUL bytes, legacy `_ROOT` patching in phase03 binary tests (production now `_root()`); production:
upload staging directory not created, `-Name` rejected by the read-only PowerShell validator, `..` publication name.

## Live checks on this workstation (FACT: executed in-process via FastMCP `call_tool`, isolated state dir)
| Check | Result |
|---|---|
| Server import: 59 tools registered, all 34 `TOOL_NAMES` present, v1 `git_push`/`run_project_tests` replaced by gated wrappers | PASS |
| `command_execute` read-only PowerShell `Get-Service -Name Spooler` | PASS (exit 0, Running) |
| `Get-Service \| Stop-Service` | PASS (denied: cmdlet not allowed) |
| `cmd` in read-only mode | PASS (denied) |
| `git_push` without approval | PASS (`APPROVAL_REQUIRED`, digest bound) |
| `service_stop Spooler` (not allowlisted) | PASS (denied) |
| `service_list` (200 rows), `service_inspect`, `process_list` | PASS |
| `software_inspect` finds 1C:Enterprise 8.3.27.2342 | PASS |
| `onec_diagnostics` finds the per-user 1C platform (webinst, wsap24) | PASS (after adding `%LOCALAPPDATA%\Programs\1cv8*` discovery) |
| `odata_probe` to a closed loopback port | PASS (`reachable:false`); found+fixed duplicated `$metadata` in URL |
| Audit hash chain verifies | PASS |

## BLOCKED (not PASS — cannot be verified here)
* Apache + 1C publication, `apache_service_control`, `odata_recovery`/`odata_publication_repair` against real files: **no
  Apache is installed** on this machine (diagnostics reports `APACHE_NOT_FOUND`). Covered only by fixtures in unit tests.
* Real 1C OData responses and infobase connectivity.
* `deployment_apply`/`rollback` with a real installer and Authenticode verification.
* Real service start/stop/restart (no allowlisted service; no elevation).
* Approval grant round trip with the real DPAPI key: key not provisioned (`approval_key_provisioned=false`);
  operator must run `python -m dc_v2.winops.approve init`.
* ChatGPT-side visibility of the new tools: the running backend (pid on 127.0.0.1:18766, started 15:31) predates this
  code; it must be restarted and the connector refreshed. Autostart task still points to `start_v2_showcase.ps1`.
* Supervisor/autostart scripts: parsed (PowerShell parser, 0 errors) but not executed (would replace the live service).

Production gates G01–G13 are **not** claimed PASS.
