# Personal DC v2.2 — implementation status

Updated: 2026-10-08. Branch: `feature/developer-gateway-v2-2`.
Foundation base: `daf5968a99bf1c237815bb0ce18a50838253267b`.

## Current verdict

PHASE 02 CODE AND LOOPBACK VERIFICATION: COMPLETE.
PHASE 02 DEPLOYED MODEL-FACING ACCEPTANCE: PARTIAL / HOLD.
PHASE 03 LOCAL EXECUTION CODE + OFFLINE DOCKER PROBES: PARTIAL (guest execution proven).
PHASE 03 DEPLOYMENT/SYSTEM ACCEPTANCE: HOLD. PRODUCTION SWITCH: NOT PERFORMED.

This distinction preserves the original deployment gates; tests of a local dev profile do not waive them. The full original tracked source is retained. New runtime code is additive under `dc_v2`; the original `personal_dc`, configuration and tunnel scripts are unchanged; feature-clone packaging and CI test discovery were extended without changing the active main checkout.

## Completed in this continuation

Authenticated Remote Desktop Commander access to the authorized Windows device was used. The complete independent local clone at `D:\Temp\Personal_DC_v2_2_full_20261008` was verified, with its own `.git` and no alternates. The main checkout `D:\Repo\Personal_DC` was not switched or edited.

Implemented six read-only MCP tools with immutable approved snapshots, scope/project/recipient checks, development bearer bindings, strict stateless Streamable HTTP, quotas, local fail-closed audit and explicit denial of legacy writes/execution. No tools execute commands, access requested host paths, issue approvals or carry provider credentials. `git_inspect` is an approved captured diagnostic, not live Git execution.

Windows final pre-commit run: 129/129 Phase 02 tests; full legacy+foundation+Phase 02 discovery 268 passed, 1 skipped. The sole skip is the original symlink-creation privilege fixture. Seven new mutations and three original mutations were detected on Windows. Official MCP SDK 1.29.0 completed concurrent real HTTP round trips with synthetic fixtures, tested another recipient's denial and confirmed listener shutdown. Linux Phase 02: 128 passed, 1 skipped (SDK absent there). Exact-head/source hash evidence is recorded separately in the final receipt.

## What remains

Applicable deployed G01/G04/G08/G09/G10/G11 checks: protected installation/identity/audit boundaries; real approved data export; actual OAuth/tunnel integration; protected update procedure; explicit later switching and retirement of old model-accessible paths. None was performed by modifying the owner's running connection. See the five bounded blockers in `PHASE02_GATE_EVIDENCE.md`.

Phase 03 now has a tested isolated Docker CLI backend, local resource-ID file broker, task lifecycle, snapshot diff, synthetic signed promotion CAS, offline Python/Node/npm/Git smoke, fsynced local audit and persistent STOP latch. This is real disposable guest execution but NOT a production gateway. Still missing independent privileged broker/approval device, protected ACLs, independent OS kill controller, real-data ingestion, externally anchored audit, credential adapters, controlled promotion, .NET/pwsh/Playwright guest profiles, model-facing authentication and deployment gate clearance. No host-shell fallback. See PHASE03_EXECUTION.md, SECURITY_GATES_PHASE03.md and OPERATOR_BACKLOG.md.

## Evidence and use

See `PHASE02_READONLY.md`, `PHASE02_GATE_EVIDENCE.md`, `PHASE02_OPERATOR_RUNBOOK.md` and `evidence/v2_2/phase02-closure.json` when present. Raw logs/JUnit remain local at `evidence/phase02`. The generated delivery receipt distinguishes tested code commit from any later documentation/evidence-only commit. The isolated feature branch now packages `dc_v2` and includes the Phase03 tests in default pytest discovery; the installed live main runtime is unchanged.

## Latest continuation checkpoint (2026-10-08)

Authenticated Remote Desktop Commander confirmed main unchanged, isolated
feature clone at c9e88c82 baseline, and Docker Engine 29.5.2 Linux online.
A bounded forensic script checked both old recovery packages; both are
unusable (malformed Base64, incomplete zlib respectively). New code did not
execute anything from those packages.

Improved grant-scoped `task.propose`, fail-closed environment overrides,
persisted aggregate task output budgets, registered-only diffs and broker
read/search/diff budgets; security-oriented negative tests were added.
Full Windows regression: **575 passed, 3 skipped, exit 0**.
Live Docker and offline toolchains probes: **PASS, exit 0** (synthetic only).
Raw evidence is under evidence/phase03; in-process ten-perspective review is
in PHASE03_HARDENING_REVIEW.md. Production deployment remains HOLD.

## Autonomous import/quota continuation (2026-10-08)

Synthetic Windows workspace imports now reject casefold-equivalent names,
conflicting file and parent-directory paths, and protected nested paths
before creating a workspace. Imports of up to 200 files use a versioned
canonical list snapshot after the legacy 128-key digest boundary. Broker
writes recalculate the current file/byte totals and enforce 200 files /
10 MB, as well as the existing per-file limit. This does not make
Windows path accesses race-free or replace a protected OS broker.

Latest independent full Windows regression: **580 passed, 3 skipped**.
Phase 03 focused: **52 passed, 1 skipped**. Tests cover negative import
and quota cases; production system acceptance remains HOLD. Current
console evidence was captured under
`D:\Temp\Personal_DC_v2_2_isolated\evidence\phase03-full-20261008-v3.txt`.

## Latest autonomous source continuation — 2026-10-08

New additive local candidates:
- `dc_v2/phase03_inventory.py`: bounded read-only reconciliation of registered tasks and labeled Docker worker containers. Unknown containers are never stopped or deleted.
- `dc_v2/phase03_container_policy.py`: inspect-time Docker identity, image, privilege, network, mount and resource checks. Real disposable Docker HostConfig check returned PASS; does not certify Windows/VM isolation.
- `dc_v2/phase03_supervisor.py`: single-run STOP reconciliation, policy-checking each registered Docker task, fail-closed for unknown/unverified tasks. NOT installed as an independently privileged service.
- `dc_v2/approved_execution.py`: signed one-time Ledger reservation prior to starting a Docker job. Replay is rejected or returned as already reserved, not rerun. Direct underlying runner remains callable inside trusted Python; no protected IPC boundary exists.
- `dc_v2/phase03_output_store.py`: redacted, bounded, integrity-checked output snapshot prototype with stable paging. Multi-process races, Windows ACL, atomic two-file persistence and external audit remain outstanding.
- `docs/v2_2/MANUAL_ACCEPTANCE_CHECKLIST.md`: explicit acceptance checks for all 13 gates, not evidence of passing them.

Tests were added for all components, including denial on tampering, ambiguous Docker inventory, hostile HostConfig, replay, output quota and cross-principal reads. The first full Windows regression had **623 passed, 3 skipped, 1 failed**, where the one failure was an old 5-second MCP stdio latency assertion at 6.02 seconds. That test passed on isolated retry. A clean full regression and exact-head CI are required before declaring green. Production gate status remains HOLD/PARTIAL, with no G01–G13 system PASS.

The operator can approve design choices, but source code alone does NOT safely deliver the privileged independent broker, approval agent, audited OS configuration or cutover. Do not interpret this as production-ready.

## Repeat full regression result

Repeated full Windows suite on 2026-10-08: **624 passed, 3 skipped, 0 failed**, exit 0. The earlier legacy stdio latency threshold failure (6.02 s vs 5 s) passed in a separately executed retry, then the full suite passed unchanged. Evidence remains in the isolated diagnostics directory `D:\Temp\Personal_DC_v2_2_isolated\evidence\phase03-full-repeat.txt`. These are local source-tree tests, not production G01–G13 approval.
