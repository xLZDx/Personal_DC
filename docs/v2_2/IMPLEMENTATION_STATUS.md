# Personal DC v2.2 — implementation batch 01

Date: 2026-10-08. FOUNDATION IMPLEMENTED / EXECUTION HOLD / NOT RELEASED.
Base: `d3fb644263694091e20dd2c3782747d60fe777cc`.
Branch: `feature/developer-gateway-v2-2`.

## Completed

The complete original tracked project is retained in the GitHub branch. New code is additive in `dc_v2/`; original runtime, configuration, tunnel scripts and CI are unchanged.

Implemented: bounded immutable contracts and manifest hashes; strict request schema rejecting client authority; server-configured export classification, recipients and exact content digests; metadata-only tool discovery; explicit environment construction; TaskGrant scope evaluation; transactional one-time approval reservations and audit outbox; random challenges, expiration, ownership, quotas and idempotency; optional Ed25519 signature verification with pinned public keys; bounded output and exact-literal redaction across chunks; deny-by-default facade; transport/legacy-denial primitives; escaped approval PREVIEW.

132 synthetic tests exercise these components. `tests/test_v2_foundation.py` makes them discoverable by the original repository testpath; `pytest-v2.ini` selects the foundation suite independently.

## Evidence

| Environment | Result | Limits |
|---|---|---|
| Linux, Python 3.13.5 | 132 passed, 0 skipped | Foundation suite only |
| User Windows, Python 3.14.3, DC_MCP pytest | 131 passed, 1 skipped, exit 0 | Symlink creation privilege unavailable; no elevation requested |
| Negative mutations R01/R02/R03, disposable Linux copies | All three detected with expected test failures | Windows mutation run NOT_RUN |
| Source transfer | SHA-256 of eight core source/test files matches between Linux and Windows | LF-normalized; see SOURCE_MANIFEST.json |

Dependency versions observed, not installed by this batch: Linux pytest 9.0.2 / cryptography 46.0.4; Windows pytest 8.4.2 / cryptography 43.0.3. The cryptographic test uses synthetic keys. No real credentials are in evidence.

Evidence is pre-commit source-hash evidence, not a hosted-CI or production attestation. Production G01–G13 remain NOT_RUN. The legacy suite has not been run in this new directory.

## Local workstation state

`D:\Repo\Personal_DC` remains the active checkout on main. Source/test writes were confined to `D:\Temp\Personal_DC_v2_2_isolated`. This directory contains the new foundation, its tests/evidence, and a separate copy of the original `personal_dc` Python package and `run_server.py` for comparison. The copied legacy server has not been launched.

IMPORTANT: this local directory is NOT a complete Git clone and NOT an OS sandbox. Git metadata, the remaining original scripts/configuration/docs and generated/vendor files have not been copied there. The complete original tracked project remains available in the remote feature branch. A full independent local clone is still pending an authorized clone/process tool; no shared worktree was created.

Desktop Commander Remote MCP was searched and its official connection page inspected, but authenticated Commander tools are not present in this session. Work used the available DC_MCP and GitHub tools. No browser credentials or old tunnel keys were extracted. Do not repurpose pytest as a shell/clone/install workaround.

## Not implemented / release blockers

1. Full independent local clone and non-sensitive host/toolchain inventory; choose one tested isolation backend.
2. Protected installation, Windows identities/ACLs, authenticated broker IPC and service separation.
3. Real identity/OAuth/tunnel adapter and mandatory transport wiring; default identity denies all access.
4. Independent Approval Agent/device, trusted display, registration/recovery and WebAuthn UV. Ed25519 verification alone is not approval UX.
5. Disposable execution backend, network restrictions, process/resource limits, leases and independent OS emergency controller. No host fallback.
6. Provider adapters, race-safe snapshot promotion and CI isolation, unknown-outcome reconciliation.
7. Separate append-only audit service with remote anchors, protected updater, key rotation/security floor.
8. Actual migration/retirement of all old model-accessible paths and G01–G13 system acceptance.

## Security limitations

Python path checks do not solve Windows handle/ancestor-rename races, hardlinks, ACLs or kernel/VM boundaries. Tool metadata inspection does not prove Authenticode or loaded dependency integrity. Literal redaction is not universal DLP. SQLite/outbox hashes are not tamper-proof audit without independent protection/anchors. A reservation is not execution. The persisted stop flag is not an OS kill switch. `deny_legacy` does not disable the running old endpoint. The TransportGuard primitive is not a deployed authenticated transport. Preview HTML cannot approve anything.

The new package opens no listener and provides no shell/VM/deploy/promotion/update side effects. `task.start` always returns EXECUTION_HOLD. Do not register it as a replacement MCP or switch the active branch until applicable gates pass.

## Reproduce

From a checkout containing the additive files: `python -m pytest -c pytest-v2.ini`.
Developer-only mutation utility: `python scripts_v2/mutation_check.py`.
Optional crypto integration needs cryptography; tests never install dependencies. The original pyproject installs only personal_dc; dc_v2 is a source-mode foundation, not a packaged deployment.
