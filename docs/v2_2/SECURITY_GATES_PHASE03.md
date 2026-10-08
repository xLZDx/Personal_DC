# Phase 03 — security gate register (2026-10-08)

Test status is NOT a deployment verdict. No row below is an overall G01–G13
system PASS. Review this against the originally defined gate contract.

| Gate | Result | Concrete evidence / remaining acceptance |
| --- | --- | --- |
| G01 Gateway self-protection | PARTIAL | No model-facing execution endpoint; no privileged broker process/ACL or signed installer validated. |
| G02 Guest isolation | PARTIAL | Real pinned offline Linux Docker guest, network=none, restricted uid/caps/CPU/RAM/PIDs; NOT VM-equivalent, Windows reparse/daemon threat still open. |
| G03 Trustworthy approvals | HOLD | Existing ledger verifies Ed25519 capability in unit tests but no separately enrolled trusted Approval Agent or boundary-issued TaskGrant in deployed architecture. |
| G04 Model data export | HOLD | Only synthetic disposable fixtures; real data classification and recipients not exercised. |
| G05 Network/external authority | PARTIAL | No route in Node guest; no secrets inherited in Node probe; external capability adapters not implemented. |
| G06 Promotion | PARTIAL | Synthetic content-addressed plan, one-time signature-bound Ledger reservation and single-file CAS apply tested; no protected production destination or transactional multi-file rollback. |
| G07 Processes / kill switch | PARTIAL | Real start/status/output/cancel; timeout enforced in guest, STOP latch persists; independent OS-level orphan controller missing. |
| G08 Audit | PARTIAL | Local fsynced hash chain with corruption refusal; no external anchor/ACL/HA audit delivery. |
| G09 Legacy bypass removal | HOLD | Legacy runtime and tunnel intentionally unchanged; cutover review not executed. |
| G10 Auth / tunnel | HOLD | No direct model-facing Phase03 route; deployed issuer and OAuth/tunnel not validated. |
| G11 Secure updates | HOLD | No installed Windows production updater and rollback evidence. |
| G12 Approval UX | HOLD | Only foundation preview; trusted out-of-band confirmations absent. |
| G13 Functional completeness | PARTIAL | Real Python, Node, npm, Git in pinned Linux guests; .NET, PowerShell, pytest guest, Playwright, CI, provider adapters not validated. |

## Test evidence

- evidence/phase03/unit-console.txt: Phase03 unit/security/reliability tests.
- evidence/phase03/full-console.txt: legacy + foundation + Phase02 + Phase03 regression.
- evidence/phase03/live-probe.json: actual Docker engine, Python command, guest
  write/diff, long task cancellation, autonomous deadline and emergency STOP.
- evidence/phase03/toolchains.json: Node CLI, offline npm build, Git, environment
  isolation, disabled guest route.
- scripts_v2/phase03_live_probe.py and phase03_toolchains_probe.py bind checks to
  immutable local image config IDs. These are disposable probes, not deploy tests.

Current merge decision: PR preparation permitted; merge into main, production
activation, credential integration and any deletion are operator-controlled.
