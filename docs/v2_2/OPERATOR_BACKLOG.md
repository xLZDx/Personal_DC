# Personal DC v2.2 — operator / production backlog

Updated: 2026-10-08. No action in this register is silently approved.
All normal isolated feature-branch work remains authorized.

## Requires owner decision or separate privilege

| ID | Required action | Why blocked | Safe autonomous alternative |
| --- | --- | --- | --- |
| OP-01 | Authorize trusted Windows broker service installation and service account ACLs | Elevated machine changes and separate network/broker privileges | Implement only source and synthetic tests. |
| OP-02 | Enroll independent approval device and define protected confirmation ceremony | Agent-controlled UI cannot approve its own privileged effects | Retain Ledger/Ed25519 code with RejectAll defaults. |
| OP-03 | Approve signed source snapshots and per-resource model exports for actual projects | Real user/company data and recipients | Synthetic fixture images and local resource IDs only. |
| OP-04 | Approve immutable Docker/VM image profile policy for .NET, PowerShell, Playwright, pytest | Missing preprovisioned pinned guest toolchains; installation and image security review required | Python 3.12-slim, Node 22 bookworm offline smoke. |
| OP-05 | Authorize installation of independent OS emergency controller | Elevated service/system configuration | In-process stop + persisted STOP file stays candidate only. |
| OP-06 | Approve design of protected promotion into target projects | Writes outside disposable workspace cross a security boundary | Diff/CAS proof only; NO target mutation. |
| OP-07 | Authorize Phase03 identity/OAuth/tunnel cutover and secure updater, after G01–G13 | Production infrastructure changes, possible downtime | Keep current Phase02/main MCP untouched. |
| OP-08 | Decide whether to merge candidate PR into main after strict review | Protected main / release authorization | Feature branch pushed; PR only. |
| OP-09 | Authorize deleting failed/stopped synthetic pdc22- containers and temp fixture folders | Explicit deletion approval needed | Leave artifacts labelled for selective later cleanup. |
| OP-10 | Provision external audit anchor and immutable attestation storage | Separate trusted storage/admin action | Keep bounded local fsync hash chain; gate HOLD. |
| OP-11 | Allow a Windows symlink/reparse test under elevated test account | Local account lacks symlink privilege in pytest | Mark SKIPPED, not PASS. |
| OP-12 | Select Windows process/VM isolation hardening approach and CPU/memory quotas | Docker daemon and bind mount are privileged; container != VM | Offline no-socket Linux guest only. |
| OP-13 | Approve remote read of sensitive recovery archive material if necessary | execution-transfer-v1.b64 was Base64-decodable but its zlib/JSON contents and hashes have not been fully validated; phase03-source.b64 was malformed | Independently implemented and tested new local source. |

## Technical backlog (can proceed in future feature branches)

- TECH-01 Broker network IPC protected by ACL and per-request identity binding.
- TECH-02 Grant issuance/renewal/revocation through separately trusted approval
  service; ensure exact project/snapshot/tool/image/capability/recipient binding.
- TECH-03 Windows file-descriptor-level anti-race semantics while guests write,
  compare-and-swap promotion and content-addressed output snapshots.
- TECH-04 Supervisor that can discover owned Docker workers after crashes,
  independently enforce STOP and prevent orphan processes.
- TECH-05 Stable bounded stdout/stderr stream cursor independent of Docker log
  rotation, with redaction across all chunks and controlled log retention.
- TECH-06 Durable task-state storage with cross-process locking and atomic
  outbox integration; external audit verification.
- TECH-07 Separate security review of pinned tool images, Docker Desktop
  privilege boundary and read-only HostConfig/mount inspection.
- TECH-08 Real pytest, .NET, pwsh, GitHub CLI, Playwright and browser E2E
  in guest images only; no host fallback.
- TECH-09 Exact-head CI and mutation/negative security testing of Phase03.
- TECH-10 Model-facing integration only after required deployment gates.
- TECH-11 Harden synthetic signed promotion prototype into protected production
  protocol with handles/ACL, multi-file atomicity/rollback and owner challenge,
  without automatic code execution.
- TECH-12 Add project import policy to exclude .git, token stores, symlinks,
  private/company datasets and dangerous artifact metadata.

## Hard restrictions

No deletion; no changes to D:\Repo\Personal_DC; no production tunnel restart;
no credentials in workers; no branch merge or force-push without explicit
authorization. Any release or production switch needs a new gate decision.

## Recovery and latest technical status, 2026-10-08

- OP-13 inspection has completed in metadata-only mode without extraction:
  source transfer is malformed Base64; second transfer has incomplete
  compressed payload. No operator request to execute or trust either file.
- TECH-05 partly hardened: total output grant bounds and fail-closed
  legacy-state reads. Stable stream cursor across log rotation still needed.
- TECH-12 partly hardened: synthetic broker diff now excludes unregistered
  files; production import/classification/cross-process handles remain open.
- TECH-09 local evidence refreshed: full regression 575 passed, 3 skipped;
  pinned guest probes passed. Exact-head remote CI remains to verify after push.
- Do not interpret these local tests as approval for service installation,
  tunnel routing, real credentials, data exports or protected promotion.
