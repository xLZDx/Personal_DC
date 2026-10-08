# Phase 03 security / functional review — 2026-10-08

Scope: isolated clone `D:\Temp\Personal_DC_v2_2_full_20261008`, branch
`feature/developer-gateway-v2-2`. No review or claim covers installed
Windows broker, production tunnel, host accounts, real 1C data, or protected main.

## Confirmed work

- Added metadata-only, bounded Base64/zlib recovery examination. The old
  `phase03-source.b64` is malformed Base64; `execution-transfer-v1.b64`
  decodes but is not a complete zlib stream. Neither was extracted or executed.
  Evidence: `evidence/phase03/recovery-audit.json`.
- Added grant-bound `task.propose`, with no host command or Docker launch.
- Guest environment overrides are rejected with `UNSUPPORTED` rather than
  silently ignored or inherited from Windows.
- Output limits are attached to persisted task records and enforced across
  all pages, not reset per call. Older state without an output grant fails
  closed for `task.output`. Redaction precedes pagination.
- `file.diff` now exposes only registered resource keys. File read, diff,
  and search responses enforce manifest/grant output budgets, not only
  general memory limits.
- Synthetic test suite: **575 passed, 3 skipped**, full local Windows run;
  Phase03-only: **47 passed, 1 skipped**. Exit code 0; raw console files
  under `evidence/phase03`. Three skips are not PASS.
- Live Docker probe: Python execution, guest writes and diff, cancellation,
  deadline, persisted STOP and restart denial: PASS.
- Pinned Node guest: Node, offline npm build, Git, no inherited test secrets
  and no guest network route: PASS. These are disposable probes, not a
  Windows threat-model certification.

## Ten review perspectives (in-process analytical passes, NOT external agents)

| Role | Evidence-focused finding | Disposition |
| --- | --- | --- |
| Architect | `dc_v2` is additive, but trusted deployment broker/issuer boundary is absent | HOLD |
| Security | Docker Desktop bind mount and daemon still hold elevated host authority | G02 PARTIAL |
| Windows engineering | Windows ACL, reparse-point and race-safe handle tests are not certified | BLOCKED |
| Backend | Real container lifecycle and persisted task state work; data store lacks cross-process locking | PARTIAL |
| Functional testing | 575 passing tests plus actual guest probes; .NET/pwsh/Playwright guests unverified | PARTIAL |
| Performance | CPU, RAM, PID and timeout caps exist; concurrency and exhaustion/load tests missing | PARTIAL |
| DevSecOps | Feature branch/CI test discovery available; signer, privileged service and secure updates absent | HOLD |
| Integration | No production model-facing Phase03 endpoint; existing Phase02 tunnel intact | HOLD |
| Red-team | Output budget and unregistered diff disclosure paths were addressed, but TOCTOU and orphan processes remain | PARTIAL |
| Devil's advocate | Successful isolated CLI execution does not prove safe arbitrary developer access or protected promotion | NO PRODUCTION GO |

This is a **role-by-role review within one assistant execution**, not ten
independent human or model attestations; no fictional consensus is asserted.

## Known blocking risks

1. A local API can construct `TaskGrant` in-process. Only a separately
   protected identity/grant issuer could make it a production authority.
2. Python path inspection and `os.replace` are not a guarantee against
   concurrent Windows reparse, rename or malicious guest races.
3. Docker Desktop is NOT a security-equivalent replacement for a separately
   protected virtual machine; label ownership is not OS-level containment.
4. STOP persistence works but no independently privileged orphan reaper exists.
5. Audit hash chaining is local, not externally anchored, and journal writes
   are not protected across independent processes.
6. Promotion is a separately authorized **synthetic single-file** CAS
   prototype; no atomic multi-file rollback or privileged target handle.
7. No verified network IPC, signed broker, real approval device, fine-grained
   data classification or production OAuth/tunnel integration exists.
8. `changes.export`, `file.replace`, `directory.create` and remote
   lifecycle mediation are not separately exposed as public supported tools.
   Existing `file.write` / `file.mkdir` are local broker methods, not
   a verified replacement contract.
9. Real .NET, PowerShell, pytest and browser toolchain **inside the guest**
   remain unverified, irrespective of host-installed binaries.
10. Running source under a Python shell on the Windows host is restricted to
    trusted validation/probe orchestration; arbitrary client argv are passed
    only to isolated guest CLI.

## Gate conclusion

G01 PARTIAL; G02 PARTIAL; G03 BLOCKED; G04 BLOCKED; G05 PARTIAL;
G06 PARTIAL; G07 PARTIAL; G08 PARTIAL; G09 BLOCKED; G10 BLOCKED;
G11 BLOCKED; G12 BLOCKED; G13 PARTIAL.

Merge to main: **NOT AUTHORIZED**. Live gateway cutover: **NOT AUTHORIZED**.
Required operator approvals and technical follow-ups remain in
`docs/v2_2/OPERATOR_BACKLOG.md`. Feature-branch PR may be reviewed without
promoting or activating code.

## Follow-up cancellation error reporting

An additional negative test verifies that Docker stop failure **does not**
produce the public success-like `CANCEL_REQUESTED` response. The failure
surfaces as `ENVIRONMENT_UNAVAILABLE`. Emergency STOP latches regardless of
individual Docker stop failures and records affected tasks as
`STOP_UNVERIFIED`. This does not replace an independent privileged
orphan-controller or guarantee all workers have terminated.

## Import and workspace quota hardening — next isolated continuation

- A case-insensitive Windows path alias (for example Foo.py/foo.py) now
  rejects the whole synthetic snapshot before files are written.
- Conflicting file/parent directory paths also reject before workspace creation.
- Protected nested source paths are explicitly covered by regression tests.
- Import supports the documented 200-file count: legacy snapshot digests for
  <=128 files remain unchanged; larger snapshots use a versioned canonical
  list with up to 200 entries.
- Broker writes now recount current workspace file count and total size.
  A post-import write may not exceed 200 files or 10 MB of content.
- These are in-process safeguards, **not** race-free Windows handle or ACL
  enforcement against an untrusted process concurrently mutating workspaces.
  G02/G06 remain PARTIAL, and deployment remains HOLD.

## Orphan inventory — independent read-only foundation

The new `dc_v2/phase03_inventory.py` performs a bounded read-only comparison
of broker-owned task IDs and Docker containers carrying the exact
`personal-dc.owner=phase03` label. Every returned name must match the
`pdc22-` random ID format; malformed, ambiguous, duplicate or corrupted
results fail closed. Audit integrity is verified before Docker inspection.
A report flags missing registered containers and unregistered labeled
containers for trusted operator review.

This is **not** a deployable kill controller: it has no daemon authority
hardening, independent service identity, periodic monitoring, STOP enforcement,
or automatic termination. TECH-04 is still PARTIAL and G07 is not PASS.
The unit negative-test suite is `tests_phase03/test_inventory.py` (7 tests).

## Autonomous continuation — broker candidates, 2026-10-08

Additional additive, not model-facing modules:
- `phase03_inventory.py`: read-only reconciliation of registered tasks and labeled Docker containers; unexpected IDs and audit corruption fail closed.
- `phase03_container_policy.py`: HostConfig/image/mount validation. Real Docker inspect smoke was PASS for a disposable guest, but Docker is NOT VM-equivalent.
- `phase03_supervisor.py`: stop-latch one-shot reconciliation for registered/policy-matching containers only. Not installed as independent Windows service; unknown resources never stopped.
- `approved_execution.py`: transactional single-use signed Ledger approval before Docker side effect; replay cannot start another process, uncertain failed attempt is not retried.
- `phase03_output_store.py`: redacted, hash-checked immutable synthetic task-output snapshots with stable cursors and grant-limited export. Not cross-process transactional and depends on trusted ACLs.
- `MANUAL_ACCEPTANCE_CHECKLIST.md`: explicit operator review criteria for G01–G13.

These components are local prototypes behind the trusted broker boundary, not production-ready services or public MCP routes. TECH-02/04/05/07/09 are PARTIAL, and G01–G13 system status remains unchanged pending independent service identity, approval enrollment, audit anchoring, Windows ACL, end-to-end gates, and deployment review.

## Output snapshot pre-existing-file refusal

The snapshot sealing prototype now refuses to overwrite a pre-existing,
partially written or suspicious snapshot path. A new negative test confirms
that the existing file stays intact and no missing metadata is synthesized.
This remains a best-effort application-level precheck; concurrent trusted
processes and Windows filesystem races still require a separately protected
service, cross-process synchronization and handle-based write semantics.
Production TECH-03/05/06 and G01/G08 remain PARTIAL or HOLD.

## Release gate evaluator

The new `dc_v2/release_gate.py` requires all G01–G13 to be represented.
Any claimed PASS must be bound to the exact reviewed Git HEAD and to
independent system-test evidence with a SHA-256 digest. Missing and mismatched
evidence fails closed. Even a full asserted PASS returns only
`REVIEW_ELIGIBLE`, never automatic activation. This is validation of
evidence metadata, not verification that a claimed evidence payload is
genuine or that deployment is actually secure. Protected evidence collection,
independent reviewers and full system acceptance remain required.
