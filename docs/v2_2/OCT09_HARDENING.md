# Personal DC 2.2 — 2026-10-09 independent continuation

Branch: `feature/developer-gateway-v2-2`. Development clone only. Active
`D:\Repo\Personal_DC` and production tunnel are not modified.

## Verification before change

Current development HEAD at start: `7d279d596ad1fff6cf476487cc730a85b82a19ef`.
Full Windows test suite before changes: **645 passed, 4 skipped**.
Skipped tests remain distinct from PASS. Prior local Docker CLI probes are
recorded in `evidence/phase03`; they do not certify production isolation.

## Defects fixed in this slice

### OS-level emergency stop must not depend on application audit

Previously `reconcile_stop_latch` called `audit.verify()` before acting.
Corrupt/unavailable audit therefore prevented stopping even an identified,
previously registered and policy-matching Docker worker. This contradicted
the accepted emergency-stop threat model.

The trusted one-shot STOP reconciler now attempts audit verification, but
does not let its failure prevent inspection/stop of **registered** workers.
Container identity, image and host policy still must match; unknown
containers are untouched. It reports `audit_verified=false` when necessary;
no production release PASS follows. Normal inventory still verifies audit.
This is not the independent OS-level emergency controller required by G07.

### Snapshot output overwrite race and UTF-8 pages

Previously snapshot sealing used `os.replace(stage, destination)`, allowing
overwriting an artifact created after the preflight check. New snapshot
payload and metadata are created with exclusive `xb` semantics and fsync.
If the process stops after only one of the pair, it is deliberately treated
as corrupt, not recovered or overwritten without separate authorization.
Windows ACL, cross-process file handles, multi-file durability and tamper-
proof audit remain open.

Output cursors are byte offsets aligned to UTF-8 character boundaries.
Unaligned input cursors now fail closed, and a page too small for the next
character gets `PAGE_LIMIT_TOO_SMALL`, rather than silent replacement
characters or a non-progressing cursor.

## New negative and functional regressions

- Tampered audit does not block STOP of a policy-matching registered task.
- A concurrent writer plants snapshot metadata between checks; its bytes
  remain unchanged and the incomplete pair is rejected.
- UTF-8 multibyte output paginates losslessly with stable byte cursors.
- Invalid mid-code-point cursor and too-small page are rejected.
- Tests run with only synthetic fixtures; no real project data, credentials,
  unknown container or existing service was modified.

## Production / completion verdict

G07, G08 and G01 remain PARTIAL; G02/G03/G04/G05/G06/G09/G10/G11/G12/G13
retain their earlier HOLD/PARTIAL statuses. Do not claim that this slice
removes the need for the independent identity/broker service, an attested
approval device, production OAuth/tunnel integration, protected ACLs,
external audit anchors, a secure updater and cutover authorization.
Do not enable shell execution on the host or switch the live gateway.
