# Personal DC v2.2 — manual acceptance checklist

This is a **future** acceptance plan, not permission to activate the feature.
All tests below require evidence on the exact reviewed Git SHA. Any failure is
a release blocker. Do not mark a gate PASS from a unit-test-only result.

## Preconditions

- [ ] Reviewed and approved exact commit SHA and dependency lock manifest.
- [ ] Independently authorized Windows broker service account; ACL and IPC
      identity verified against a different, unprivileged Windows user.
- [ ] Independent approval/TaskGrant signer enrolled; no client-controlled
      'approved=true' or user-controlled token can grant access.
- [ ] Disposable test VM/snapshot, isolated Docker engine and disposable data.
- [ ] Explicit real-data export classification; never use secrets as fixtures.
- [ ] Protected rollback snapshot and working emergency shutdown method.
- [ ] Confirm live DC_MCP and existing tunnel remain healthy before test.

## Operator checks, after all automated gates pass

- [ ] G01: unauthenticated and low-privilege clients cannot alter broker
      configuration, service files, token stores, audit, policy or images.
- [ ] G02: worker has no Docker socket, host shell, user profile, writable
      production mounts, secret env, privileged mode or unrestricted network.
      Prove directory escape, symlinks, junction and race attempts fail.
- [ ] G03: approval request visibly binds exact principal, recipient, project,
      snapshot digest, manifest, operation, nonce and expiry. Replay fails.
- [ ] G04: every model-visible byte is classified and exported only to an
      explicitly authorized recipient. A canary never appears unredacted.
- [ ] G05: arbitrary guest internet egress and external-capability calls
      without policy are rejected and logged.
- [ ] G06: proposed diff exactly matches approved snapshot; concurrent target
      changes fail closed; multi-file rollback restores consistency.
- [ ] G07: kill switch persists across service restart and stops owned workers
      after broker crash. Unknown Docker resources remain untouched.
- [ ] G08: denied and successful actions appear in independently protected
      audit, with continuity verified after crash and replay.
- [ ] G09: legacy endpoints cannot bypass new approvals or invoke host shell.
- [ ] G10: bound authenticated MCP/OAuth/tunnel principal cannot impersonate
      other projects or select arbitrary host paths.
- [ ] G11: signed upgrade, downgrade refusal where required and rollback
      are tested without service/data loss.
- [ ] G12: authorized human can review, reject and approve exact operation
      with clear consequences; expiry/revocation work.
- [ ] G13: Python, Node, Git, pytest, .NET, PowerShell, browser E2E, filesystem
      operations, task cancel/timeout/output and promotion pass against real
      pinned guest profiles.

## Release decision

**NO GO** whenever any G01–G13 is PARTIAL / HOLD / FAIL / NOT_RUN or any
critical finding remains. Recheck production configuration, health, rollback,
and audit before any operator-approved cutover. The existing live MCP remains
untouched until that separate change is explicitly authorized.
