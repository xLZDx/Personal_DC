# Phase 02 — evidence map, residual blockers and non-claims

Date: 2026-10-08. All PASS statements below refer only to the tested local development profile and exact source hashes. They do not close production gates by inheritance. No external AI reviewers were used.

## Measured runs

| Run | Result | Scope |
|---|---|---|
| Windows Phase 02 final | 129 passed, 0 failed, 0 skipped | Unit, ASGI, config and real official-SDK HTTP round trip |
| Windows full discovery | 268 passed, 0 failed, 1 skipped | Original tests plus foundation plus Phase 02 |
| Windows foundation alone | 131 passed, 0 failed, 1 skipped | Original foundation symlink-privilege skip remains |
| Linux Phase 02 final | 128 passed, 0 failed, 1 skipped | SDK unavailable on this Linux environment |
| Windows new mutations | 7/7 detected | Expected assertion failures; originals unchanged |
| Windows original mutations | R01/R02/R03 detected | Expected nonzero pytest results in disposable copies |

Suite totals overlap; do not sum the three Windows runs as distinct tests. The source-hash run precedes the implementation commit. A separate exact-head rerun and receipt are required before final delivery; that receipt is authoritative over these summary labels. JUnit/log files remain local; only bounded non-secret summaries/source hashes are committed.

## Required deployed gates

| Gate | Verified here | Remaining requirement / status |
|---|---|---|
| G01 self-protection | Read API has no write/execute fallback; frozen snapshot; independent clone | Installed runtime/policy/approval-store ACL/process separation NOT_RUN |
| G04 data export | Strict classes/digests, all read paths scoped, canary and metadata/page tests | Real owner export manifest and deployment data-flow acceptance NOT_RUN |
| G08 audit | Local integrity, missing-newline/truncation tests, fail-closed delivery | Independent protected service, durable/remote anchor and recovery NOT_RUN |
| G09 bypass retirement | New endpoint refuses all legacy names | Old model-connected Commander/DC/CI paths intentionally retained for development; retirement NOT_PERFORMED |
| G10 auth/transport | Loopback peer, Host/Origin, duplicate/spoof headers, expiry/audience, post-body recheck, cross-client denial, real SDK | Actual tunnel identity mapping/OAuth client flow, exposed endpoint and direct-local bypass acceptance NOT_RUN |
| G11 update integrity | This batch does not update installed gateway at all | Protected updater/signing/floor/rotation deployment NOT_RUN |
| G13 capability coverage | Six declared snapshot tools and real MCP round trip | Universal development CLI/process parity belongs to Phase 03; NOT_IMPLEMENTED |

G02/G03/G05/G06/G07/G12 production requirements remain as in the baseline. No VM sandbox, OS kill switch, trusted confirmation display, network sandbox, credential adapter or secure promotion is claimed by these read-only tests.

## Mutation evidence

P02-M01 removes audience matching; P02-M02 removes Host matching; P02-M03 removes export classification; P02-M04 removes project-scope authorization; P02-M05 removes literal scrubbing; P02-M06 ignores audit failure; P02-M07 falsely permits execution. Each selected test must exit 1 with at least one assertion failure and zero setup/collection errors. The utility verifies original source hashes are unchanged.

Original R01/R02/R03 mutations cover trusted-path checks, cross-chunk redaction and installed-root protection primitives. These tests do not establish OS-enforced boundaries by themselves.

## Blocking decisions, not hidden TODOs

| ID | Closure evidence | Responsible role | Why not silently automated |
|---|---|---|---|
| P02-DEPLOY-01 | Owner-approved export manifest and recipient mapping | Data owner | Source-code development permission is not permission to export every host file |
| P02-DEPLOY-02 | Protected installed files, separate identities, verified IPC/audit permissions | Platform security + owner | Administrative/identity changes need explicit local approval |
| P02-DEPLOY-03 | Verified OAuth/tunnel configuration and negative tests on the real client | Identity/integration owner | Do not borrow existing keys or expose this dev profile as a production OAuth service |
| P02-DEPLOY-04 | Approved replacement/rollback plus failed probes on retired old paths | Owner + operations | User explicitly reserved switching for later; current connection must remain working |
| P02-DEPLOY-05 | Protected signed update path or reviewed immutable release procedure satisfying G11 | Release security | A Git commit/signature alone is not proof of protected runtime installation |

Implementation and loopback test tasks are completed. Original Phase 02 model-facing deployment acceptance is PARTIAL / HOLD on the items above, not redefined as complete. Phase 03 execution stays HOLD. No issue or external task was created on behalf of a named person; roles here are backlog ownership, not claims of assignment.
