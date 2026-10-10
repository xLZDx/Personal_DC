# Personal DC v2.2 — Phase 02 read-only implementation

Date: 2026-10-08. Branch: `feature/developer-gateway-v2-2`.
Status: IMPLEMENTATION AND LOOPBACK TESTS COMPLETE; DEPLOYED MODEL-FACING ACCEPTANCE PARTIAL; EXECUTION HOLD.

## Scope and truthful completion boundary

The requested independent full clone now exists on the owner's Windows machine at `D:\Temp\Personal_DC_v2_2_full_20261008`. It has its own Git database, no alternates and no shared worktree with `D:\Repo\Personal_DC`. All 51 files tracked at foundation commit `daf5968a99bf1c237815bb0ce18a50838253267b` were retained. Ignored credentials, logs, vendor downloads and runtime state were deliberately not copied. The historical preparation script's BLOCKED report was superseded by an independent successful clone verification.

The implementation delivers an authenticated, bounded loopback MCP endpoint over approved immutable snapshots. It is a DEVELOPMENT profile, not a production OAuth/tunnel installation. Phase 02's original requirement to pass applicable deployed G01/G04/G08/G09/G10/G11 has not been waived: full model-facing activation remains conditional. The active gateway, main branch, tunnel, Windows privileges, installed credentials and CI configuration are unchanged. No listener is left running by the acceptance test.

## Data flow and trust

Owner-selected export file + exact SHA-256 -> strict bounded parser -> immutable in-memory snapshot -> server-authenticated Principal -> scope/project/recipient checks -> bounded and scrubbed result -> fsynced audit decision -> MCP response.

The model supplies resource IDs, not paths or identity. No file, Git executable or development command is opened/executed by a read request. Repositories, log text and responses remain UNTRUSTED even when their export is permitted. SECRET, LOCAL_ONLY and unknown classifications are rejected during snapshot loading. Reading the snapshot requires deliberate export authorization; this version does not autonomously crawl a host or classify arbitrary files.

## Actual MCP tools

| Tool | Actual behavior | Explicit limitation |
|---|---|---|
| capabilities_list | Returns granted operations and execution HOLD | No unsupported capability advertised |
| projects_list | Lists authorized projects from the snapshot | Not a live filesystem scan |
| project_describe | Lists authorized metadata/resources | Scope and recipient filtering apply |
| file_read | Paged UTF-8 text, exact source/export digests | Offset and limit count Unicode code points |
| tools_inspect | Approved binary metadata/digest/size | Does not run --version or prove signature/executability |
| git_inspect | Approved captured Git diagnostic text | SNAPSHOT_NOT_LIVE; does not run Git |

Old read/write tool names are denied, never dispatched to the original server. `task_start`, `task.start`, `execute_command` and `start_process` return EXECUTION_HOLD. There is no approval-issuing, shell, VM, deploy, update or promotion tool.

## Runtime components

`readonly_snapshot.py`: exact schema, duplicate-key rejection, size/digest validation, immutable values, explicit classifications/recipients, link/hardlink checks on initial snapshot loading. These bootstrap checks are not a Windows ACL/sandbox or a complete rename-race proof.

`readonly_auth.py`: explicit pinned opaque bearer hashes with principal, issuer, audience, expiry, not-before and revocation state. A valid access token is reusable. Maximum configured lifetime is one hour. No credentials are read from owner profiles, environment or tool arguments. There is no token issuer, OAuth authorization server or sender-constrained-token claim. Changes to records require trusted restart/reconfiguration; online revocation service is not implemented.

`readonly_service.py`: common scope/project/recipient enforcement, default deny, no legacy fallback, safe codes, bounded metadata/pages, literal canary scrubbing before pagination and metadata export. Literal masking is not universal DLP. CLI configuration does not import real secret values to populate a scanner; forbidden data should not be supplied to this profile.

`readonly_mcp.py`: stateless Streamable HTTP JSON responses, loopback-only bind and peer, explicit Host/Origin handling, no proxy trust, authenticated initialization/listing/calls, reauthentication after body receipt, strict requests, quotas. Protocol negotiation is tested with official MCP SDK 1.29.0. GET streaming and DELETE sessions are not provided; those methods return 405. A remote client cannot connect directly without a separately approved transport integration.

`readonly_audit.py`: bounded local append/hash-chain journal, fsync before release, existing-record verification against a retained anchor, fail-closed output on failure. This is not an independently protected audit service. A runtime owner can forge its journal/anchor; durable independent anchors, remote copies, ACL separation and rotation are deployment work.

## Limits

Snapshot: 8 MiB; resource: 1 MiB; projects: 64; resources/tools: 128 per project. Read page: 4096 Unicode code points; service JSON: 64 KiB; HTTP serialized response: 256 KiB. Headers: 16 KiB; request body: 32 KiB; body receipt: 5 seconds. Default admission: 600 requests/minute globally and 8 active ASGI requests. Audit: 4 MiB default, explicit fail closed when full. These bounds are not an independently measured production latency/memory SLA.

## Reproduction

From this independent source checkout, using already provisioned dependencies:

```powershell
python scripts_v2/run_phase02_validation.py --label local-check --legacy
python scripts_v2/mutation_phase02.py
python scripts_v2/mutation_check.py
```

The runner is a developer utility, not an MCP tool. It disables automatic pytest plugin loading and writes local JUnit/logs/source hashes. The deployment receipt separately binds evidence to Git HEAD. The original pyproject still packages only `personal_dc`; this addition is source-mode and is not advertised as an installed replacement.

## Verification and remaining boundaries

See `PHASE02_GATE_EVIDENCE.md`, `PHASE02_OPERATOR_RUNBOOK.md` and the checked-in evidence receipt. Windows final source run: Phase 02 129 passed; complete original+foundation+Phase 02 discovery 268 passed, 1 skipped. The skip is the original symlink-privilege fixture, not a waived OS reparse gate. Seven Phase 02 mutation tests detected assertion failures with no test-collection errors; three original foundation mutations were also detected on Windows. The live test uses only synthetic data/tokens, checks cross-client denial and confirms listener shutdown. Linux Phase 02: 128 passed, 1 skipped because MCP SDK is not installed there; Windows supplies the real SDK evidence.
