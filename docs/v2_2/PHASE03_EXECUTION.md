# Phase 03 — isolated Developer Execution (candidate, not deployment)

Date: 2026-10-08. Branch: feature/developer-gateway-v2-2.
Owner's active main, MCP endpoint, tunnel, service and other containers are NOT modified.

## Scope actually implemented

- dc_v2/execution.py: detached Docker task lifecycle, task list/status/output/cancel,
  OS process deadline via guest /usr/bin/timeout, crash-recoverable local task IDs,
  persistent STOP latch, and a broker-local emergency stop.
- WorkspacePool: random server-generated workspace IDs, bounded synthetic file
  import, read/write with compare-and-swap, symlink/reparse checks, unified diff.
- dc_v2/workspace_broker.py: resource IDs resolved by a trusted local registry;
  file.read, file.write, file.patch, file.mkdir, file.search, file.diff
  require authenticated Principal, Manifest, TaskGrant and project scope.
- dc_v2/phase03_audit.py: fsynced bounded local hash-chain audit of task/file
  operations; tampered chain fails closed. NOT an immutable external audit anchor.
- dc_v2/promotion.py: content-addressed synthetic promotion plans, target CAS,
  independent Ledger challenge reservation, and write only after signature
  verification. No auto-execution; multi-file atomicity/Windows races unverified.
- Tests: tests_phase03/test_execution.py (fake Docker, negative policy tests).
- Real smoke scripts: scripts_v2/phase03_live_probe.py and
  scripts_v2/phase03_toolchains_probe.py.

## Trust boundaries

No public MCP tool, HTTP handler or existing gateway uses the execution classes.
There is deliberately NO production grant issuer, secret-bearing integration,
trusted approval ceremony, or direct model-accessible shell. Only a trusted local
Python invocation of the broker can launch a guest today.

Docker CLI is invoked with subprocess(shell=False), a minimal explicit process
environment, a fixed local CLI path and fixed Docker Desktop Linux endpoint.
Arbitrary argv is passed ONLY after the container image as guest command arguments.
There is NO fallback to Windows PowerShell, cmd.exe, or host Python.

Each worker has network=none, read-only root filesystem, user 65534, all Linux
capabilities dropped, no-new-privileges, bounded CPU/RAM/PIDs/log size, no privileged
mode, no Docker socket, /tmp tmpfs, and only its own workspace bind-mounted.
The local image config ID is pinned and must exist offline; image pulls are disabled.
The guest timeout binary is required for autonomous task time limits.
Docker is **not** treated as security-equivalent to a dedicated virtual machine.

Test profiles (local IDs, not an approved production image allowlist):

- python:3.12-slim config digest:
  sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de
- node:22-bookworm config digest:
  sha256:0e5f906573693feaa1e21057ebdcfdb5bd5021f050b2dc7c9deceb629c7da2a8

Capability check: Python CLI, Node.js, npm offline build and Git work in the
available guest images; .NET, pwsh, pytest inside guest, Playwright and graphical
E2E have NOT been validated. They are UNSUPPORTED/ENVIRONMENT_UNAVAILABLE in this
profile; running host tools is not an alternative.

## Local reproduction (owner-controlled, disposable fixtures only)

From PowerShell:

    cd D:\Temp\Personal_DC_v2_2_full_20261008
    python -m pytest -o addopts='' -q tests_phase03
    python -m pytest -o addopts='' -q tests tests_v2 tests_phase02 tests_phase03
    python scripts_v2\phase03_live_probe.py
    python scripts_v2\phase03_toolchains_probe.py

The last two commands create new synthetic fixture directories under
D:\Temp\Personal_DC_v2_2_isolated, new containers with label
personal-dc.owner=phase03 and a local evidence file under evidence\phase03.
They do NOT use your real source projects, accounts or credentials.
The scripts deliberately leave test artifacts and stopped containers for
inspection; no destructive cleanup is carried out without owner authorization.

Output file read is bounded and redacted before cursor paging. Rotating Docker
logs can invalidate old cursors; this is not a durable streaming API.
Workspace access still needs hardening against races with actively running
guest processes; only local protected synthetic workspaces are approved.
Task state is written to a local control-root JSON file, not production HA storage.

## Security requirements NOT cleared

- Independent broker process identity and protected OS ACLs, installer hardening,
  signed launcher, process separation and a real approval device.
- Real authorized project snapshot ingestion; confidential-data policy enforcement;
  separate model-export approval, output classification and per-recipient limits.
- Independent OS kill controller that can discover and terminate all orphan workers.
  Current kill switch is local/in-process plus durable STOP file, not OS independent.
- Audit anchoring externally, journal synchronization across processes, and a
  protected outbox delivery service.
- Production-grade promotion/apply with protected destination handle/ACL, whole-tree
  transaction and rollback; synthetic signed single-file CAS implementation exists.
- Real MCP authentication/tunnel, update strategy, CI fleet and E2E user journeys.
- Proven Windows ACL/reparse/race protections and a stronger VM isolation profile.
- Production CI approval and change management.

**System acceptance remains HOLD.** See SECURITY_GATES_PHASE03.md and
OPERATOR_BACKLOG.md. No production switch or merge is authorized.

## 2026-10-08 hardening continuation

- `task.propose` now validates project, principal, grant, snapshot, image,
  policy and capabilities without starting Docker. Proposals leave a local
  audit event. `task.start` remains separately authorized.
- `manifest.environment` is explicitly UNSUPPORTED pending environment
  classification; no Windows host environment is inherited.
- Task outputs have a persisted *total* grant budget across cursor reads;
  older synthetic task records lacking a budget cannot export output.
  Redaction happens before pagination; discarded early logs fail closed.
- `file.diff` only returns registered resources; file.read, file.search and
  file.diff enforce output_limit even for synthetic data.
- Read-only forensic validation of old Phase03 transfer packages confirmed
  two integrity failures. Do not extract or execute them.
- Final local Windows regression: **575 passed, 3 skipped, exit 0**.
  New Phase03 tests: **47 passed, 1 skipped**. Actual pinned Docker Python,
  cancellation/timeout/STOP, Node/npm/Git, clean environment and no route
  probes all returned exit 0; see `evidence/phase03`.
- No independent trusted grant issuer, protected model-facing execution
  endpoint, OS-level kill controller or production promotion was deployed.
  Acceptance remains HOLD; refer to PHASE03_HARDENING_REVIEW.md.
