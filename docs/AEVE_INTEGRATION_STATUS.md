# AEVE integration handoff

## Current local evidence

- The AEVE checkout is `D:\Repo\AEVE-pr1-integration`. Its worktree contains staged changes; do not
  reset or modify it as part of Personal DC recovery.
- `codex mcp list`, run from that checkout, reports the project-scoped `aeve` stdio server as
  enabled. The server command is `python -m aeve.cli mcp --root .` with `PYTHONPATH=src`.
- The currently connected assistant tool surface does not expose an AEVE MCP tool. A project server
  listed by the CLI is configuration evidence only; it does not prove that the current session
  loaded or initialized it.
- The AEVE CLI is available from the checkout with
  `$env:PYTHONPATH='D:\Repo\AEVE-pr1-integration\src'` and
  `C:\Python314\python.exe -m aeve.cli ...`. Invoking `python -m aeve.cli` without the source path
  fails with `ModuleNotFoundError: No module named 'aeve'`.
- `docs/runbooks/AEVE_MCP.md` in the AEVE checkout documents reopening it as a trusted Codex project
  and reloading/restarting Codex to load its local server configuration. A listed server alone does
  not establish a completed task ledger or a source review.

## Boundary and next action

The Personal DC restoration task forbids external AI reviewers/agents. Therefore the requested
AEVE `reliability-reviewer` source review remains `NOT_RUN`; no profile or skill was simulated as a
completed review. The next permitted integration step is to load the documented local AEVE MCP
server in a supported trusted host session and confirm its MCP tools/ledger path. A source review
requires a separately permitted host action under the incident's reviewer restriction. Do not
enable source disclosure or memory as a workaround.

The source checkout's frozen benchmark remains read-only. Its expected HEAD is
`0b4c56d8d0fa7410534b51da77d90999e983ebf6`; the recorded `worker.py` digest is
`D996B91FFBE7883C70D206D6C5715087C73B2E284F4FCD2C09EFB0E5B9CB6738`.
