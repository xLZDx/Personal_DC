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

## Prescribed contract identifiers

Read-only `profile get` calls with the checkout's `src` on `PYTHONPATH` returned all four required
contracts as `AVAILABLE`. The source hashes identify the full authoritative contract files; they do
not represent an executed review:

| Kind | Exact ID | Source SHA-256 |
| --- | --- | --- |
| Reviewer profile | `reliability-reviewer` | `57897d55145782bfc057131466c91949ef89f8e211ed72af3fa5c295fbab8a00` |
| Skill | `reliability-contract` | `696bb4cbe8a032369181af70c07a6edbac1a19836fbb6201bd7eef926d80eec8` |
| Skill | `verification-contract` | `907dde77fc29b0b3109b0858766b9d5c750289a6f53893d28fca23cb105321f9` |
| Skill | `observability-contract` | `26a848ae3ffa0ca1e913d8fcbf0c67c7dbd88878837a89a9ef8c71923cd5ebe0` |
