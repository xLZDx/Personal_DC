# Record the local AEVE handoff boundary

## Change

Added `docs/AEVE_INTEGRATION_STATUS.md` with the current local AEVE CLI/MCP route evidence, the
checkout worktree boundary, the remaining reviewer restriction and the documented next step.

## Why

The MCP tunnel and Personal DC Customer Showcase are restored, but the original integration task
also asks for an authorized AEVE path check. Exact local evidence distinguishes a configured
project-level MCP server from one loaded into the current assistant session, and records why the
source review remains `NOT_RUN`.

## Verification state

Read-only observations: `codex mcp list` in the AEVE checkout listed the `aeve` stdio server as
enabled with `PYTHONPATH=*****`; `C:\Python314\python.exe -m aeve.cli` without `PYTHONPATH` failed
with `ModuleNotFoundError`; setting `PYTHONPATH=D:\Repo\AEVE-pr1-integration\src` made CLI help and
`profile get reliability-reviewer` available. The assistant's available MCP tool catalog contained
no AEVE tools. No AEVE task/review was started, no AEVE files were changed, and no source disclosure
or memory permission was enabled.

## Ownership

Operator is accountable for the delegated restoration request; Codex executed the evidence record.
No technical owner for the Codex-to-AEVE host connection is identified in the reviewed project
records.
