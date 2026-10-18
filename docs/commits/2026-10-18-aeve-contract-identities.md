# Record exact AEVE contract identities

## Change

Added the exact `reliability-reviewer` profile and three prescribed skill IDs with their full
source-file SHA-256 identities to `docs/AEVE_INTEGRATION_STATUS.md`.

## Evidence

Read-only command from `D:\Repo\AEVE-pr1-integration` with
`PYTHONPATH=D:\Repo\AEVE-pr1-integration\src`:

```powershell
$env:PYTHONPATH='D:\Repo\AEVE-pr1-integration\src'
C:\Python314\python.exe -m aeve.cli profile get reliability-reviewer
C:\Python314\python.exe -m aeve.cli profile get reliability-contract
C:\Python314\python.exe -m aeve.cli profile get verification-contract
C:\Python314\python.exe -m aeve.cli profile get observability-contract
```

All four returned `status: AVAILABLE`. Their source hashes are recorded separately from
instruction-body hashes; availability does not prove that an AEVE review ran. No AEVE files were
changed, and no tests/checks were run for this documentation-only change.

## Ownership

Operator is accountable for the delegated restoration request; Codex executed this evidence update.
No technical owner for the current-session AEVE MCP connection is established by the available
project records.
