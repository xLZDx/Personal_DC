# Correct the autostart task in security documentation

## Change

Updated the Windows autostart section in `docs/SECURITY.md` to describe
`Personal_DC_V2_Tunnel` as the supported limited-privilege task and identify `Personal_DC_Tunnel`
as disabled legacy configuration.

## Why

The old wording could send an operator to an inactive task and contradicted the installer,
recovery guide and current task registration.

## Verification state

Documentation-only correction based on `scripts/install-autostart.ps1`, `docs/AUTOSTART_RECOVERY.md`
and the read-only live task query recorded in
`docs/commits/2026-10-18-live-task-recovery-settings.md`. No runtime code, task, service or
credential changed. No tests/checks were run for this prose-only change.

## Ownership

Operator is accountable for the delegated Personal DC task; Codex executed the documentation fix.
No separate technical owner for security documentation is recorded.
