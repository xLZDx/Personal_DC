# Correct the documented Personal DC autostart task

## Change

Updated `docs/CHATGPT_SETUP.md` to identify `Personal_DC_V2_Tunnel` as the supported logon task,
describe its current supervised backend/tunnel behavior and bounded retry policy, and state that
the disabled `Personal_DC_Tunnel` task is legacy. Added a link to the recovery guide.

## Why

The prior setup guide described the legacy task as active. That conflicted with the installed v2
task and could direct operators to a disabled task during diagnosis.

## Verification state

Documentation-only correction based on the current installer, recovery guide and verified live
task configuration. No runtime code, credentials, scheduled tasks or services changed. No tests or
checks were run for this prose-only correction.

## Ownership

Operator is accountable for the delegated restoration request; Codex executed this documentation
correction. No separate service owner for the setup guide is recorded.
