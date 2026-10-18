# Record the Task Scheduler test-environment blocker

## Change

Documented why Windows Task Scheduler crash-retry behavior remains `NOT_RUN` and the safe path to
confirm an isolated Windows guest in `docs/AUTOSTART_RECOVERY.md`.

## Evidence

Read-only host inventory on Windows 11 Pro build `26300`:

- `WindowsSandbox.exe` was not available.
- `wsl.exe --list --verbose` showed only `docker-desktop` (WSL 2, Running), not a Windows guest.
- `Get-VM` returned: `You do not have the required permission to complete this task. Contact the administrator of the authorization policy for the computer 'RAZER'.`
- The current PowerShell session is not elevated (`IsAdministrator=False`). Hyper-V CIM exposed the host only; that result does not rule out VMs hidden from this account.

No VM, scheduled task, service, repository source or production runtime was changed. The
documentation records the exact missing permission and recommended inventory action. No tests or
checks were run for this documentation-only update.

## Ownership

The operator is accountable for the delegated Personal DC task. The administrator/authorization
policy owner for host `RAZER` is not identified by the available records. The administrator's
specific next action is to grant Hyper-V inventory permission or provide an authorized
read-only VM/checkpoint inventory; Codex can then continue the isolated scheduler test.
