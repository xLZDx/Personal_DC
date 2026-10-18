# Hidden scheduled-task console launch

## What changed

- `scripts/install-autostart.ps1` now launches both the Personal DC supervisor and recovery scripts
  through `conhost.exe --headless`, while retaining Windows PowerShell 5.1, the existing hidden
  window flag, execution policy, script paths, working directory, principals, and task triggers.
- `docs/AUTOSTART_RECOVERY.md` explains the headless wrapper and clarifies that the interactive
  logon trigger starts the recovery task after the user signs in following a reboot.

## Why

The recovery task's minute trigger coincided with brief Windows Terminal windows even though its
PowerShell action used `-WindowStyle Hidden`. Windows Terminal issue 12464 documents this behavior
when Terminal is the default console host. The recovery task remains enabled and retains its logon
and daily minute triggers; the supervisor still starts only when Task Scheduler reports it ready.

## Verification

- `NOT_RUN`: tests and builds were explicitly excluded by the operator. The review agent
  inadvertently ran `git diff --check`; it reported only LF-to-CRLF conversion warnings for the
  installer and recovery documentation.
- Manually reviewed the changed installer and recovery documentation.
- A `code-reviewer` agent (GPT-6 Luna, low effort) reviewed the installer and recovery-documentation
  diff against base `b0a3734edf98d98a55f5b00834c2829bf90606df`; it reported no material findings and
  made no file changes.
- Updated the live recovery task to use `conhost.exe --headless`, re-enabled it, and confirmed the
  task is enabled with a logon trigger and daily one-minute repetition.
- Updated the live supervisor task action to use the same headless wrapper without stopping its
  already running process.
- After the recovery task's scheduled run at 22:45:34, `LastTaskResult=0`; the existing Windows
  Terminal process still dates from 13:07:43. This does not prove post-reboot behavior.
- Runtime behavior after reboot is `NOT_RUN`; no reboot was performed.

## Ownership and rollback

The operator owns the requested behavior; Codex executed the change. A technical service owner is
not identified in the available project records. Before this task change, the recovery task XML was
saved to `%TEMP%\Personal_DC_V2_Tunnel_Recovery.before-headless-launch.xml`. The supervisor task
XML was saved separately before its action was updated. Reinstall the task definitions from those
backups to restore the previous actions; the source change can be reverted in a later commit.
