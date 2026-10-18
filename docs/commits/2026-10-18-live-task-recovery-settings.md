# Record live Task Scheduler recovery settings

## Change

Added the latest read-only observation of `Personal_DC_V2_Tunnel` recovery settings to
`docs/AUTOSTART_RECOVERY.md`, explicitly distinguishing configuration from a runtime restart test.

## Evidence

```powershell
$t = Get-ScheduledTask -TaskName 'Personal_DC_V2_Tunnel'
$i = Get-ScheduledTaskInfo -TaskName 'Personal_DC_V2_Tunnel'
```

Observed on 2026-10-18: `State=Running`, `RestartCount=5`, `RestartInterval=PT1M`,
`MultipleInstances=IgnoreNew`, `ExecutionTimeLimit=PT0S`, `LastTaskResult=267009` (currently-running
marker). No task, service or process was changed. This does not establish crash-retry behavior.

## Ownership

Operator is accountable for the delegated Personal DC task; Codex executed the read-only query and
documentation update. The administrator/policy owner controlling Hyper-V inventory permission on
host `RAZER` is not identified by available records.
