# Personal DC regression coverage follow-up

## Change and reason

Added focused regression coverage for an occupied loopback port and authentication failure logging,
then ran the required suite and isolated E2E scenarios against the current Personal DC source. This
closes explicit gaps in the original recovery test list without injecting failures into the live
Personal DC service or touching ERP/AEVE processes.

## Changed paths

- `tests/AutostartRecovery.Tests.ps1`: adds a mocked execution of the production startup port guard
  and the production supervised-runtime failure catch with production redaction/event helpers.
- `docs/AUTOSTART_RECOVERY.md`: records the current test scope and links this evidence.

No production script, scheduled task, credential, external tunnel, or unrelated process was changed.
`docs/BACKLOG.md` remains untouched in this change because it contains unrelated uncommitted user
work; the current runbook and this record carry the updated regression evidence.

## Functional result

Command:

```powershell
Invoke-Pester -Script @('D:\Repo\Personal_DC\tests\AutostartRecovery.Tests.ps1','D:\Repo\Personal_DC\tests\AutostartMutex.Tests.ps1') -EnableExit
```

Result: **16 passed, 0 failed, 0 skipped**, 14.06 seconds. Runtime was PowerShell 7.6.7 with
Pester 3.4.0; child worker was Windows PowerShell 5.1.26100.9711. Network and ScheduledTasks calls
were mocked. The auth failure test used fixture secrets and confirmed neither value appeared in
the temporary log. The port test executed the production guard body and confirmed startup stopped
on occupied port 18765 before checking the next port.

## Isolated E2E result

The `e2e-runner` used a copy of the supervisor in
`D:\Temp\PersonalDC_E2E_d44e91342f3546f58d9e42195b93201e`, fake backend/tunnel processes, a synthetic
DPAPI blob, and loopback ports 25604–25607. The 6/6 scenarios passed:

1. Clean startup: fake backend MCP `initialize` and `health`, plus tunnel `/healthz` and `/readyz`.
2. Controlled backend exit 37: supervisor restarted it after the configured 10-second backoff.
3. Controlled tunnel exit 37: supervisor restarted it after the configured 20-second backoff.
4. Port conflict on 25606: exited 1 with the expected refusal; fake backend/tunnel start counts were
   both zero.
5. Duplicate supervisor: second instance exited 0 with `duplicate_instance_refused`; the first
   supervisor remained active and child start counts did not increase.
6. Process isolation: a synthetic sentinel remained alive through recovery and duplicate-instance
   checks, then was stopped by its exact PID.

The supervisor fixture was launched with PowerShell using the copied source:

```powershell
$root = 'D:\Temp\PersonalDC_E2E_d44e91342f3546f58d9e42195b93201e'
$env:LOCALAPPDATA = Join-Path $root 'isolated-localappdata'
$script = Join-Path $root 'main\scripts\start-autostart.ps1'
Start-Process -FilePath (Join-Path $PSHOME 'pwsh.exe') `
  -ArgumentList @('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$script) `
  -WorkingDirectory (Join-Path $root 'main') -PassThru -WindowStyle Hidden
```

Controlled exits were signalled only inside the fixture:

```powershell
Set-Content "$root\main\signals\backend.exit.once" 'controlled-backend-exit-37'
Set-Content "$root\main\signals\tunnel.exit.once" 'controlled-tunnel-exit-37'
```

The port-conflict scenario launched the separate copy at
`$root\conflict\scripts\start-autostart.ps1` while a fixture `TcpListener` held port 25606.

Harness-only failures occurred before the final run because a disposable fake tunnel initially had
an import-path error and then omitted `Content-Type: text/plain`. The fixture was corrected and all
six final scenarios passed; these were not product failures. No production process or Task Scheduler
task was created or modified. Final inspection found no fixture command lines and no listeners on
ports 25604–25606.

The disposable root remains at
`D:\Temp\PersonalDC_E2E_d44e91342f3546f58d9e42195b93201e`, containing synthetic scripts/logs and a
synthetic DPAPI blob. Cleanup was rejected by tool policy; the agent did not retry. No live process
or listener remains.

The test agent results did not expose resolved model or reasoning-effort metadata in the returned
evidence; no model/effort value is inferred here.

## Exact revision and fingerprints

- Repository HEAD during both test runs:
  `c23f48a0da0bfc149c42c51e99ad2d9a2f210d28`.
- `scripts/start-autostart.ps1` SHA-256:
  `F0B463B94C6D567AAFE1FC306D2149469C4DA3EC20CC76FC5A4C84DA883D4AE7`.
- `scripts/install-autostart.ps1` SHA-256:
  `140CDAB55451787A4B3DBC64804A7F228D0C9A3C3E3FD81381D6B52173DFB697`.
- `tests/AutostartRecovery.Tests.ps1` SHA-256 after the two new cases:
  `4B63E2A2BD1218AFECE3BB056787FEE18A6F94527557F114EF90B59B6F53FE79`.
- `tests/AutostartMutex.Tests.ps1` SHA-256:
  `0915301E840D58E0BD59519B36CC0AD34E4554D0AB640DE8C3038AC6B3BF06E3`.
- Disposable supervisor copy SHA-256:
  `59A55FAD57E9681A9A65DA57082845A0E4847CA79EE1F8D6F99140CAED411646`.
- Disposable conflict copy SHA-256:
  `D29836B510742A6619927509199090CAE43D56FE57876AB02D9D7E7D8CBE354E`.
- Fake backend SHA-256:
  `F874B73C4EE016FF43643F4F12429073DC1DDE3815A9088B478D2F4F98B051CC`.
- Fake tunnel SHA-256:
  `E08E6BDF3F3BF3451CD9FF72581AF22F21D9381EEE944CAF66EB3CEB234BC5C7`.
- Sentinel SHA-256:
  `1E555D951B97FB5B45DC1512DA2824504CEB8E988D7523D1CE4874D4F4E832BF`.

## Remaining limits and ownership

The full 24-hour scheduled-trigger rollover and execution from a second interactive Windows
session remain `NOT_RUN`. The E2E suite also did not start the live supervisor, bind production
ports, or contact a real authentication service. The operator remains accountable for the
delegated PDC task; Codex executed the work, and the relevant functional/E2E roles authored or ran
their assigned tests. No human owner for the Windows Task Scheduler service is established in the
project's canonical records.
