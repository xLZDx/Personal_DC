# Implementation report — Personal DC v2 native Windows commander

Branch `feature/developer-gateway-v2-2`, version 2.0.0, native Windows, no Docker. Identity untouched: tunnel
`tunnel_6ac8aa4940108191bf19192c12b1475c`, profile `personal-dc-v2`, backend 127.0.0.1:18766, health 127.0.0.1:18081,
task `Personal_DC_V2_Tunnel`, plugin "Personal DC v2.2 — Customer Showcase". v1 and `main` unchanged; no new keys.

| Group | Tools | Status |
|---|---|---|
| A commands | command_execute/start/status/output/cancel (+history) | implemented, tested, live-checked (read-only path) |
| B processes | process_list/inspect/start/status/output/stop | implemented, tested (identity, Job Objects, adoption) |
| C services | service_list/inspect/start/stop/restart/wait | implemented, tested; live mutation BLOCKED |
| D 1C/Apache/OData | onec_diagnostics, onec_connection_check, onec_publication_inspect/repair, apache_diagnostics, apache_service_control, odata_probe, odata_recovery | implemented, fixture-tested; live BLOCKED (no Apache) |
| E deployment | software_inspect, installer_verify, deployment_plan/apply/status/rollback | implemented, tested; real installer BLOCKED |
| F files/binary | chunked upload/download, SHA-256, resume, abort, file_info | implemented, tested; shared path gate |
| G autostart | supervisor, update task script, status | implemented, parsed; not executed |
| H security | approvals, audit chain, trust modes, v1 gate, shared policy | implemented, tested |

Process followed: implement → one consolidated 10-perspective local review → one remediation batch → one verification
run (1231 passed, 4 skipped; see FINAL_VERIFICATION.md) → push. Details: ARCHITECTURE.md, SECURITY_REVIEW.md,
WINDOWS_NATIVE_TOOLS.md, ONEC_APACHE_ODATA.md, KNOWN_LIMITATIONS.md.

Deployment steps for the operator (not yet done): `python -m dc_v2.winops.approve init`; stop the old backend on 18766;
run `scripts_v2\update_v2_native_autostart.ps1` (reversible: `-Rollback`, original export kept); refresh the connector.
