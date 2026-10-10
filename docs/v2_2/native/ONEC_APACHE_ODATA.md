# 1C / Apache / OData

Nothing is assumed: Apache is found from `httpd.exe` services and the configured `apache_roots`; 1C platforms from
`onec_roots`; publications from `ManagedApplicationDescriptor` directives (following `Include`, ≤ 50 files); infobase
names from `%APPDATA%\1C\1CEStart\ibases.v8i` (names and kind only).

| Tool | Mutates | Notes |
|---|---|---|
| `onec_diagnostics` | no | platforms, 1C/Apache services, infobase names, merged findings |
| `onec_connection_check` | no | file infobase path / `1Cv8.1CD`, or TCP to cluster host (loopback/allow-listed hosts only); no login |
| `onec_publication_inspect` | no | VRD hash, redacted `ib`, `standardOdata`, services flags |
| `apache_diagnostics` | no | `httpd -t`, Listen ports, 1C module files, publication findings |
| `apache_service_control` | start/stop/restart | service must be the discovered Apache service **and** allow-listed; start/restart refused when `httpd -t` fails; approval |
| `odata_probe` | no | GET only; loopback/allow-listed hosts; no redirects; returns status/timing/metadata counts or record **count** — never record contents |
| `onec_publication_repair` | VRD file | `enable_standard_odata` or `rollback`; default is a PLAN with diff + hashes; apply needs approval bound to old/new SHA-256, backs up first, validates XML + `httpd -t`, auto-restores on failure |
| `odata_recovery` | via plan | PLAN of steps (enable OData, start/restart Apache); one approval bound to the step list; re-probes at the end; blocked when Apache config is invalid |

Findings ids: `APACHE_NOT_FOUND`, `APACHE_SERVICE_NOT_RUNNING`, `APACHE_CONFIG_INVALID`, `ONEC_MODULE_NOT_LOADED`,
`ONEC_MODULE_FILE_MISSING`, `ONEC_MODULE_VERSION_NOT_INSTALLED`, `NO_1C_PUBLICATION`, `VRD_MISSING`, `VRD_INVALID`,
`ODATA_DISABLED`, `IB_FILE_PATH_MISSING`, `IB_CONNECTION_MISSING`, `LISTEN_PORT_NOT_ACCEPTING`, `ONEC_PLATFORM_NOT_FOUND`.

Credentials: connection strings are redacted (`Usr`, `Pwd`), never logged. For authenticated OData the owner provisions a
DPAPI secret `%LOCALAPPDATA%\Personal_DC_V2\secrets\odata-<ref>.dpapi` (JSON with user, password and the BOUND endpoint scheme/host/port/publication, protected with the entropy
`personal-dc-v2.winops`), created by `python -m dc_v2.winops.approve set-odata-credential <ref> --endpoint <odata base url>`.
The caller passes only `credential_ref`; a probe to any other endpoint never receives the secret, and unbound legacy
`user:password` blobs are refused. Recovery verdicts: HEALTHY only for HTTP 2xx with valid OData metadata; 401/403, 404,
5xx and malformed metadata are reported separately.

Out of scope / manual: editing `httpd.conf`, re-publishing with `webinst`, platform upgrades, database repair.
