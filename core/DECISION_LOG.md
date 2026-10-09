# Decision log — Personal DC v2

Durable decisions and evidence only. Newest entries at the bottom. Full per-commit detail lives in
`docs/v2_2/commit-notes/`.

## 2026-10-09 — Native Windows operations layer (winops)

* **Decision:** build the personal Windows commander as `dc_v2/winops` (stdlib + ctypes, no Docker, no new
  tunnel/plugin/keys) on the existing v2 MCP backend (127.0.0.1:18766) and tunnel profile `personal-dc-v2`.
* **Decision:** the "No authentication" MCP front door is not user authorization. Privileged actions return
  `APPROVAL_REQUIRED`; the owner grants out-of-band with `python -m dc_v2.winops.approve`; an approval is bound to the
  SHA-256 of (action, params), expires, is single-use and HMAC-signed with a DPAPI-protected key.
* **Decision:** read-only execution is a structural allowlist, never a keyword blacklist.
* **Decision:** the server never elevates or bypasses UAC; installers needing admin report `needs_elevation`.
* **Process (operator 2026-10-09 master prompt):** no tests/CI/GPT during development; one consolidated local review,
  one final verification run, one final GPT request. This commit's test sources are NOT executed yet.
* **Evidence status:** none yet (UNKNOWN until final verification). Production gates G01–G13 are NOT claimed.
* **Detail:** `docs/v2_2/commit-notes/2026-10-09-winops-core.md`.

## 2026-10-09 — Remediation of the consolidated local review

* **Decision:** interpreters (python/node/npm/pip/dotnet) require operator approval; only local git subcommands run free.
* **Decision:** path safety lives once in `personal_dc/policy.py` and is shared by v1 and v2; v1 identity stays separate.
  v1 `git_push`/`run_project_tests` are approval-gated only inside the v2 process (`winops/v1_gate.py`, delegating).
* **Decision:** repair and recovery share one reversible write path (`_apply_vrd_change`); recovery fails closed when
  Windows service discovery is degraded.
* **Decision (honest limit):** the approval key is held by the same Windows user as the server; reported as
  `approval_authority_isolated=false`, documented in KNOWN_LIMITATIONS.md. Not a privilege boundary.
* **Evidence status:** still UNKNOWN until the single final verification run; gates G01–G13 not claimed.
* **Detail:** `docs/v2_2/commit-notes/2026-10-09-remediation.md`.

## 2026-10-09 — Final verification run
* **Evidence (FACT):** 1231 passed, 4 skipped, 0 failed across tests_phase02/03, tests, tests_v2, tests_winops; live in-process
  checks listed in `docs/v2_2/native/FINAL_VERIFICATION.md`. Apache/real installer/service mutation/approval round trip/
  ChatGPT visibility are BLOCKED, not PASS. Gates G01-G13 not claimed.
* **Fixes from first execution:** upload staging dir creation, `-Name` PowerShell parameter, `..` publication name,
  per-user 1C discovery, duplicated `$metadata` in odata_probe URL.

## 2026-10-09 — Final GPT review request prepared
* GPT is called only at the very end; request file `docs/v2_2/native/GPT_FINAL_REVIEW_REQUEST.md` pins code HEAD 24ffa92.

## 2026-10-09 — Live deployment of the native supervisor
* **Decision (operator "разворачивай"):** task `Personal_DC_V2_Tunnel` updated to `start_v2_native_supervisor.ps1` (original XML kept as
  `task-Personal_DC_V2_Tunnel-ORIGINAL.xml`); orphan old backend (pid 54988) and tunnel (pid 52748) stopped; same profile
  `personal-dc-v2` restarted by the supervisor. No new tunnel/key/plugin.
* **Evidence (FACT):** supervisor state `running`, backend 18766 and tunnel 18081 listening, authenticated MCP probe PASS with
  `tool_count: 59`. ChatGPT-side visibility and `approve init` remain operator steps.

## 2026-10-09 — GPT final review round 1 (REQUEST_CHANGES) remediation
* **Evidence:** GPT reviewed 24ffa92: 2 BLOCKER (F01 git `--output` write bypass, F02 paginated-output redaction bypass) and
  8 MAJOR (F03–F10). One broad sweep per policy; this commit fixes exactly F01–F10 (+ direct regressions). Detail:
  `docs/v2_2/commit-notes/2026-10-09-gpt-review-round1.md`.
* **Decision:** output paging uses a canonical redacted representation (offset semantics change to redacted bytes).
* **Decision:** OData credentials are endpoint-bound; legacy unbound blobs are refused (operator must re-provision).
* **Decision:** default process-tree lifetime = root lifetime; detaching is explicit and approval-bound.

## 2026-10-10 — Administrator token for the v2 server, tool-level no-deletion
* **Decision (operator choice, AskUserQuestion):** run the whole v2 server elevated (RunLevel Highest) instead of a narrow
  elevated helper. UAC is never bypassed: the operator consents once when running `update_v2_native_autostart.ps1 -Elevated`.
* **Decision:** "without the right to delete" is enforced by tools (`deletion_policy.py`, `deny_deletion` default true),
  not by the OS; automated uninstall (deployment_rollback) is refused while the policy is on.
* **Evidence:** 1342 passed, 4 skipped. Residual risk documented in KNOWN_LIMITATIONS.md.
