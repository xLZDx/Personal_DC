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
