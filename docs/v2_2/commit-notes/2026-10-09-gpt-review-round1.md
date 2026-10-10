# Commit note — GPT final review round 1 remediation (F01–F10)

GPT verdict on code 24ffa92: REQUEST_CHANGES (2 BLOCKER, 8 MAJOR). Scope of this commit is exactly those findings.

| ID | Fix |
|---|---|
| F01 | `guard_git_args` rejects every spelling of `--output`, `-o*`/`-O*`, `--no-index`, `--open-files-in-pager` (incl. git's unambiguous long-option abbreviations); args after `--` are not inspected. |
| F02 | `read_output` pages a canonical redacted UTF-8 representation (redaction over the whole stream; only complete lines visible while running). Offsets are bytes of the redacted text. |
| F03 | OData credential blob is JSON bound to scheme/host/port/publication (`approve set-odata-credential REF --endpoint URL`); unbound legacy blobs and mismatching targets never receive the secret. |
| F04 | `_check_vrd_path` runs in repair, recovery planning, `_apply_vrd_change` and rollback (before every write). |
| F05 | `_odata_verdict`: HEALTHY only for 2xx + valid metadata; 401/403/404/5xx/malformed are distinct; restart only for UNREACHABLE/SERVER_ERROR. |
| F06 | `deployment_apply` planned→applying transition is atomic under a per-plan file lock; a second concurrent call is refused before its approval is consumed. |
| F07 | Automated rollback requires a non-failed install whose ProductCode appeared during the plan (`new_software_keys`); otherwise NOT_SUPPORTED/manual. |
| F08 | Staging errors (OSError/hash) are caught: stage dir removed, plan `failed`, retryable with a fresh approval. |
| F09 | `process_start` kills the whole tree when the root exits by default; `detach=true` (approval-bound) records descendants (pid+creation time) and `process_stop` terminates them later, also after a restart. |
| F10 | Autostart updater: `-Rollback` restores the immutable ORIGINAL xml; `-Rollback -Previous` skips native snapshots; no snapshot of an already-native task. |

Operator note: existing `odata-<ref>` secrets must be re-provisioned with `--endpoint`.
