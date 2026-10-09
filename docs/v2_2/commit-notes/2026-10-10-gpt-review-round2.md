# GPT review round 2 remediation (2026-10-10)

Audience: a developer who knows nothing about this project. Scope: `dc_v2.winops` (native Windows tools of Personal DC v2.2).
Round 2 of the GPT-PM review returned REQUEST_CHANGES with F01 (BLOCKER) and F05, F07, F09, ND01, PS01 (MAJOR).

| Finding | Root cause | Change |
|---|---|---|
| F01 git trust boundary | "free" git subcommands could still launch programs (editor, pager, diff/textconv/filter drivers, fsmonitor, aliases, `branch --edit-description`, `commit` without `-m`). | New `winops/git_policy.py`: argument-aware free set (`args_allowed_for_free`) and `config_launches_programs` (repo + user config scan). `guard_git_args(args, cwd)` hardens with `-c core.editor=false core.pager=cat sequence.editor=false ...` plus `--no-ext-diff --no-textconv`. Anything not provably inert needs an operator approval. |
| F05 EDMX | `$metadata` was "healthy" if it merely contained entity tags. | `onec_tools._edmx_structure_error`: Edmx root in a known namespace > DataServices > Schema > EntityContainer, else `NOT_EDMX`/`EDMX_*_MISSING`. |
| F07 product ownership | Two plans for one MSI product could install/rollback concurrently. | `deploy_tools`: refuse overlapping installs (`PRODUCT_INSTALL_IN_PROGRESS_BY_ANOTHER_PLAN`), first plan observing the product claims `owners/<code>.json`; rollback needs `_owns(plan)`. |
| F09 detached descendants | Descendant identities were saved only at exit; restart or early parent exit lost them; cap of 100. | `process_tools._record_descendants` persists (pid, creation time) while running (cap 1000, `orphans_truncated` flag); all stop paths call `_stop_orphans`. |
| ND01 git deletion | Text regex missed `branch --delete`, `-D`, `remote remove`, `reset --hard`, abbreviations. | `deletion_policy.git_deletes` structured check used for text and argv; `_start` now applies the deletion policy before cwd resolution and approval. |
| PS01 script litter | Every unapproved PowerShell request wrote a `.ps1`. | Script persistence is deferred until after `authorize_launch`; `verify_script_file` re-hashes before launch; bounded cache (200 files / 8 MiB / 7 days, pruned at most once a minute). |

Tests: `tests_winops/test_review_round2.py` (new), adapted `test_command_policy.py` and
`test_review_round1_deploy_odata.py`. Full run: 1424 passed, 4 skipped.

Residual (unchanged, documented in KNOWN_LIMITATIONS.md): approval key is same-user; deletion policy is best-effort text/argv; live elevated restart needs a UAC prompt.

## Round 3 remediation (same day, follow-up commit)

GPT verification round 3 on 93f86c2 kept F01 (BLOCKER) and F05, F07, F09, PS01 (MAJOR) open; ND01 was verified.

| Finding | Why it was still open | Change |
|---|---|---|
| F01 | The config scan only read `<cwd>/.git/config`; a nested working directory (or worktree/gitfile) reached an approval-free `git add` with a repository clean filter. | `process_tools.git_config_risk` asks git itself (`git config --list --show-scope`, same sanitized env as the launch) so discovery, includes, worktrees and gitfiles are git's own. Only repository-controlled scopes (local/worktree/command) are untrusted; system/global are trusted (Git for Windows ships `filter.lfs` and `credential.helper` there). Unknown config, missing git, or no cwd => not free. |
| F05 | Schema/EntityContainer were matched by local name only. | `_edmx_structure_error` requires `Edmx[Version]` in an EDMX namespace, `DataServices` in the same namespace, `Schema[Namespace]` and `EntityContainer[Name]` in a known EDM namespace. Integration tests send HTTP 200 with invalid bodies through `odata_probe`. |
| F07 | Ownership came from the plan-creation inventory; markers were never retired. | `_pin_provenance` re-inventories immediately before the installer starts (`inventory_at_apply`; a product already present => `product_preexisting`, never owned); `_retire_ownership` removes the marker after a verified rollback. |
| F09 | After a restart only a 2 s scan could find descendants; dedupe used PID only. | Detached jobs are named kernel Job Objects (`Local\pdc-job-<id>`, `meta.job_name`); `ensure_recovered` re-opens the job (`Job.open`) so membership and termination are gap-free (`containment: job`). Records without a job are reported `containment: scan_only_incomplete`. Identity for dedupe is (pid, creation time). |
| PS01 | Quota was checked after writing and only every minute. | `sysrun.script_file` enforces file-count and byte quotas at admission under a thread + file lock (expired, then oldest removed first; otherwise `SCRIPT_CACHE_FULL`; scripts above a quarter of the byte quota are `SCRIPT_TOO_LARGE`). No pruning clock. |

Tests: full run 1440 passed, 4 skipped. Note: the test run deletes the tracked file `evidence/phase03/hardening-exit-v4.txt`
(pre-existing behaviour of an older phase03 test); it is deliberately not staged.
