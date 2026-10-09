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
